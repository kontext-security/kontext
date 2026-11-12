package hookinstall

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/antigravitymanaged"
	"github.com/kontext-security/kontext/internal/hermetic"
)

// The ways an organization (managed) install can fail for an agent, written
// down before the code. Each test below names the ones it covers.
//
// Install
//   F1  An agent self-serve wires gets no hooks from a managed install.
//   F2  The managed daemon adds user-level Claude Code, Codex or Cursor hooks:
//       their machine-wide files already run, so every hook would run twice.
//   F3  The package's root install writes an agent's file into root's home, or
//       into a path relative to the working directory when HOME is empty.
//   F4  The existing entries of a user's hooks file are lost.
// Removal
//   R1  The package's root removal reads or writes a user's file: a user
//       controls everything in their home (links, FIFOs, mounted disks), and
//       root must never touch more than that user could.
//   R2  The user's hook outlives the package and names a deleted binary.
//   R3  A repair already running when the package is removed writes the hook
//       back after it was removed.
//   R4  Removal needs a home folder, which root under an MDM does not have.
// Doctor and list
//   D1  An agent that is installed but not wired reads as healthy.
//   D2  Without a home folder the doctor reads a relative path.
//   L1  The list a release checks against names a file no install writes.

// managedInstall runs both halves of an organization install: the package's
// root half, then the half the user's daemon does.
func managedInstall(t *testing.T) (Options, []Definition) {
	t.Helper()
	opts, defs := fixture(t, System)
	installBothHalves(t, opts, defs)
	return opts, defs
}

func installBothHalves(t *testing.T, opts Options, defs []Definition) {
	t.Helper()
	if err := runDefinitions(opts, defs, false); err != nil {
		t.Fatal(err)
	}
	if opts.Scope == System {
		opts.PerUser = true
		if err := runDefinitions(opts, defs, false); err != nil {
			t.Fatal(err)
		}
	}
}

// The guard (F1): every agent a self-serve install wires is wired by a managed
// install too.
func TestEverySelfServeAgentIsWiredOnAManagedInstall(t *testing.T) {
	opts, system := managedInstall(t)
	selfServe, err := Definitions(User, opts.Home)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range selfServe {
		var managed *Definition
		for i := range system {
			if system[i].Agent == want.Agent {
				managed = &system[i]
			}
		}
		if managed == nil || len(managed.Files) == 0 {
			t.Errorf("%s (%s) is wired for self-serve only, so it stays Not Governed on every managed Mac. "+
				"Add it to the system scope in definitions(): with a machine-wide file (Scope: System) that the package writes as root, "+
				"or, when the agent reads no machine-wide file, with the file in the user's home (Scope: User), which the managed daemon installs.",
				want.Name, want.Agent)
			continue
		}
		raw, err := os.ReadFile(managed.Files[0].Path)
		if err != nil {
			t.Errorf("%s: a managed install wrote no hooks: %v", want.Name, err)
			continue
		}
		if binary, err := managed.Validate(raw); err != nil || binary != opts.Binary {
			t.Errorf("%s: managed hooks in %s: binary %q, %v", want.Name, managed.Files[0].Path, binary, err)
		}
	}
}

// F2, F3: root writes the machine-wide files only, the daemon the user's only.
func TestManagedInstallSplitsFilesBetweenRootAndTheDaemon(t *testing.T) {
	opts, defs := fixture(t, System)
	var out bytes.Buffer
	opts.Out = &out
	if err := runDefinitions(opts, defs, false); err != nil {
		t.Fatal(err)
	}
	var machine, perUser []File
	for _, d := range defs {
		for _, f := range d.Files {
			if f.Scope == User {
				perUser = append(perUser, f)
			} else {
				machine = append(machine, f)
			}
		}
	}
	if len(perUser) == 0 {
		t.Fatal("fixture has no per-user file")
	}
	for _, f := range perUser {
		if _, err := os.Lstat(f.Path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("root wrote the user file %s: %v", f.Path, err)
		}
		if !strings.Contains(out.String(), "skip\tuser\t"+f.Path+"\tuser-daemon\n") {
			t.Fatalf("root's plan does not say who installs %s:\n%s", f.Path, &out)
		}
	}
	for _, f := range machine {
		if err := os.Remove(f.Path); err != nil {
			t.Fatal(err)
		}
	}
	opts.PerUser = true
	if err := runDefinitions(opts, defs, false); err != nil {
		t.Fatal(err)
	}
	for _, f := range machine {
		if _, err := os.Lstat(f.Path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the daemon wrote the machine-wide file %s: %v", f.Path, err)
		}
	}
	for _, f := range perUser {
		if _, err := os.Stat(f.Path); err != nil {
			t.Fatalf("the daemon did not write %s: %v", f.Path, err)
		}
	}
}

// F3, R4: with no home folder the per-user file is a placeholder, never a path
// relative to the working directory.
func TestSystemDefinitionsWithoutHomeNameNoRelativePath(t *testing.T) {
	hermetic.NotOnWindows(t, "ENG-1001", "Windows system scope has no per-user file yet")
	defs, err := Definitions(System, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range defs {
		for _, f := range d.Files {
			if !filepath.IsAbs(f.Path) && !strings.HasPrefix(f.Path, "~/") {
				t.Fatalf("%s: relative path %q", d.Agent, f.Path)
			}
		}
	}
	// Neither install nor removal touches the placeholder.
	work := t.TempDir()
	t.Chdir(work)
	for _, remove := range []bool{false, true} {
		opts := Options{Scope: System, DryRun: true, Binary: "/usr/local/bin/kontext", Out: &bytes.Buffer{}}
		if err := runDefinitions(opts, defs, remove); err != nil {
			t.Fatal(err)
		}
	}
	if entries, _ := os.ReadDir(work); len(entries) != 0 {
		t.Fatalf("wrote into the working directory: %v", entries)
	}
}

// R1: the package's root removal reads and writes no user's file, whatever is
// there: a link, a FIFO, another user's mount. It reports who removes it.
func TestSystemRemovalLeavesUserHomesAlone(t *testing.T) {
	opts, defs := managedInstall(t)
	var perUser File
	for _, d := range defs {
		for _, f := range d.Files {
			if f.Scope == User {
				perUser = f
			}
		}
	}
	// A link root must never follow; reading it would fail the removal.
	if err := os.Remove(perUser.Path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing"), perUser.Path); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	opts.Out = &out
	if err := runDefinitions(opts, defs, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "skip\tuser\t"+perUser.Path+"\tuser-daemon\n") {
		t.Fatalf("removal does not say who removes %s:\n%s", perUser.Path, &out)
	}
	if target, err := os.Readlink(perUser.Path); err != nil || !strings.HasSuffix(target, "missing") {
		t.Fatalf("root touched the user's file: %q %v", target, err)
	}
	for _, d := range defs {
		for _, f := range d.Files {
			if f.Scope == System {
				if _, err := os.Lstat(f.Path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("machine-wide file remains: %s", f.Path)
				}
			}
		}
	}
}

// R2, F4: the daemon's removal drops Kontext's hook and keeps another tool's;
// a file left empty goes.
func TestPerUserRemovalKeepsOtherEntries(t *testing.T) {
	opts, _ := fixture(t, System)
	for _, foreign := range []bool{false, true} {
		home := t.TempDir()
		path := antigravitymanaged.UserHooksPath(home)
		if foreign {
			write(t, path, `{"other-tool":{"Stop":[{"type":"command","command":"/bin/true"}]}}`, 0o600)
		}
		o := Options{Scope: System, PerUser: true, Home: home, Binary: opts.Binary, NoBackup: true}
		if err := Install(o); err != nil {
			t.Fatal(err)
		}
		installed := read(t, path)
		// RemoveIf sees the bytes the removal plans with, and can keep them.
		keep := o
		keep.RemoveIf = func(_ File, content []byte) bool {
			if string(content) != installed {
				t.Errorf("RemoveIf saw other bytes than the file's")
			}
			return false
		}
		if err := Remove(keep); err != nil {
			t.Fatal(err)
		}
		if read(t, path) != installed {
			t.Fatal("a removal RemoveIf rejected changed the file")
		}
		if err := Remove(o); err != nil {
			t.Fatal(err)
		}
		if !foreign {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a file holding only Kontext's hook remains: %v", err)
			}
			continue
		}
		if left := read(t, path); strings.Contains(left, `"kontext"`) || !strings.Contains(left, "other-tool") {
			t.Fatalf("removal must drop Kontext's hook and keep the other: %s", left)
		}
	}
}

// D1, D2.
func TestDoctorManagedPerUserHooks(t *testing.T) {
	_, defs := managedInstall(t)
	present := func(string) bool { return true }
	userConfig := filepath.Join(t.TempDir(), "config.toml")
	var out bytes.Buffer
	if !diagnose(&out, System, defs, present, userConfig, "") {
		t.Fatalf("complete managed install is unhealthy:\n%s", &out)
	}
	if !strings.Contains(out.String(), "Antigravity hooks: installed (") {
		t.Fatalf("doctor does not report Antigravity:\n%s", &out)
	}
	var perUser File
	for _, d := range defs {
		if d.Agent == "antigravity" {
			perUser = d.Files[0]
		}
	}
	if err := os.Remove(perUser.Path); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if diagnose(&out, System, defs, present, userConfig, "") {
		t.Fatalf("an installed agent without hooks is healthy:\n%s", &out)
	}
	if !strings.Contains(out.String(), "Antigravity hooks:") || !strings.Contains(out.String(), perUser.Path) {
		t.Fatalf("doctor does not name the unwired agent and its file:\n%s", &out)
	}
	// Root without a home folder: nothing to read, and nothing reported broken.
	// A user's overrides in root's environment do not count either.
	userCodex := filepath.Join(t.TempDir(), "user-codex")
	write(t, filepath.Join(userCodex, "config.toml"), "[features]\nhooks = false\n", 0o600)
	write(t, filepath.Join(userCodex, "hooks.json"), "{", 0o600)
	t.Setenv("CODEX_HOME", userCodex)
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(t.TempDir(), "user-claude"))
	out.Reset()
	Diagnose(&out, System, "", func(string) bool { return true })
	if strings.Contains(out.String(), "user-codex") || strings.Contains(out.String(), "user-claude") {
		t.Fatalf("root's doctor read a user's override:\n%s", &out)
	}
	noHome, err := Definitions(System, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range noHome {
		if d.Agent != "antigravity" {
			continue
		}
		out.Reset()
		if !diagnose(&out, System, []Definition{d}, present, userConfig, "") || !strings.Contains(out.String(), "per user") {
			t.Fatalf("doctor without a home folder:\n%s", &out)
		}
	}
}

// L1: the list names exactly the files of the definitions, and a per-user file
// by a path that holds for every user.
func TestListNamesEveryManagedFile(t *testing.T) {
	hermetic.NotOnWindows(t, "ENG-1001", "the list leaves out the files Windows does not install yet")
	t.Setenv("CODEX_HOME", "")
	list, err := List(System, "/Users/someone")
	if err != nil {
		t.Fatal(err)
	}
	defs, err := Definitions(System, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != len(defs) {
		t.Fatalf("list has %d agents, definitions %d", len(list), len(defs))
	}
	for i, d := range defs {
		if list[i].Agent != d.Agent || len(list[i].Files) != len(d.Files) {
			t.Fatalf("%s: %+v", d.Agent, list[i])
		}
		for j, f := range d.Files {
			if got := list[i].Files[j]; got != f {
				t.Fatalf("%s: %+v, want %+v", d.Agent, got, f)
			}
			if f.Scope == User && !strings.HasPrefix(f.Path, "~/") {
				t.Fatalf("%s: per-user path %q names one user's home", d.Agent, f.Path)
			}
		}
	}
}
