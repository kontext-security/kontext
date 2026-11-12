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
//   R1  Machine-wide removal leaves a user's hook naming a deleted binary.
//   R2  One user's broken file stops the removal for every other user.
//   R3  Removal takes another tool's entries along with Kontext's.
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

// R1, R2, R3, F4: removal cleans the hook of every home, keeps other tools'
// entries, and a broken file of one user does not stop the next.
func TestSystemRemovalCleansEveryHome(t *testing.T) {
	opts, defs := managedInstall(t)
	root := t.TempDir()
	homes := map[string]string{}
	for _, name := range []string{"only-kontext", "with-foreign", "broken", "no-antigravity"} {
		homes[name] = filepath.Join(root, name)
		if err := os.MkdirAll(homes[name], 0o755); err != nil {
			t.Fatal(err)
		}
	}
	hooks := func(name string) string { return antigravitymanaged.UserHooksPath(homes[name]) }
	for _, name := range []string{"only-kontext", "with-foreign"} {
		o := Options{Scope: System, PerUser: true, Home: homes[name], Binary: opts.Binary, NoBackup: true}
		if name == "with-foreign" {
			write(t, hooks(name), `{"other-tool":{"Stop":[{"type":"command","command":"/bin/true"}]}}`, 0o600)
		}
		if err := Install(o); err != nil {
			t.Fatal(err)
		}
		if _, err := antigravitymanaged.ValidateInstalled([]byte(read(t, hooks(name)))); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(read(t, hooks("with-foreign")), "other-tool") {
		t.Fatal("install dropped another tool's hook")
	}
	write(t, hooks("broken"), "{", 0o600)
	previous := perUserHomes
	perUserHomes = func(Options) []userHome {
		var list []userHome
		for _, name := range []string{"broken", "only-kontext", "with-foreign", "no-antigravity"} {
			list = append(list, userHome{Path: homes[name], UID: os.Geteuid(), GID: os.Getegid()})
		}
		return list
	}
	t.Cleanup(func() { perUserHomes = previous })

	var out bytes.Buffer
	opts.Out = &out
	if err := runDefinitions(opts, defs, true); err != nil {
		t.Fatalf("a user's broken file failed the removal: %v\n%s", err, &out)
	}
	if _, err := os.Lstat(hooks("only-kontext")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a file holding only Kontext's hook remains: %v", err)
	}
	if left := read(t, hooks("with-foreign")); strings.Contains(left, "kontext") || !strings.Contains(left, "other-tool") {
		t.Fatalf("removal must drop Kontext's hook and keep the other: %s", left)
	}
	if read(t, hooks("broken")) != "{" {
		t.Fatal("removal rewrote a file it could not read")
	}
	if !strings.Contains(out.String(), "error\tuser\t"+homes["broken"]+"\t"+hooks("broken")) {
		t.Fatalf("the broken file is not reported:\n%s", &out)
	}
	if _, err := os.Lstat(filepath.Join(homes["no-antigravity"], ".gemini")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removal created a folder: %v", err)
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

// Root finds the homes to clean under /Users and never treats a link, the
// shared folder or a root-owned folder as one.
func TestLocalHomes(t *testing.T) {
	hermetic.NotOnWindows(t, "ENG-1001", "per-user hook files exist on macOS only")
	dir := t.TempDir()
	for _, name := range []string{"alice", "Shared"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(dir, ".localized"), "", 0o644)
	if err := os.Symlink(filepath.Join(dir, "alice"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	got := localHomes(dir)
	if len(got) != 1 || got[0].Path != filepath.Join(dir, "alice") || got[0].UID != os.Geteuid() {
		t.Fatalf("homes = %+v", got)
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
