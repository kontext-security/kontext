package platform

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

const (
	probeEnv    = "KONTEXT_PLATFORM_PROBE"
	errorPrefix = "error: "
)

// wantProgramData is where this machine's system directories belong, read
// without the environment and whether or not ProgramData was moved.
func wantProgramData(t *testing.T) string {
	t.Helper()
	windowsDir, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.VolumeName(windowsDir) + `\ProgramData`
}

// TestProbeDirectories is the child of the tests below: it prints the
// directories as a process started with that environment sees them.
func TestProbeDirectories(t *testing.T) {
	if os.Getenv(probeEnv) == "" {
		t.Skip("runs as the child of the fresh-process tests")
	}
	dirs := map[string]string{}
	for name, dir := range map[string]func() (string, error){
		"system": SystemConfigDir, "codex": CodexSystemDir, "claude": ClaudeManagedDir, "user": UserStateDir,
	} {
		path, err := dir()
		if err != nil {
			path = errorPrefix + err.Error()
		}
		dirs[name] = path
	}
	out, err := json.Marshal(dirs)
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout.WriteString("\nPROBE " + string(out) + "\n")
}

// probe runs the child in a fresh process, so no folder lookup this process
// made can hide what the environment does.
func probe(t *testing.T, env ...string) map[string]string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestProbeDirectories$")
	cmd.Env = append(env, probeEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "PROBE "); ok {
			dirs := map[string]string{}
			if err := json.Unmarshal([]byte(rest), &dirs); err != nil {
				t.Fatal(err)
			}
			return dirs
		}
	}
	t.Fatalf("child printed no directories:\n%s", out)
	return nil
}

// The drive comes from the Windows folder, on whichever drive that is.
func TestProgramDataIsOnTheDriveOfTheWindowsFolder(t *testing.T) {
	for _, test := range []struct{ windowsDir, want string }{
		{`C:\Windows`, `C:\ProgramData\Kontext`},
		{`D:\Windows`, `D:\ProgramData\Kontext`},
	} {
		if got := programDataOn(test.windowsDir, "Kontext"); got != test.want {
			t.Errorf("programDataOn(%q) = %q, want %q", test.windowsDir, got, test.want)
		}
	}
}

// A system directory is one a process trusts, so a variable a user can set
// must not move it.
func TestSystemDirectoriesIgnoreTheEnvironment(t *testing.T) {
	programData := wantProgramData(t)
	elsewhere := t.TempDir()
	var env []string
	for _, name := range []string{"ProgramData", "ALLUSERSPROFILE", "ProgramFiles", "ProgramW6432", "SystemDrive", "SystemRoot", "windir", "PUBLIC"} {
		env = append(env, name+"="+elsewhere)
	}
	dirs := probe(t, env...)
	for name, want := range map[string]string{
		"system": filepath.Join(programData, "Kontext"),
		"codex":  filepath.Join(programData, "OpenAI", "Codex"),
		"claude": `C:\Program Files\ClaudeCode`,
	} {
		if dirs[name] != want {
			t.Errorf("%s = %q, want %q", name, dirs[name], want)
		}
	}
}

// Tests point LOCALAPPDATA at a temporary folder.
func TestUserStateDirFollowsLocalAppData(t *testing.T) {
	local := t.TempDir()
	if got, want := probe(t, "LOCALAPPDATA="+local)["user"], filepath.Join(local, "Kontext"); got != want {
		t.Fatalf("UserStateDir() = %q, want %q", got, want)
	}
}

// A hook started with a filtered environment still finds the folder its daemon
// uses; only Go's own SYSTEMROOT reaches this child.
func TestUserStateDirWithoutTheEnvironment(t *testing.T) {
	got := probe(t)["user"]
	if !filepath.IsAbs(got) || !strings.HasSuffix(got, filepath.Join("AppData", "Local", "Kontext")) {
		t.Fatalf("UserStateDir() = %q, want an absolute path under AppData\\Local", got)
	}
}

// The folder may not exist yet: this package computes paths, and creating them
// is the caller's business.
func TestUserStateDirDoesNotNeedTheFolder(t *testing.T) {
	home := t.TempDir()
	if got, want := probe(t, "USERPROFILE="+home)["user"], filepath.Join(home, "AppData", "Local", "Kontext"); got != want {
		t.Fatalf("UserStateDir() = %q, want %q", got, want)
	}
}

// The known folder follows USERPROFILE, and a relative path would put the socket
// under each process's directory.
func TestUserStateDirRefusesARelativeProfile(t *testing.T) {
	got := probe(t, `USERPROFILE=relative\folder`)["user"]
	if !strings.HasPrefix(got, errorPrefix) {
		t.Fatalf("UserStateDir() = %q, want an error", got)
	}
}

// A relative value would put the socket under each process's directory, so a
// hook and its daemon would disagree.
func TestUserStateDirRefusesARelativeLocalAppData(t *testing.T) {
	got := probe(t, `LOCALAPPDATA=relative\folder`)["user"]
	if !filepath.IsAbs(got) || !strings.HasSuffix(got, filepath.Join("AppData", "Local", "Kontext")) {
		t.Fatalf("UserStateDir() = %q, want an absolute path under AppData\\Local", got)
	}
}

// A hook started with a filtered environment reads the same system files as
// its daemon.
func TestSystemDirectoriesWithoutTheEnvironment(t *testing.T) {
	programData := wantProgramData(t)
	dirs := probe(t)
	for name, want := range map[string]string{
		"system": filepath.Join(programData, "Kontext"),
		"codex":  filepath.Join(programData, "OpenAI", "Codex"),
		"claude": `C:\Program Files\ClaudeCode`,
	} {
		if dirs[name] != want {
			t.Errorf("%s = %q, want %q", name, dirs[name], want)
		}
	}
}
