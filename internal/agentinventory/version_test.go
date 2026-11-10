package agentinventory

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func TestParseVersion(t *testing.T) {
	for output, want := range map[string]string{
		"2.1.300 (Claude Code)\n":   "2.1.300",
		"codex-cli 0.162.1\n":       "0.162.1",
		"2026.10.22-27dcf5f\n":      "2026.10.22-27dcf5f",
		"3.21.13":                   "3.21.13",
		"Usage: gemini [options]\n": "",
		"version 7\n":               "",
	} {
		if got := parseVersion(output); got != want {
			t.Errorf("parseVersion(%q) = %q, want %q", output, got, want)
		}
	}
}

// The daemon's PATH may not hold the folders agents install to, so a program
// in one of the fixed folders counts without being on PATH.
func TestProgramInAFixedFolderCounts(t *testing.T) {
	t.Run("a program", func(t *testing.T) {
		home := t.TempDir()
		executableFixture(t, filepath.Join(home, ".local", "bin", "codex"))
		t.Setenv("PATH", t.TempDir())
		if got, err := agentInstalled(home, "codex", map[string]bool{}); got != InstalledYes || err != nil {
			t.Fatalf("installed = %s, %v", got, err)
		}
	})
	// What makes a file a program is the execute bit on unix and the
	// extension on Windows; a file without it is not an install.
	t.Run("a file that is no program", func(t *testing.T) {
		home := t.TempDir()
		path := filepath.Join(home, ".local", "bin", "codex")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", t.TempDir())
		if got, err := agentInstalled(home, "codex", map[string]bool{}); got != InstalledNo || err != nil {
			t.Fatalf("installed = %s, %v", got, err)
		}
	})
	t.Run("a folder named like the program", func(t *testing.T) {
		home := t.TempDir()
		name := "codex"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		if err := os.MkdirAll(filepath.Join(home, ".local", "bin", name), 0o700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", t.TempDir())
		if got, err := agentInstalled(home, "codex", map[string]bool{}); got != InstalledNo || err != nil {
			t.Fatalf("installed = %s, %v", got, err)
		}
	})
}

// A CLI's --version runs with its own folder and the install folders ahead
// of the daemon's PATH, joined the way this OS splits PATH. The system
// folders are unix paths: on Windows, where a path without a drive is taken
// on the current one, they stay off the PATH.
func TestVersionPathSplitsIntoItsFolders(t *testing.T) {
	home, bin, onPath := t.TempDir(), t.TempDir(), t.TempDir()
	t.Setenv("PATH", onPath)
	system := []string{"/opt/homebrew/bin", "/usr/local/bin"}
	SystemCLIDirs = system
	t.Cleanup(func() { SystemCLIDirs = nil })
	name := "codex"
	if runtime.GOOS == "windows" {
		name, system = name+".exe", nil
	}
	got := filepath.SplitList(versionPath(home, filepath.Join(bin, name)))
	want := append([]string{bin}, system...)
	want = append(want, filepath.Join(home, ".local", "bin"), filepath.Join(home, ".bun", "bin"), filepath.Join(home, ".npm-global", "bin"), onPath)
	if !slices.Equal(got, want) {
		t.Fatalf("PATH folders = %q, want %q", got, want)
	}
}

// The version run itself gets that PATH: a CLI that needs a program from an
// install folder, as an npm shim needs node, finds it though the daemon's
// PATH does not hold the folder.
func TestVersionRunFindsWhatTheCLINeedsInAnInstallFolder(t *testing.T) {
	home, bin := t.TempDir(), t.TempDir()
	t.Setenv("PATH", t.TempDir())
	scriptFixture(t, filepath.Join(home, ".local", "bin", "kx-version-helper"), "echo 9.8.7")
	cli := scriptFixture(t, filepath.Join(bin, "codex"), "kx-version-helper")
	if got, err := runVersion(home, cli); got != "9.8.7" || err != nil {
		t.Fatalf("version = %q, %v", got, err)
	}
}

// scriptFixture writes a one-command script this OS runs as a program, a
// shell script on unix and a batch file on Windows, and returns its path.
func scriptFixture(t *testing.T, path, command string) string {
	t.Helper()
	content := "#!/bin/sh\n" + command + "\n"
	if runtime.GOOS == "windows" {
		path, content = path+".cmd", "@echo off\r\ncall "+command+"\r\n"
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}
