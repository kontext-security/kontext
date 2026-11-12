package main

import (
	"github.com/kontext-security/kontext/internal/hermetic"
	"github.com/kontext-security/kontext/internal/managedobserve"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestHooksCommandContract(t *testing.T) {
	root := hooksCmd()
	for _, action := range []string{"install", "remove"} {
		cmd, _, err := root.Find([]string{action})
		if err != nil {
			t.Fatal(err)
		}
		if cmd.Name() != action {
			t.Fatalf("missing %s", action)
		}
		if err := cmd.ParseFlags([]string{"--scope", "system", "--dry-run"}); err != nil {
			t.Fatal(err)
		}
		if cmd.Flags().Lookup("scope") == nil || cmd.Flags().Lookup("dry-run") == nil {
			t.Fatal("missing flags")
		}
		if action == "install" && cmd.Flags().Lookup("binary") == nil {
			t.Fatal("missing binary")
		}
		if err := cmd.Args(cmd, []string{"unexpected"}); err == nil {
			t.Fatal("accepted positional argument")
		}
	}
}

func TestDoctorIgnoresLocalHooksWhenClaudeAbsent(t *testing.T) {
	home := t.TempDir()
	hermetic.SetHome(t, home)
	path := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"disableAllHooks":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	old := doctorAgentPresent
	t.Cleanup(func() { doctorAgentPresent = old })
	for _, present := range []bool{false, true} {
		doctorAgentPresent = func(string, string) bool { return present }
		_, healthy := checkHooks(io.Discard, managedobserve.DoctorStatus{})
		if healthy == present {
			t.Fatalf("present=%v healthy=%v", present, healthy)
		}
	}
}

// System scope refuses before touching any file when the process lacks the
// privilege its OS asks for: root on macOS, an elevated token on Windows.
func TestHooksSystemScopeNeedsPrivilege(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("kontext hooks runs on macOS and Windows")
	}
	old := hooksPrivileged
	hooksPrivileged = func() bool { return false }
	t.Cleanup(func() { hooksPrivileged = old })
	hermetic.SetHome(t, t.TempDir())
	binary := filepath.Join(t.TempDir(), "kontext")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	for _, args := range [][]string{{"install", "--scope", "system", "--binary", binary}, {"remove", "--scope", "system"}} {
		cmd := hooksCmd()
		cmd.SetArgs(args)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		if err := cmd.Execute(); err == nil || err.Error() != hooksPrivilegeHint {
			t.Errorf("%v: err = %v, want %q", args, err, hooksPrivilegeHint)
		}
	}
}

// An MDM runs its scripts as root with an empty environment, so no home folder
// resolves. System scope writes only machine-wide files and must not ask for
// one; user scope has nowhere to write without it.
func TestHooksSystemScopeNeedsNoHome(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("kontext hooks runs on macOS and Windows")
	}
	hermetic.SetHome(t, "")
	_, noHome := os.UserHomeDir()
	if noHome == nil {
		t.Fatal("the home folder still resolves")
	}
	binary := filepath.Join(t.TempDir(), "kontext")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	for _, action := range [][]string{{"install", "--binary", binary}, {"remove"}} {
		for _, scope := range []string{"system", "user"} {
			cmd := hooksCmd()
			cmd.SetArgs(append(action, "--scope", scope, "--dry-run"))
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			// A dry run plans against this machine's own files, which decide
			// everything else about the result; only the home error is checked.
			err := cmd.Execute()
			if stopped := err != nil && err.Error() == noHome.Error(); stopped != (scope == "user") {
				t.Errorf("%s --scope %s without a home folder: err = %v", action[0], scope, err)
			}
		}
	}
}
