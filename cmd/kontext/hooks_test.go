package main

import (
	"github.com/kontext-security/kontext/internal/managedobserve"
	"io"
	"os"
	"path/filepath"
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
	t.Setenv("HOME", home)
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
