package hookinstall

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kontext-security/kontext/internal/claudemanaged"
)

func refreshFixture(t *testing.T) (string, string, []byte) {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, "kontext")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	settings := claudemanaged.Template(binary)
	delete(settings.Hooks, "Stop")
	delete(settings.Hooks, "SubagentStop")
	old, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "20-kontext.json")
	if err := os.WriteFile(path, old, 0644); err != nil {
		t.Fatal(err)
	}
	return path, binary, old
}

func TestRefreshClaudeMigratesFiveHooksAndIsIdempotent(t *testing.T) {
	path, binary, _ := refreshFixture(t)
	digest, err := ClaudeRefreshDigest(path, binary)
	if err != nil || digest == "" {
		t.Fatalf("plan: %q %v", digest, err)
	}
	if err := RefreshClaude(path, binary, digest); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := claudemanaged.Validate(data, binary); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0644 {
		t.Fatalf("mode: %v %v", info, err)
	}
	if digest, err := ClaudeRefreshDigest(path, binary); err != nil || digest != "" {
		t.Fatalf("unchanged: %q %v", digest, err)
	}
}

func TestRefreshClaudeRejectsChangesAfterApproval(t *testing.T) {
	path, binary, old := refreshFixture(t)
	digest, err := ClaudeRefreshDigest(path, binary)
	if err != nil {
		t.Fatal(err)
	}
	changed := append(old, '\n') // Still owned, but no longer the approved bytes.
	if err := os.WriteFile(path, changed, 0644); err != nil {
		t.Fatal(err)
	}
	if err := RefreshClaude(path, binary, digest); err == nil {
		t.Fatal("overwrote a changed configuration")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(changed) {
		t.Fatalf("changed file: %s %v", got, err)
	}
}

func TestRefreshClaudeRefusesMissingForeignAndSymlinkFiles(t *testing.T) {
	for _, kind := range []string{"missing", "foreign", "symlink", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			path, binary, old := refreshFixture(t)
			var err error
			switch kind {
			case "missing":
				err = os.Remove(path)
			case "foreign":
				var data map[string]any
				if err := json.Unmarshal(old, &data); err != nil {
					t.Fatal(err)
				}
				data["allowManagedHooksOnly"] = true
				raw, _ := json.Marshal(data)
				err = os.WriteFile(path, raw, 0644)
			case "malformed":
				err = os.WriteFile(path, []byte("{"), 0644)
			case "symlink":
				if err := os.Rename(path, path+".target"); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(path+".target", path)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ClaudeRefreshDigest(path, binary); err == nil {
				t.Fatal("planned an unsafe migration")
			}
			if err := RefreshClaude(path, binary, "anything"); err == nil {
				t.Fatal("applied an unsafe migration")
			}
		})
	}
}
