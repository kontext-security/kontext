package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/claudemanaged"
)

// An MDM package installs only the managed-settings.d drop-in; the base
// managed settings file is absent on such a Mac.
func TestManagedClaudeHookStatusAcceptsDropInWithoutBaseFile(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "kontext")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := claudemanaged.TemplateJSON(binary)
	if err != nil {
		t.Fatal(err)
	}
	dropIn := filepath.Join(dir, "20-kontext.json")
	if err := os.WriteFile(dropIn, data, 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	healthy := printManagedClaudeHookStatus(&out, dropIn, filepath.Join(dir, "managed-settings.json"))
	if !healthy {
		t.Fatalf("healthy = false, want true; output = %q", out.String())
	}
	if !strings.Contains(out.String(), "Claude Code managed hooks: installed ("+dropIn) {
		t.Fatalf("output = %q, want the drop-in reported as installed", out.String())
	}
}

func TestOrganizationManagedHookPathsStartWithDropIn(t *testing.T) {
	paths := organizationManagedHookPaths()
	if len(paths) != 2 || paths[0] != claudemanaged.ManagedSettingsDropInPath || paths[1] != claudemanaged.DefaultManagedSettingsPath() {
		t.Fatalf("paths = %v", paths)
	}
}
