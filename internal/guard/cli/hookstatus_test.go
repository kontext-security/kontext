package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/claudemanaged"
	"github.com/kontext-security/kontext/internal/codexmanaged"
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

// A base managed settings file with unrelated enterprise policy next to a
// valid drop-in must not read as an incomplete Kontext hook set.
func TestOrganizationManagedHookStatusIgnoresBaseFileWhenDropInInstalled(t *testing.T) {
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
	base := filepath.Join(dir, "managed-settings.json")
	if err := os.WriteFile(base, []byte(`{"permissions":{"deny":["Bash(rm -rf *)"]}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if !printOrganizationClaudeHookStatus(&out, dropIn, base) {
		t.Fatalf("healthy = false, want true; output = %q", out.String())
	}
	if strings.Contains(out.String(), "incomplete") {
		t.Fatalf("output = %q, want the base file left alone", out.String())
	}
}

// With no drop-in, a base file that lacks the hooks is still reported.
func TestOrganizationManagedHookStatusJudgesBaseFileWithoutDropIn(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "managed-settings.json")
	if err := os.WriteFile(base, []byte(`{"permissions":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if printOrganizationClaudeHookStatus(&out, filepath.Join(dir, "20-kontext.json"), base) {
		t.Fatalf("healthy = true, want false; output = %q", out.String())
	}
	if !strings.Contains(out.String(), "incomplete or disabled") {
		t.Fatalf("output = %q, want the base file judged", out.String())
	}
}

func TestOrganizationManagedHookPathsStartWithDropIn(t *testing.T) {
	paths := organizationManagedHookPaths()
	if len(paths) != 2 || paths[0] != claudemanaged.ManagedSettingsDropInPath || paths[1] != claudemanaged.DefaultManagedSettingsPath() {
		t.Fatalf("paths = %v", paths)
	}
}

func TestCodexHookStatusRecognizesSystemInstallation(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		missingBinary, disabled bool
	}{
		{name: "healthy"}, {name: "missing binary", missingBinary: true}, {name: "disabled feature", disabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			binary := filepath.Join(dir, "kontext")
			if !tc.missingBinary {
				if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0755); err != nil {
					t.Fatal(err)
				}
			}
			paths := codexmanaged.InstallationPaths{SystemHooks: filepath.Join(dir, "system.json"), UserHooks: filepath.Join(dir, "user.json"), UserConfig: filepath.Join(dir, "config.toml")}
			raw, err := codexmanaged.TemplateJSON(binary)
			if err != nil {
				t.Fatal(err)
			}
			config := "[features]\nhooks = true\n"
			if tc.disabled {
				config = "[features]\nhooks = false\n"
			}
			for path, data := range map[string][]byte{paths.SystemHooks: raw, paths.UserHooks: []byte(`{"hooks":{}}`), paths.UserConfig: []byte(config)} {
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			var out bytes.Buffer
			got := printCodexHookStatusAt(&out, paths)
			want := !tc.missingBinary && !tc.disabled
			if got != want {
				t.Fatalf("healthy=%t, output=%s", got, &out)
			}
			if want && (!strings.Contains(out.String(), paths.SystemHooks) || strings.Contains(out.String(), "incomplete")) {
				t.Fatalf("output=%s", &out)
			}
		})
	}
}

// Exercise the combined organization path used by doctor, with valid Claude
// settings in every case. A good personal Codex installation must not mask
// a missing or invalid system installation.
func TestOrganizationManagedHookStatusRequiresSystemCodex(t *testing.T) {
	for _, name := range []string{"valid", "missing", "malformed", "partial", "missing executable", "not executable"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("CODEX_HOME", filepath.Join(dir, "user"))
			binary := filepath.Join(dir, "kontext")
			if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0755); err != nil {
				t.Fatal(err)
			}
			claudePath := filepath.Join(dir, "claude.json")
			claude, err := claudemanaged.TemplateJSON(binary)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(claudePath, claude, 0600); err != nil {
				t.Fatal(err)
			}
			personal, err := codexmanaged.TemplateJSON(binary)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(dir, "user"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "user/hooks.json"), personal, 0600); err != nil {
				t.Fatal(err)
			}
			// No user config.toml: the package must not require a user opt-in.
			systemPath := filepath.Join(dir, "system.json")
			systemBinary := binary
			if name == "missing executable" || name == "not executable" {
				systemBinary = filepath.Join(dir, "system/kontext")
				if name == "not executable" {
					if err := os.Mkdir(filepath.Dir(systemBinary), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(systemBinary, []byte("#!/bin/sh\n"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			system := codexmanaged.Template(systemBinary)
			if name == "partial" {
				delete(system.Hooks, "Stop")
			}
			raw, err := json.Marshal(system)
			if err != nil {
				t.Fatal(err)
			}
			if name == "malformed" {
				raw = []byte("{")
			}
			if name != "missing" {
				if err := os.WriteFile(systemPath, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			var out bytes.Buffer
			got := printOrganizationManagedHookStatus(&out, systemPath, claudePath)
			if got != (name == "valid") {
				t.Fatalf("healthy=%t; output=%s", got, &out)
			}
			if !strings.Contains(out.String(), "Codex hooks:") {
				t.Fatalf("Codex check skipped: %s", &out)
			}
			if name == "valid" && !strings.Contains(out.String(), systemPath) {
				t.Fatalf("system path not reported: %s", &out)
			}
		})
	}
}
