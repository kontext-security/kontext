package codexmanaged

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectInstallationLayers(t *testing.T) {
	valid, err := TemplateJSON("/opt/homebrew/bin/kontext")
	if err != nil {
		t.Fatal(err)
	}
	partial := Template("/opt/homebrew/bin/kontext")
	delete(partial.Hooks, "Stop")
	partialJSON, _ := json.Marshal(partial)
	other, err := TemplateJSON("/Applications/Kontext/runtime/bin/kontext")
	if err != nil {
		t.Fatal(err)
	}
	foreign := []byte(`{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"/enterprise/audit"}]}]}}`)
	for _, tc := range []struct {
		name                string
		system, user        []byte
		wantErr, incomplete bool
		source              string
		layers              int
	}{
		{name: "system only", system: valid, source: "system"},
		{name: "system with empty user hooks", system: valid, user: []byte(`{"hooks":{}}`), source: "system"},
		{name: "system with foreign user hooks", system: valid, user: foreign, source: "system", wantErr: true, incomplete: true},
		{name: "foreign system with user hooks", system: foreign, user: valid, source: "user", wantErr: true, incomplete: true},
		{name: "user only", user: valid, source: "user"},
		{name: "both same binary", system: valid, user: valid, layers: 2},
		{name: "both different binaries", system: valid, user: other, layers: 2},
		{name: "partial system with valid user", system: partialJSON, user: valid, source: "user", wantErr: true, incomplete: true},
		{name: "valid system with partial user", system: valid, user: partialJSON, source: "system", wantErr: true, incomplete: true},
		{name: "missing", wantErr: true, incomplete: true},
		{name: "partial system", system: partialJSON, wantErr: true, incomplete: true},
		{name: "corrupt system with valid user", system: []byte(`{`), user: valid, source: "user", wantErr: true},
		{name: "valid system with corrupt user", system: valid, user: []byte(`{`), source: "system", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			paths := InstallationPaths{SystemHooks: filepath.Join(dir, "system"), UserHooks: filepath.Join(dir, "user")}
			for path, data := range map[string][]byte{paths.SystemHooks: tc.system, paths.UserHooks: tc.user} {
				if data != nil {
					if err := os.WriteFile(path, data, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			got, err := InspectInstallation(paths)
			if (err != nil) != tc.wantErr || errors.Is(err, ErrIncompleteInstallation) != tc.incomplete {
				t.Fatalf("installation=%+v, err=%v", got, err)
			}
			wantLayers := tc.layers
			if tc.source != "" {
				wantLayers = 1
			}
			if len(got.Layers) != wantLayers {
				t.Fatalf("installation=%+v, want %d complete layers", got, wantLayers)
			}
			if tc.source != "" && got.Layers[0] != (InstallationLayer{Path: filepath.Join(dir, tc.source), Binary: "/opt/homebrew/bin/kontext"}) {
				t.Fatalf("installation=%+v", got)
			}
			for path, data := range map[string][]byte{paths.SystemHooks: tc.system, paths.UserHooks: tc.user} {
				after, err := os.ReadFile(path)
				if data == nil {
					if !os.IsNotExist(err) {
						t.Fatalf("discovery created %s", path)
					}
				} else if err != nil || string(after) != string(data) {
					t.Fatalf("discovery changed %s", path)
				}
			}
		})
	}
}

func TestInspectInstallationRejectsEventsSplitAcrossLayers(t *testing.T) {
	dir := t.TempDir()
	paths := InstallationPaths{SystemHooks: filepath.Join(dir, "system"), UserHooks: filepath.Join(dir, "user")}
	system := Template("/opt/homebrew/bin/kontext")
	user := Settings{Hooks: map[string][]MatcherGroup{"Stop": system.Hooks["Stop"]}}
	delete(system.Hooks, "Stop")
	for path, settings := range map[string]Settings{paths.SystemHooks: system, paths.UserHooks: user} {
		raw, _ := json.Marshal(settings)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := InspectInstallation(paths)
	if !errors.Is(err, ErrIncompleteInstallation) || len(got.Layers) != 0 {
		t.Fatalf("installation=%+v, err=%v", got, err)
	}
}

func TestDefaultInstallationPathsHonorsCodexHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, custom := range []string{"", filepath.Join(home, "custom")} {
		t.Setenv("CODEX_HOME", custom)
		paths, err := DefaultInstallationPaths()
		if err != nil {
			t.Fatal(err)
		}
		base := custom
		if base == "" {
			base = filepath.Join(home, ".codex")
		}
		if paths.SystemHooks != "/etc/codex/hooks.json" || paths.UserHooks != filepath.Join(base, "hooks.json") || paths.UserConfig != filepath.Join(base, "config.toml") {
			t.Fatalf("paths=%+v", paths)
		}
		if _, err := os.Stat(base); !os.IsNotExist(err) {
			t.Fatalf("discovery created %s", base)
		}
	}
}
