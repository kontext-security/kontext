package hookinstall

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/codexmanaged"
)

func fixture(t *testing.T, scope Scope) (Options, []Definition) {
	t.Helper()
	t.Setenv("CODEX_HOME", "")
	root := t.TempDir()
	opts := Options{Scope: scope, Home: "/Users/test", Binary: filepath.Join(root, "kontext")}
	write(t, opts.Binary, "#!/bin/sh\n", 0755)
	defs, err := Definitions(scope, opts.Home)
	if err != nil {
		t.Fatal(err)
	}
	for i := range defs {
		for j := range defs[i].Files {
			defs[i].Files[j].Path = filepath.Join(root, defs[i].Files[j].Path)
		}
	}
	return opts, defs
}
func write(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}
func read(t *testing.T, path string) string {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return string(b)
}

func TestDefinitionsInstallRemove(t *testing.T) {
	for _, scope := range []Scope{User, System} {
		t.Run(string(scope), func(t *testing.T) {
			opts, defs := fixture(t, scope)
			var out bytes.Buffer
			opts.Out = &out
			opts.DryRun = true
			if err := runDefinitions(opts, defs, false); err != nil {
				t.Fatal(err)
			}
			got := strings.ReplaceAll(out.String(), filepath.Dir(opts.Binary), "<root>")
			golden, err := os.ReadFile("testdata/" + string(scope) + "-dry-run.txt")
			if err != nil {
				t.Fatal(err)
			}
			if got != string(golden) {
				t.Fatalf("dry run:\n%s", got)
			}
			for _, d := range defs {
				for _, f := range d.Files {
					if _, err := os.Stat(filepath.Dir(f.Path)); !os.IsNotExist(err) {
						t.Fatalf("dry run created %s", f.Path)
					}
				}
			}
			opts.DryRun = false
			out.Reset()
			if err := runDefinitions(opts, defs, false); err != nil {
				t.Fatal(err)
			}
			for _, d := range defs {
				if _, err := d.Validate([]byte(read(t, d.Files[0].Path))); err != nil {
					t.Fatal(err)
				}
				for _, f := range d.Files {
					info, err := os.Stat(f.Path)
					if err != nil {
						t.Fatal(err)
					}
					want := os.FileMode(0600)
					if f.Scope == System {
						want = 0644
					}
					if info.Mode().Perm() != want {
						t.Fatalf("%s mode %v", f.Path, info.Mode())
					}
				}
			}
			out.Reset()
			if err := runDefinitions(opts, defs, false); err != nil {
				t.Fatal(err)
			}
			if strings.Count(out.String(), "skip\t") != 3 {
				t.Fatalf("re-run wrote: %s", &out)
			}
			for _, d := range defs {
				for _, f := range d.Files {
					matches, _ := filepath.Glob(f.Path + ".*backup*")
					if len(matches) != 0 {
						t.Fatalf("re-run backed up %s", f.Path)
					}
				}
			}
			if err := runDefinitions(opts, defs, true); err != nil {
				t.Fatal(err)
			}
			for _, d := range defs {
				for _, f := range d.Files {
					if _, err := os.Stat(f.Path); !os.IsNotExist(err) {
						t.Fatalf("owned file remains: %s", f.Path)
					}
				}
			}
			if err := runDefinitions(opts, defs, true); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestForeignContentSurvives(t *testing.T) {
	for _, scope := range []Scope{User, System} {
		t.Run(string(scope), func(t *testing.T) {
			opts, defs := fixture(t, scope)
			hooks, config := defs[1].Files[0].Path, defs[1].Files[1].Path
			foreign := `{"meta": "keep", "hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo foreign"}]}]}}`
			write(t, hooks, foreign, 0644)
			original := "model = 'test'\n[features]\nhooks = false # user preference\njs_repl = true\n"
			write(t, config, original, 0644)
			if err := runDefinitions(opts, defs, false); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(read(t, hooks), "echo foreign") {
				t.Fatal("foreign hook removed")
			}
			write(t, config, read(t, config)+"\n[extra]\nvalue = 'keep'\n", 0644)
			if err := runDefinitions(opts, defs, true); err != nil {
				t.Fatal(err)
			}
			if got := read(t, config); got != original+"\n[extra]\nvalue = 'keep'\n" {
				t.Fatalf("restored config = %q", got)
			}
			if got := read(t, hooks); !strings.Contains(got, "echo foreign") || strings.Contains(got, "kontext") {
				t.Fatalf("remaining hooks %s", got)
			}
			write(t, defs[0].Files[0].Path, `{"permissions":{}}`, 0644)
			if err := runDefinitions(opts, defs, true); err != nil {
				t.Fatal(err)
			}
			if got := read(t, defs[0].Files[0].Path); got != `{"permissions":{}}` {
				t.Fatal(got)
			}
			if err := runDefinitions(opts, defs, false); err == nil {
				t.Fatal("overwrote foreign Claude file")
			}
		})
	}
}

func TestFeatureOwnership(t *testing.T) {
	for _, original := range []string{"", "model = 'x'\n", "[features]\njs_repl = true\n", "[features]\nhooks = true\n", "[features]\r\nhooks = false # original\r\n", "features.hooks = true\n", "features = { hooks = true }\n", "[features]\ncodex_hooks = true\n"} {
		t.Run(original, func(t *testing.T) {
			next, err := codexmanaged.EnableHooksFeature(original)
			if err != nil {
				t.Fatal(err)
			}
			marked := []byte(next)
			if next != original {
				marked = markFeature([]byte(original), marked)
			}
			removed, err := removeFeature(marked)
			if err != nil {
				t.Fatal(err)
			}
			if strings.TrimSpace(string(removed)) != strings.TrimSpace(original) {
				t.Fatalf("%q -> %q -> %q", original, marked, removed)
			}
		})
	}
}

func TestInstallRefusesMalformedConfigBeforeWriting(t *testing.T) {
	opts, defs := fixture(t, System)
	write(t, defs[1].Files[1].Path, "[features\n", 0644)
	if err := runDefinitions(opts, defs, false); err == nil {
		t.Fatal("accepted malformed config")
	}
	if _, err := os.Stat(defs[0].Files[0].Path); !os.IsNotExist(err) {
		t.Fatal("partial install")
	}
}

func TestDoctorEveryAgentAndScope(t *testing.T) {
	for _, scope := range []Scope{User, System} {
		for _, agent := range []string{"claude_code", "codex"} {
			for _, state := range []string{"absent", "valid", "missing", "broken", "disabled", "missing binary"} {
				t.Run(string(scope)+"/"+agent+"/"+state, func(t *testing.T) {
					opts, defs := fixture(t, scope)
					if err := runDefinitions(opts, defs, false); err != nil {
						t.Fatal(err)
					}
					for _, def := range defs {
						if def.Agent == agent {
							switch state {
							case "absent", "broken":
								write(t, def.Files[0].Path, "{", 0644)
							case "missing":
								if err := os.Remove(def.Files[0].Path); err != nil {
									t.Fatal(err)
								}
							case "disabled":
								if agent == "codex" {
									write(t, def.Files[1].Path, "[features]\nhooks = false\n", 0644)
								} else {
									write(t, def.Files[0].Path, `{"disableAllHooks":true}`, 0644)
								}
							case "missing binary":
								if err := os.Remove(opts.Binary); err != nil {
									t.Fatal(err)
								}
							}
						}
					}
					var out bytes.Buffer
					healthy := diagnose(&out, defs, func(id string) bool { return id == agent && state != "absent" }, filepath.Join(t.TempDir(), "config.toml"), "")
					want := state == "valid" || state == "absent"
					if healthy != want {
						t.Fatalf("healthy=%v want=%v: %s", healthy, want, &out)
					}
					if state == "absent" && !strings.Contains(out.String(), "hooks: not installed (agent not present)") {
						t.Fatal(&out)
					}
				})
			}
		}
	}
}

func TestDoctorUserOverrideDisablesSystemHooks(t *testing.T) {
	opts, defs := fixture(t, System)
	if err := runDefinitions(opts, defs, false); err != nil {
		t.Fatal(err)
	}
	user := filepath.Join(t.TempDir(), "config.toml")
	write(t, user, "[features]\nhooks = false\n", 0600)
	var out bytes.Buffer
	if diagnose(&out, defs, func(string) bool { return true }, user, "") {
		t.Fatal("ignored user override")
	}
	if !strings.Contains(out.String(), "disabled by user override") {
		t.Fatal(&out)
	}
}

func TestRefreshStaleHooksAndRemoveDryRun(t *testing.T) {
	for _, scope := range []Scope{User, System} {
		t.Run(string(scope), func(t *testing.T) {
			opts, defs := fixture(t, scope)
			stale := opts
			stale.Binary = filepath.Join(filepath.Dir(opts.Binary), "old", "kontext")
			write(t, stale.Binary, "#!/bin/sh\n", 0755)
			if err := runDefinitions(stale, defs, false); err != nil {
				t.Fatal(err)
			}
			if err := runDefinitions(opts, defs, false); err != nil {
				t.Fatal(err)
			}
			for _, d := range defs {
				binary, err := d.Validate([]byte(read(t, d.Files[0].Path)))
				if err != nil || binary != opts.Binary {
					t.Fatalf("stale hook survived: %s %v", binary, err)
				}
			}
			var out bytes.Buffer
			opts.Out = &out
			opts.DryRun = true
			if err := runDefinitions(opts, defs, true); err != nil {
				t.Fatal(err)
			}
			if strings.Count(out.String(), "would-remove\t") != 3 {
				t.Fatal(&out)
			}
			for _, d := range defs {
				for _, f := range d.Files {
					if _, err := os.Stat(f.Path); err != nil {
						t.Fatal("dry removal changed files", err)
					}
				}
			}
		})
	}
}

func TestForeignOnlyFilesUnchangedOnRemoval(t *testing.T) {
	opts, defs := fixture(t, System)
	data := []string{`{"permissions":{}}`, `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo foreign"}]}]}}`, "[features]\nhooks = true\n"}
	i := 0
	for _, d := range defs {
		for _, f := range d.Files {
			write(t, f.Path, data[i], 0644)
			i++
		}
	}
	if err := runDefinitions(opts, defs, true); err != nil {
		t.Fatal(err)
	}
	i = 0
	for _, d := range defs {
		for _, f := range d.Files {
			if got := read(t, f.Path); got != data[i] {
				t.Fatalf("foreign file changed %s", f.Path)
			}
			i++
		}
	}
}

func TestSystemInstallRefusesSymlink(t *testing.T) {
	opts, defs := fixture(t, System)
	target := filepath.Join(t.TempDir(), "foreign")
	write(t, target, "foreign", 0644)
	file := defs[0].Files[0].Path
	if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, file); err != nil {
		t.Fatal(err)
	}
	if err := runDefinitions(opts, defs, false); err == nil {
		t.Fatal("accepted system symlink")
	}
	if got := read(t, target); got != "foreign" {
		t.Fatal(got)
	}
}

func TestFeatureRemovalPreservesNewTableMembers(t *testing.T) {
	next, err := codexmanaged.EnableHooksFeature("")
	if err != nil {
		t.Fatal(err)
	}
	marked := markFeature(nil, []byte(next))
	marked = append(marked, []byte("\njs_repl = true\n")...)
	removed, err := removeFeature(marked)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(removed), "[features]") || !strings.Contains(string(removed), "js_repl = true") {
		t.Fatalf("changed table meaning: %s", removed)
	}
	if strings.Contains(string(removed), "hooks = true") {
		t.Fatal("owned flag remains")
	}
}

func TestFeatureRemovalIgnoresForeignMarkerText(t *testing.T) {
	for _, raw := range []string{
		"description = '''\nhooks = true # kontext-hooks-original:\n'''\n[features]\nhooks = true\n",
		"[other]\nhooks = true # kontext-hooks-original:\n[features]\nhooks = true\n",
	} {
		got, err := removeFeature([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != raw {
			t.Fatalf("changed foreign content: %s", got)
		}
	}
}

func TestDoctorRejectsBrokenOtherCodexLayer(t *testing.T) {
	opts, defs := fixture(t, System)
	if err := runDefinitions(opts, defs, false); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "hooks.json")
	write(t, other, "{", 0600)
	var out bytes.Buffer
	if diagnose(&out, defs, func(string) bool { return true }, "", other) {
		t.Fatal("ignored malformed user hooks")
	}
}

func TestUserCommandsHonorCodexHome(t *testing.T) {
	opts, defs := fixture(t, User)
	custom := filepath.Join(t.TempDir(), "custom-codex")
	t.Setenv("CODEX_HOME", custom)
	opts.ClaudePath = defs[0].Files[0].Path
	if err := Install(opts); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"hooks.json", "config.toml"} {
		if _, err := os.Stat(filepath.Join(custom, name)); err != nil {
			t.Fatal(err)
		}
	}
	actual, err := Definitions(User, opts.Home)
	if err != nil {
		t.Fatal(err)
	}
	if got := actual[1].Files[0].Path; got != filepath.Join(custom, "hooks.json") {
		t.Fatal(got)
	}
	if err := Remove(opts); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"hooks.json", "config.toml"} {
		if _, err := os.Stat(filepath.Join(custom, name)); !os.IsNotExist(err) {
			t.Fatalf("not removed: %s", name)
		}
	}
	// Setup compatibility is deliberate; it retains its historical home paths.
	legacy, err := definitions(User, opts.Home, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := legacy[1].Files[0].Path; got != filepath.Join(opts.Home, ".codex", "hooks.json") {
		t.Fatal(got)
	}
}

func TestInstallRejectsUnusableBinary(t *testing.T) {
	for _, state := range []string{"missing", "directory", "not executable"} {
		t.Run(state, func(t *testing.T) {
			opts, defs := fixture(t, System)
			if err := os.Remove(opts.Binary); err != nil {
				t.Fatal(err)
			}
			switch state {
			case "directory":
				if err := os.Mkdir(opts.Binary, 0755); err != nil {
					t.Fatal(err)
				}
			case "not executable":
				write(t, opts.Binary, "content", 0644)
			}
			if err := runDefinitions(opts, defs, false); err == nil {
				t.Fatal("accepted unusable binary")
			}
			if _, err := os.Stat(defs[0].Files[0].Path); !os.IsNotExist(err) {
				t.Fatal("wrote hooks")
			}
			opts.DryRun = true
			if err := runDefinitions(opts, defs, false); err != nil {
				t.Fatal("dry-run requires installed binary", err)
			}
		})
	}
}

func TestDoctorCodexLayers(t *testing.T) {
	for _, scope := range []Scope{System, User} {
		for _, state := range []string{"only owned", "same binary", "different binary", "foreign owned", "foreign other", "malformed owned", "malformed other", "missing other binary"} {
			t.Run(string(scope)+"/"+state, func(t *testing.T) {
				opts, defs := fixture(t, scope)
				if err := runDefinitions(opts, defs, false); err != nil {
					t.Fatal(err)
				}
				home := t.TempDir()
				t.Setenv("HOME", home)
				other := filepath.Join(home, ".codex", "hooks.json")
				otherBinary := opts.Binary
				if state == "different binary" || state == "missing other binary" {
					otherBinary = filepath.Join(home, "runtime", "bin", "kontext")
					if state == "different binary" {
						write(t, otherBinary, "#!/bin/sh\n", 0755)
					}
				}
				if state != "only owned" {
					raw, err := codexmanaged.TemplateJSON(otherBinary)
					if err != nil {
						t.Fatal(err)
					}
					write(t, other, string(raw), 0600)
				}
				owned := defs[1].Files[0].Path
				switch state {
				case "foreign owned", "foreign other":
					raw, err := codexmanaged.TemplateJSON("/enterprise/other-agent")
					if err != nil {
						t.Fatal(err)
					}
					path := owned
					if state == "foreign other" {
						path = other
					}
					write(t, path, string(raw), 0600)
				case "malformed owned":
					write(t, owned, "{", 0600)
				case "malformed other":
					write(t, other, "{", 0600)
				}
				var out bytes.Buffer
				healthy := diagnose(&out, defs, func(id string) bool { return id == "codex" }, filepath.Join(home, ".codex", "config.toml"), other)
				wantHealthy := state == "only owned" || state == "same binary"
				if healthy != wantHealthy {
					t.Fatalf("healthy=%v, want %v: %s", healthy, wantHealthy, &out)
				}
				wantWarnings := 0
				if state == "different binary" {
					wantWarnings = 1
					warning := "Codex hooks: another Kontext install also hooks Codex (~/.codex/hooks.json → " + otherBinary + "); run kontext setup --uninstall on an organization-managed Mac\n"
					if !strings.Contains(out.String(), warning) {
						t.Fatal(&out)
					}
					if strings.Contains(out.String(), "incomplete") || strings.Contains(out.String(), "different binary paths") {
						t.Fatal(&out)
					}
				}
				if got := strings.Count(out.String(), "another Kontext install"); got != wantWarnings {
					t.Fatalf("warnings=%d, want %d: %s", got, wantWarnings, &out)
				}
				if state != "foreign owned" && state != "malformed owned" {
					installed := "Codex hooks: installed (" + owned + "; binary " + opts.Binary + ")\n"
					if !strings.Contains(out.String(), installed) {
						t.Fatal(&out)
					}
				}
			})
		}
	}
}
