package hookinstall

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/agenthooks"
	"github.com/kontext-security/kontext/internal/claudemanaged"
	"github.com/kontext-security/kontext/internal/codexmanaged"
	"github.com/kontext-security/kontext/internal/cursormanaged"
	"github.com/kontext-security/kontext/internal/hermetic"
)

func fixture(t *testing.T, scope Scope) (Options, []Definition) {
	t.Helper()
	t.Setenv("CODEX_HOME", "")
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	root := t.TempDir()
	claudeDropIn, cursorHooks := machineClaudeDropIn, machineCursorHooks
	machineClaudeDropIn = filepath.Join(root, claudemanaged.ManagedSettingsDropInPath)
	machineCursorHooks = filepath.Join(root, cursormanaged.SystemHooksPath)
	t.Cleanup(func() { machineClaudeDropIn, machineCursorHooks = claudeDropIn, cursorHooks })
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
			wantFiles := 0
			for _, d := range defs {
				wantFiles += len(d.Files)
			}
			if strings.Count(out.String(), "skip\t") != wantFiles {
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
					if f.Kind == "claude-user" {
						if strings.TrimSpace(read(t, f.Path)) != "{}" {
							t.Fatalf("user hooks remain: %s", read(t, f.Path))
						}
						continue
					}
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
			if scope == User {
				return
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
					healthy := diagnose(&out, opts.Scope, defs, func(id string) bool { return id == agent && state != "absent" }, filepath.Join(t.TempDir(), "config.toml"), "")
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
	if diagnose(&out, opts.Scope, defs, func(string) bool { return true }, user, "") {
		t.Fatal("ignored user override")
	}
	if !strings.Contains(out.String(), "disabled by user override") {
		t.Fatal(&out)
	}
}

func TestDoctorNamesStaleClaudeEventsAndScopeRepair(t *testing.T) {
	for _, scope := range []Scope{User, System} {
		t.Run(string(scope), func(t *testing.T) {
			opts, defs := fixture(t, scope)
			path := defs[0].Files[0].Path
			old := strings.ReplaceAll(read(t, "testdata/claude-1.7.0.json"), "/usr/local/bin/kontext", opts.Binary)
			write(t, path, old, 0644)
			var out bytes.Buffer
			if diagnose(&out, scope, defs[:1], func(string) bool { return true }, "", "") {
				t.Fatal("stale hooks reported healthy")
			}
			prefix := ""
			if scope == System {
				prefix = "sudo "
			}
			want := "Claude Code hooks: out of date (missing UserPromptSubmit, Stop, SubagentStop). Run `" + prefix + agenthooks.ShellQuote(opts.Binary) + " hooks install --scope " + string(scope) + " --binary " + agenthooks.ShellQuote(opts.Binary) + "`.\n" +
				"Claude Code hooks: prompt hook missing: turns and type of work unavailable\n"
			if out.String() != want {
				t.Fatalf("doctor = %q, want %q", out.String(), want)
			}
			if read(t, path) != old {
				t.Fatal("doctor modified the hooks")
			}
			// Exercise the actual install path used by the recommended command.
			if err := runDefinitions(opts, defs, false); err != nil {
				t.Fatal(err)
			}
			out.Reset()
			if !diagnose(&out, scope, defs[:1], func(string) bool { return true }, "", "") {
				t.Fatalf("installed hooks remain unhealthy: %s", &out)
			}
		})
	}
}

func TestDoctorKeepsOtherClaudeValidationErrorsRaw(t *testing.T) {
	for _, problem := range []string{"malformed", "disabled", "foreign policy", "invalid async", "invalid timeout", "different binaries", "missing binary", "symlink"} {
		t.Run(problem, func(t *testing.T) {
			opts, defs := fixture(t, User)
			path := defs[0].Files[0].Path
			old := strings.ReplaceAll(read(t, "testdata/claude-1.7.0.json"), "/usr/local/bin/kontext", opts.Binary)
			var settings map[string]any
			if err := json.Unmarshal([]byte(old), &settings); err != nil {
				t.Fatal(err)
			}
			switch problem {
			case "disabled":
				settings["disableAllHooks"] = true
			case "foreign policy":
				settings["allowManagedHooksOnly"] = true
			case "invalid async":
				old = strings.Replace(old, `"async": true`, `"async": false`, 1)
			case "invalid timeout":
				old = strings.Replace(old, `"timeout": 20`, `"timeout": 5`, 1)
			case "different binaries":
				old = strings.Replace(old, opts.Binary, "/other/kontext", 1)
			case "malformed":
				old = "{"
			case "missing binary":
				if err := os.Remove(opts.Binary); err != nil {
					t.Fatal(err)
				}
			}
			if problem == "disabled" || problem == "foreign policy" {
				raw, err := json.Marshal(settings)
				if err != nil {
					t.Fatal(err)
				}
				old = string(raw)
			}
			write(t, path, old, 0644)
			if problem == "symlink" {
				if err := os.Rename(path, path+".target"); err != nil {
					t.Fatal(err)
				}
				hermetic.Symlinks(t)
				if err := os.Symlink(path+".target", path); err != nil {
					t.Fatal(err)
				}
			}
			var out bytes.Buffer
			if diagnose(&out, User, defs[:1], func(string) bool { return true }, "", "") {
				t.Fatal("invalid hooks reported healthy")
			}
			want := "Claude Code hooks: incomplete or disabled (" + path + ")\n"
			if out.String() != want {
				t.Fatalf("doctor = %q, want raw error %q", out.String(), want)
			}
		})
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
			// The user's Claude settings file stays; only its hooks go.
			if want := map[Scope]int{User: 3, System: 4}[scope]; strings.Count(out.String(), "would-remove\t") != want {
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
	data := []string{`{"permissions":{}}`, `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo foreign"}]}]}}`, "[features]\nhooks = true\n", `{"version":1,"hooks":{"stop":[{"command":"echo foreign"}]}}`}
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
	hermetic.Symlinks(t)
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
	if diagnose(&out, opts.Scope, defs, func(string) bool { return true }, "", other) {
		t.Fatal("ignored malformed user hooks")
	}
}

func TestUserCommandsHonorCodexHome(t *testing.T) {
	opts, _ := fixture(t, User)
	custom := filepath.Join(t.TempDir(), "custom-codex")
	t.Setenv("CODEX_HOME", custom)
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(t.TempDir(), "custom-claude"))
	opts.Home = t.TempDir()
	if err := Install(opts); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("CLAUDE_CONFIG_DIR"), "settings.json")); err != nil {
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
		for _, state := range []string{"only owned", "only other", "empty owned", "both empty", "incomplete owned", "same binary", "different binary", "foreign owned", "foreign other", "malformed owned", "malformed other", "missing other binary"} {
			t.Run(string(scope)+"/"+state, func(t *testing.T) {
				opts, defs := fixture(t, scope)
				if err := runDefinitions(opts, defs, false); err != nil {
					t.Fatal(err)
				}
				home := t.TempDir()
				hermetic.SetHome(t, home)
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
				case "only other":
					if err := os.Remove(owned); err != nil {
						t.Fatal(err)
					}
				case "empty owned":
					write(t, owned, `{"hooks":{}}`, 0600)
				case "both empty":
					write(t, owned, `{"hooks":{}}`, 0600)
					write(t, other, `{"hooks":{}}`, 0600)
				case "incomplete owned":
					write(t, owned, `{"hooks":{"Stop":[]}}`, 0600)
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
				healthy := diagnose(&out, opts.Scope, defs, func(id string) bool { return id == "codex" }, filepath.Join(home, ".codex", "config.toml"), other)
				wantHealthy := state == "only owned" || state == "same binary" || state == "only other" || state == "empty owned"
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
				if state == "only other" || state == "empty owned" {
					installed := "Codex hooks: installed (" + other + "; binary " + opts.Binary + ")\n"
					if !strings.Contains(out.String(), installed) {
						t.Fatal(&out)
					}
				} else if state != "foreign owned" && state != "malformed owned" && state != "both empty" && state != "incomplete owned" {
					installed := "Codex hooks: installed (" + owned + "; binary " + opts.Binary + ")\n"
					if !strings.Contains(out.String(), installed) {
						t.Fatal(&out)
					}
				}
			})
		}
	}
}

// An installed Codex set without UserPromptSubmit mints no turns; doctor says
// what that costs next to the hook-health line.
func TestDoctorNamesMissingCodexPromptHook(t *testing.T) {
	opts, defs := fixture(t, User)
	if err := runDefinitions(opts, defs, false); err != nil {
		t.Fatal(err)
	}
	owned := defs[1].Files[0].Path
	var settings map[string]any
	if err := json.Unmarshal([]byte(read(t, owned)), &settings); err != nil {
		t.Fatal(err)
	}
	delete(settings["hooks"].(map[string]any), "UserPromptSubmit")
	raw, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	write(t, owned, string(raw), 0600)
	var out bytes.Buffer
	if diagnose(&out, opts.Scope, defs[1:], func(id string) bool { return id == "codex" }, defs[1].Files[1].Path, "") {
		t.Fatalf("a set without the prompt hook reported healthy: %s", &out)
	}
	want := "Codex hooks: prompt hook missing: turns and type of work unavailable (" + owned + ")\n"
	if !strings.Contains(out.String(), want) {
		t.Fatalf("doctor = %q, want line %q", out.String(), want)
	}
	if err := runDefinitions(opts, defs, false); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	diagnose(&out, opts.Scope, defs[1:], func(id string) bool { return id == "codex" }, defs[1].Files[1].Path, "")
	if strings.Contains(out.String(), "prompt hook missing") {
		t.Fatalf("complete set still reported the prompt hook missing: %s", &out)
	}
}

// A machine-wide file an administrator changes while sudo waits for a password
// must not be overwritten with the plan made before the change.
func TestSystemWriterRechecksAfterAuthorization(t *testing.T) {
	opts, defs := fixture(t, System)
	cursor := defs[2].Files[0].Path
	write(t, cursor, `{"version":1,"hooks":{}}`, 0644)
	const admin = `{"version":1,"hooks":{"stop":[{"command":"/opt/audit/hook"}]}}`
	opts.WriteSystem = func(path string, data []byte, unchanged func() error) error {
		if path == cursor {
			write(t, cursor, admin, 0644) // the administrator's edit lands during the prompt
		}
		if err := unchanged(); err != nil {
			return err
		}
		return os.WriteFile(path, data, 0644)
	}
	if err := runDefinitions(opts, defs[2:], false); err == nil || !strings.Contains(err.Error(), "changed during hook installation") {
		t.Fatalf("runDefinitions() = %v, want a changed-file error", err)
	}
	if got := read(t, cursor); got != admin {
		t.Fatalf("Cursor hooks = %s, want the administrator's edit kept", got)
	}
}

// Cursor runs every hooks file without deduplicating, so each event must carry
// exactly one runnable Kontext hook across the machine-wide and user files.
func TestUserCursorCoversWhatTheMachineFileDoesNot(t *testing.T) {
	for _, tc := range []struct {
		name          string
		drop          string // event removed from the earlier machine-wide set
		deadBinary    bool
		wantUserHooks int
	}{
		{name: "complete machine-wide set", wantUserHooks: 0},
		{name: "machine-wide set without stop", drop: "stop", wantUserHooks: 1},
		{name: "machine-wide binary deleted", deadBinary: true, wantUserHooks: len(cursormanaged.Events)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, defs := fixture(t, User)
			legacy := filepath.Join(t.TempDir(), "old", "kontext")
			write(t, legacy, "#!/bin/sh\n", 0755)
			machine := map[string]any{}
			if err := cursormanaged.MergeManagedHooks(machine, legacy); err != nil {
				t.Fatal(err)
			}
			delete(machine["hooks"].(map[string]any), tc.drop)
			raw, _ := json.Marshal(machine)
			write(t, machineCursorHooks, string(raw), 0644)
			if tc.deadBinary {
				if err := os.Remove(legacy); err != nil {
					t.Fatal(err)
				}
			}
			if err := runDefinitions(opts, defs, false); err != nil {
				t.Fatal(err)
			}
			user := defs[2].Files[0].Path
			data, _ := os.ReadFile(user)
			if got := len(cursormanaged.Coverage(data)); got != tc.wantUserHooks {
				t.Fatalf("user file covers %d events, want %d: %s", got, tc.wantUserHooks, data)
			}
			var out bytes.Buffer
			if !diagnoseCursorLayers(&out, user, machineCursorHooks) {
				t.Fatalf("doctor: %s", &out)
			}
			if err := runDefinitions(opts, defs, false); err != nil {
				t.Fatal(err)
			}
			if again, _ := os.ReadFile(user); !bytes.Equal(again, data) {
				t.Fatal("a second run rewrote the user file")
			}
		})
	}
}

// writeMixedMachineSources leaves Stop and SubagentStop out of the drop-in and
// puts them in managed-settings.json with another binary, as an organization's
// settings next to an earlier self-serve drop-in would.
func writeMixedMachineSources(t *testing.T, dropin, dropinBinary, otherBinary string) {
	t.Helper()
	full := claudemanaged.Template(dropinBinary)
	other := claudemanaged.Template(otherBinary)
	moved := claudemanaged.Settings{Hooks: map[string][]claudemanaged.MatcherGroup{}}
	for _, event := range []string{"Stop", "SubagentStop"} {
		delete(full.Hooks, event)
		moved.Hooks[event] = other.Hooks[event]
	}
	for path, settings := range map[string]claudemanaged.Settings{dropin: full, filepath.Join(filepath.Dir(filepath.Dir(dropin)), "managed-settings.json"): moved} {
		data, err := json.Marshal(settings)
		if err != nil {
			t.Fatal(err)
		}
		write(t, path, string(data), 0644)
	}
}

func TestUserClaudeCopyMirrorsMixedMachineSources(t *testing.T) {
	opts, defs := fixture(t, User)
	alias := filepath.Join(t.TempDir(), "other", "kontext")
	write(t, alias, "#!/bin/sh\n", 0755)
	writeMixedMachineSources(t, machineClaudeDropIn, opts.Binary, alias)
	if err := runDefinitions(opts, defs[:1], false); err != nil {
		t.Fatal(err)
	}
	user := read(t, defs[0].Files[0].Path)
	if !strings.Contains(user, "'"+alias+"' hook 'stop'") || !strings.Contains(user, "'"+opts.Binary+"' hook 'pre-tool-use'") {
		t.Fatalf("user copy does not repeat each machine-wide handler:\n%s", user)
	}
	var out bytes.Buffer
	if !diagnose(&out, User, defs[:1], func(string) bool { return true }, "", "") {
		t.Fatalf("doctor rejected the mirrored copy: %s", &out)
	}
	if err := runDefinitions(opts, defs[:1], false); err != nil {
		t.Fatal(err)
	}
	if read(t, defs[0].Files[0].Path) != user {
		t.Fatal("a second install rewrote the mirrored copy")
	}
}

// Claude merges every drop-in in managed-settings.d, and a handler written as a
// command with args runs like the one-string form, so the user copy repeats it.
// The exec-form path holds a space, and one handler carries an `if` condition
// Kontext never writes itself; the copy keeps both.
func TestUserClaudeCopyMirrorsEveryMachineDropIn(t *testing.T) {
	opts, defs := fixture(t, User)
	binary := filepath.Join(t.TempDir(), "Kontext CLI", "kontext")
	write(t, binary, "#!/bin/sh\n", 0755)
	org := claudemanaged.Template(binary)
	for name, groups := range org.Hooks {
		for i := range groups {
			for j := range groups[i].Hooks {
				h := &groups[i].Hooks[j]
				fields, _ := agenthooks.SplitCommand(h.Command)
				h.Command, h.Args, h.Timeout = fields[0], fields[1:], 30
				if name == "PreToolUse" {
					h.Extra = map[string]any{"if": "Bash(*)"}
				}
			}
		}
		org.Hooks[name] = groups
	}
	data, _ := json.Marshal(org)
	write(t, filepath.Join(filepath.Dir(machineClaudeDropIn), "10-org.json"), string(data), 0644)
	if err := runDefinitions(opts, defs[:1], false); err != nil {
		t.Fatal(err)
	}
	user := read(t, defs[0].Files[0].Path)
	var got claudemanaged.Settings
	if err := json.Unmarshal([]byte(user), &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Hooks, org.Hooks) {
		t.Fatalf("user copy does not repeat the other drop-in's handlers:\n%s", user)
	}
	var out bytes.Buffer
	if !diagnose(&out, User, defs[:1], func(string) bool { return true }, "", "") {
		t.Fatalf("doctor rejected the mirrored copy: %s", &out)
	}
	if err := runDefinitions(opts, defs[:1], false); err != nil {
		t.Fatal(err)
	}
	if read(t, defs[0].Files[0].Path) != user {
		t.Fatal("a second install rewrote the mirrored copy")
	}
}

// A dotfiles link whose file held only Kontext's Cursor hooks stays a link
// when a complete machine-wide set makes the user copy redundant.
func TestUserCursorLinkSurvivesWhenTheMachineFileCoversEverything(t *testing.T) {
	opts, defs := fixture(t, User)
	machine := map[string]any{}
	if err := cursormanaged.MergeManagedHooks(machine, opts.Binary); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(machine)
	write(t, machineCursorHooks, string(raw), 0644)
	target := filepath.Join(t.TempDir(), "dotfiles", "hooks.json")
	write(t, target, string(raw), 0644)
	user := defs[2].Files[0].Path
	if err := os.MkdirAll(filepath.Dir(user), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, user); err != nil {
		t.Fatal(err)
	}
	if err := runDefinitions(opts, defs, false); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(user); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("user hooks link replaced or removed: %v", err)
	}
	if got := cursormanaged.Coverage([]byte(read(t, target))); len(got) != 0 {
		t.Fatalf("link target still runs %d Kontext hooks next to the machine-wide set", len(got))
	}
}
