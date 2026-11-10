package codexmanaged

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/hermetic"
)

// adminLayers points AdminRouteBlocker at an empty system folder and no
// managed preferences, and returns the system folder, the Codex home and a
// setter for the managed preferences, this user's first.
func adminLayers(t *testing.T) (string, string, func(...map[string]string)) {
	t.Helper()
	root := t.TempDir()
	system, codexHome := filepath.Join(root, "etc", "codex"), filepath.Join(root, "home", ".codex")
	for _, dir := range []string{system, codexHome} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	previousDir, previousPreferences := codexSystemDir, managedPreferences
	t.Cleanup(func() { codexSystemDir, managedPreferences = previousDir, previousPreferences })
	codexSystemDir = func() (string, error) { return system, nil }
	var preferences []map[string]string
	managedPreferences = func() ([]map[string]string, error) { return preferences, nil }
	return system, codexHome, func(values ...map[string]string) { preferences = values }
}

func writeLayer(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// cloudCache is a cloud-managed config cache as Codex writes it.
func cloudCache(t *testing.T, version int, config, requirements map[string]string) string {
	t.Helper()
	fragments := func(contents map[string]string) []map[string]string {
		var out []map[string]string
		for name, content := range contents {
			out = append(out, map[string]string{"id": "fragment-" + name, "name": name, "contents": content})
		}
		return out
	}
	data, err := json.Marshal(map[string]any{
		"signed_payload": map[string]any{
			"version": version, "cached_at": "2026-11-03T12:00:00Z", "expires_at": "2026-11-03T13:00:00Z",
			"chatgpt_user_id": "user-1", "account_id": "acct-1",
			"bundle": map[string]any{
				"config_toml":       map[string]any{"enterprise_managed": fragments(config)},
				"requirements_toml": map[string]any{"enterprise_managed": fragments(requirements)},
			},
		},
		"signature": "c2lnbmVk",
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// Nothing routes Codex without a layer an administrator manages, or with
// layers that leave Codex's model traffic as OpenAI sends it.
func TestNoAdministratorLayerRoutesCodex(t *testing.T) {
	system, codexHome, preferences := adminLayers(t)
	if blocker, err := AdminRouteBlocker(codexHome); err != nil || blocker != (Blocker{}) {
		t.Fatalf("AdminRouteBlocker without layers = %+v, %v", blocker, err)
	}
	writeLayer(t, filepath.Join(system, "config.toml"), "model_provider = \"openai\"\nchatgpt_base_url = \"https://chatgpt.com/backend-api/\"\n")
	writeLayer(t, filepath.Join(system, "requirements.toml"), "allowed_approval_policies = [\"on-request\"]\n# Requirements have no openai_base_url.\nopenai_base_url = \"https://gateway.example/v1\"\n")
	writeLayer(t, filepath.Join(system, "managed_config.toml"), "approval_policy = \"on-request\"\n")
	writeLayer(t, filepath.Join(codexHome, "cloud-config-bundle-cache.json"), cloudCache(t, 1,
		map[string]string{"Defaults": "model = \"gpt-6.1-sol\"\n"}, map[string]string{"Policy": "allowed_sandbox_modes = [\"read-only\"]\n"}))
	preferences(map[string]string{"config_toml_base64": base64.StdEncoding.EncodeToString([]byte("model = \"gpt-6.1-sol\"\n")),
		"unrelated": "value"})
	if blocker, err := AdminRouteBlocker(codexHome); err != nil || blocker != (Blocker{}) {
		t.Fatalf("AdminRouteBlocker = %+v, %v", blocker, err)
	}
}

// Each layer an administrator manages keeps Kontext from routing Codex when it
// routes Codex itself, the ones Kontext's line would override and the ones
// that would override it alike.
func TestEachAdministratorLayerThatRoutesCodexBlocks(t *testing.T) {
	hermetic.NotOnWindows(t, "ENG-1001", "Codex's administrator layers are read for its route, which runs on macOS only")
	encode := func(content string) string { return base64.StdEncoding.EncodeToString([]byte(content)) }
	for _, layer := range []struct {
		name  string
		write func(t *testing.T, system, codexHome string, preferences func(...map[string]string))
		want  string
	}{
		{"system config, openai_base_url", func(t *testing.T, system, _ string, _ func(...map[string]string)) {
			writeLayer(t, filepath.Join(system, "config.toml"), "openai_base_url = \"https://gateway.example/v1\"\n")
		}, "{system}/config.toml sets openai_base_url"},
		{"system config, model_provider", func(t *testing.T, system, _ string, _ func(...map[string]string)) {
			writeLayer(t, filepath.Join(system, "config.toml"), "model_provider = \"corp\"\n\n[model_providers.corp]\nname = \"Corp\"\nbase_url = \"https://gateway.example/v1\"\n")
		}, "{system}/config.toml sets model_provider"},
		{"system config, chatgpt_base_url", func(t *testing.T, system, _ string, _ func(...map[string]string)) {
			writeLayer(t, filepath.Join(system, "config.toml"), "chatgpt_base_url = \"https://gateway.example/backend-api\"\n")
		}, "{system}/config.toml sets chatgpt_base_url"},
		{"system requirements, model_provider", func(t *testing.T, system, _ string, _ func(...map[string]string)) {
			writeLayer(t, filepath.Join(system, "requirements.toml"), "model_provider = \"corp\"\n")
		}, "{system}/requirements.toml sets model_provider"},
		{"system requirements, chatgpt_base_url", func(t *testing.T, system, _ string, _ func(...map[string]string)) {
			writeLayer(t, filepath.Join(system, "requirements.toml"), "chatgpt_base_url = \"https://gateway.example/backend-api\"\n")
		}, "{system}/requirements.toml sets chatgpt_base_url"},
		{"legacy managed config", func(t *testing.T, system, _ string, _ func(...map[string]string)) {
			writeLayer(t, filepath.Join(system, "managed_config.toml"), "openai_base_url = \"https://gateway.example/v1\"\n")
		}, "{system}/managed_config.toml sets openai_base_url"},
		{"managed preference config", func(t *testing.T, _, _ string, preferences func(...map[string]string)) {
			preferences(map[string]string{"config_toml_base64": encode("model_provider = \"corp\"\n")})
		}, "the managed preference com.openai.codex config_toml_base64 sets model_provider"},
		{"managed preference requirements, the Mac's", func(t *testing.T, _, _ string, preferences func(...map[string]string)) {
			preferences(map[string]string{}, map[string]string{"requirements_toml_base64": encode("chatgpt_base_url = \"https://gateway.example/backend-api\"\n")})
		}, "the managed preference com.openai.codex requirements_toml_base64 sets chatgpt_base_url"},
		{"cloud-managed requirements", func(t *testing.T, _, codexHome string, _ func(...map[string]string)) {
			writeLayer(t, filepath.Join(codexHome, "cloud-config-bundle-cache.json"),
				cloudCache(t, 1, nil, map[string]string{"Gateway": "model_provider = \"corp\"\n"}))
		}, `the cloud-managed requirements "Gateway" sets model_provider`},
		{"cloud-managed config", func(t *testing.T, _, codexHome string, _ func(...map[string]string)) {
			writeLayer(t, filepath.Join(codexHome, "cloud-config-bundle-cache.json"),
				cloudCache(t, 1, map[string]string{"Gateway": "openai_base_url = \"https://gateway.example/v1\"\n"}, nil))
		}, `the cloud-managed config "Gateway" sets openai_base_url`},
		{"configuration server", func(t *testing.T, _, codexHome string, _ func(...map[string]string)) {
			writeLayer(t, filepath.Join(codexHome, "managed-config-corp.json"),
				cloudCache(t, 1, nil, map[string]string{"Gateway": "chatgpt_base_url = \"https://gateway.example/backend-api\"\n"}))
		}, `the cloud-managed requirements "Gateway" sets chatgpt_base_url`},
	} {
		t.Run(layer.name, func(t *testing.T) {
			system, codexHome, preferences := adminLayers(t)
			layer.write(t, system, codexHome, preferences)
			want := strings.ReplaceAll(layer.want, "{system}", system)
			// The setting is what the text ends with.
			if blocker, err := AdminRouteBlocker(codexHome); err != nil || blocker.Text != want || !strings.HasSuffix(want, " sets "+blocker.Setting) {
				t.Fatalf("AdminRouteBlocker = %+v, %v; want %q", blocker, err, want)
			}
		})
	}
}

// A layer Kontext cannot read or understand might route Codex: Kontext then
// routes nothing.
func TestAnAdministratorLayerKontextCannotReadBlocks(t *testing.T) {
	for _, layer := range []struct {
		name  string
		write func(t *testing.T, system, codexHome string, preferences func(...map[string]string))
		want  string
	}{
		{"system config that does not parse", func(t *testing.T, system, _ string, _ func(...map[string]string)) {
			writeLayer(t, filepath.Join(system, "config.toml"), "model_provider = \n")
		}, "config.toml"},
		{"system requirements that cannot be read", func(t *testing.T, system, _ string, _ func(...map[string]string)) {
			if err := os.Mkdir(filepath.Join(system, "requirements.toml"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, "requirements.toml"},
		{"managed preference that is not base64", func(t *testing.T, _, _ string, preferences func(...map[string]string)) {
			preferences(map[string]string{"requirements_toml_base64": "model_provider = \"corp\""})
		}, "requirements_toml_base64"},
		{"cloud cache of another version", func(t *testing.T, _, codexHome string, _ func(...map[string]string)) {
			writeLayer(t, filepath.Join(codexHome, "cloud-config-bundle-cache.json"), cloudCache(t, 2, nil, nil))
		}, "cache version 2"},
		{"cloud cache that is not JSON", func(t *testing.T, _, codexHome string, _ func(...map[string]string)) {
			writeLayer(t, filepath.Join(codexHome, "managed-config-corp.json"), "{")
		}, "managed-config-corp.json"},
		{"cloud fragment that does not parse", func(t *testing.T, _, codexHome string, _ func(...map[string]string)) {
			writeLayer(t, filepath.Join(codexHome, "cloud-config-bundle-cache.json"),
				cloudCache(t, 1, map[string]string{"Broken": "model_provider = \n"}, nil))
		}, `config "Broken"`},
	} {
		t.Run(layer.name, func(t *testing.T) {
			system, codexHome, preferences := adminLayers(t)
			layer.write(t, system, codexHome, preferences)
			if blocker, err := AdminRouteBlocker(codexHome); err == nil || blocker != (Blocker{}) || !strings.Contains(err.Error(), layer.want) {
				t.Fatalf("AdminRouteBlocker = %+v, %v; want an error naming %q", blocker, err, layer.want)
			}
		})
	}
}

// The strings at the top of a property list's root dictionary come out by
// key, whatever else the list holds.
func TestPlistStringsReadsTheRootDictionary(t *testing.T) {
	values, err := plistStrings([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>count</key>
	<integer>3</integer>
	<key>config_toml_base64</key>
	<string>bW9kZWxfcHJvdmlkZXIgPSAiY29ycCIK</string>
	<key>nested</key>
	<dict>
		<key>requirements_toml_base64</key>
		<string>not at the top</string>
	</dict>
	<key>forced</key>
	<true/>
	<key>escaped</key>
	<string>a &amp; b</string>
	<key>when</key>
	<date>2026-01-01T00:00:00Z</date>
</dict>
</plist>
`))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"config_toml_base64": "bW9kZWxfcHJvdmlkZXIgPSAiY29ycCIK", "escaped": "a & b"}
	if len(values) != len(want) || values["config_toml_base64"] != want["config_toml_base64"] || values["escaped"] != want["escaped"] {
		t.Fatalf("plistStrings = %v", values)
	}
	if _, err := plistStrings([]byte("<plist><dict><key>a</key>")); err == nil {
		t.Fatal("plistStrings read a cut-off list")
	}
}
