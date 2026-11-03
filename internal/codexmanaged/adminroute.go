package codexmanaged

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/kontext-security/kontext/internal/platform"
)

// Codex builds its configuration from layers, some of which an administrator
// manages. Codex's loader stacks them like this, highest precedence first
// (codex-rs/config/src/loader, README.md and mod.rs):
// https://github.com/openai/codex/blob/4a971492e765ef6f98012578a2de73098efdb8a2/codex-rs/config/src/loader/README.md
//
//  1. config_toml_base64, forced by an MDM profile in com.openai.codex (macOS)
//  2. /etc/codex/managed_config.toml (Unix)
//  3. session flags, then project config, then the selected profile
//  4. ~/.codex/config.toml, where Kontext writes its route
//  5. the cloud-managed config of the person's ChatGPT workspace, or of a
//     configuration server, which Codex caches in ~/.codex
//  6. /etc/codex/config.toml, the system layer
//
// Requirements outrank every layer: a model_provider or chatgpt_base_url there
// replaces what any layer says. They come from /etc/codex/requirements.toml,
// the cloud-managed requirements, and requirements_toml_base64 forced in
// com.openai.codex (macOS). Neither config nor requirements can redefine the
// built-in openai provider, only select another one.
//
// An administrator who routes Codex in layers 5 or 6 would lose to Kontext's
// line, and one who routes it anywhere else would leave the proxy nothing to
// carry. Either way Kontext leaves Codex alone: see AdminRouteBlocker.

// codexPreferenceDomain is the preference domain whose forced values Codex
// reads as administrator configuration.
const codexPreferenceDomain = "com.openai.codex"

// cloudConfigCacheVersion is the format of Codex's cloud-managed config cache
// that AdminRouteBlocker reads; Codex ignores a cache of any other version.
const cloudConfigCacheVersion = 1

// defaultChatGPTBackend is Codex's own chatgpt_base_url.
const defaultChatGPTBackend = "https://chatgpt.com/backend-api"

// codexSystemDir and managedPreferences are seams for tests.
var (
	codexSystemDir     = platform.CodexSystemDir
	managedPreferences = readManagedPreferences
)

// AdminRouteBlocker says which layer of Codex's configuration that an
// administrator manages routes Codex's model traffic, or "" when none does:
// one that sets openai_base_url, a model_provider other than OpenAI's, or a
// chatgpt_base_url of its own. codexHome is where Codex caches its
// cloud-managed config. A layer that cannot be read or parsed is an error,
// since it might route Codex.
func AdminRouteBlocker(codexHome string) (string, error) {
	dir, err := codexSystemDir()
	if err != nil {
		return "", err
	}
	for _, file := range []struct {
		name         string
		requirements bool
	}{{"managed_config.toml", false}, {"requirements.toml", true}, {"config.toml", false}} {
		path := filepath.Join(dir, file.name)
		data, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		setting, err := routeSetting(string(data), file.requirements)
		if err != nil {
			return "", fmt.Errorf("%s: %w", path, err)
		}
		if setting != "" {
			return path + " sets " + setting, nil
		}
	}

	preferences, err := managedPreferences()
	if err != nil {
		return "", err
	}
	for _, values := range preferences {
		for _, key := range []struct {
			name         string
			requirements bool
		}{{"config_toml_base64", false}, {"requirements_toml_base64", true}} {
			encoded, set := values[key.name]
			if !set {
				continue
			}
			content, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
			setting := ""
			if err == nil {
				setting, err = routeSetting(string(content), key.requirements)
			}
			if err != nil {
				return "", fmt.Errorf("managed preference %s %s: %w", codexPreferenceDomain, key.name, err)
			}
			if setting != "" {
				return fmt.Sprintf("the managed preference %s %s sets %s", codexPreferenceDomain, key.name, setting), nil
			}
		}
	}

	caches, err := filepath.Glob(filepath.Join(codexHome, "managed-config-*.json"))
	if err != nil {
		return "", err
	}
	for _, path := range append([]string{filepath.Join(codexHome, "cloud-config-bundle-cache.json")}, caches...) {
		setting, err := cloudRouteSetting(path)
		if err != nil {
			return "", fmt.Errorf("%s: %w", path, err)
		}
		if setting != "" {
			return "the cloud-managed " + setting, nil
		}
	}
	return "", nil
}

// cloudRouteSetting reads a cloud-managed config cache Codex wrote, and names
// the fragment that routes Codex's model traffic, if one does.
func cloudRouteSetting(path string) (string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	type fragment struct {
		Name     string `json:"name"`
		Contents string `json:"contents"`
	}
	var cache struct {
		SignedPayload struct {
			Version int `json:"version"`
			Bundle  struct {
				Config struct {
					EnterpriseManaged []fragment `json:"enterprise_managed"`
				} `json:"config_toml"`
				Requirements struct {
					EnterpriseManaged []fragment `json:"enterprise_managed"`
				} `json:"requirements_toml"`
			} `json:"bundle"`
		} `json:"signed_payload"`
	}
	if err := json.Unmarshal(data, &cache); err != nil {
		return "", err
	}
	if version := cache.SignedPayload.Version; version != cloudConfigCacheVersion {
		return "", fmt.Errorf("cache version %d, not %d", version, cloudConfigCacheVersion)
	}
	bundle := cache.SignedPayload.Bundle
	for _, layer := range []struct {
		kind         string
		fragments    []fragment
		requirements bool
	}{{"requirements", bundle.Requirements.EnterpriseManaged, true}, {"config", bundle.Config.EnterpriseManaged, false}} {
		for _, fragment := range layer.fragments {
			setting, err := routeSetting(fragment.Contents, layer.requirements)
			if err != nil {
				return "", fmt.Errorf("%s %q: %w", layer.kind, fragment.Name, err)
			}
			if setting != "" {
				return fmt.Sprintf("%s %q sets %s", layer.kind, fragment.Name, setting), nil
			}
		}
	}
	return "", nil
}

// routeSetting names the setting in a layer's TOML that routes Codex's model
// traffic, or "". Requirements have no openai_base_url.
func routeSetting(content string, requirements bool) (string, error) {
	var layer map[string]any
	if _, err := toml.Decode(content, &layer); err != nil {
		return "", err
	}
	if _, set := layer["openai_base_url"]; set && !requirements {
		return "openai_base_url", nil
	}
	if provider, set := layer["model_provider"]; set && provider != "openai" {
		return "model_provider", nil
	}
	if backend, set := layer["chatgpt_base_url"].(string); set && strings.TrimRight(backend, "/") != defaultChatGPTBackend {
		return "chatgpt_base_url", nil
	}
	return "", nil
}

// plistStrings reads the strings at the top of an XML property list's root
// dictionary, by key.
func plistStrings(data []byte) (map[string]string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	values := map[string]string{}
	depth, key := 0, ""
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return values, nil
		}
		if err != nil {
			return nil, err
		}
		switch element := token.(type) {
		case xml.StartElement:
			// The root dictionary's entries open inside <plist><dict>, at depth 2;
			// any other value there leaves the key before it without a string.
			if depth != 2 || (element.Name.Local != "key" && element.Name.Local != "string") {
				depth++
				key = ""
				continue
			}
			var text string
			if err := decoder.DecodeElement(&text, &element); err != nil {
				return nil, err
			}
			if element.Name.Local == "key" {
				key = text
			} else if key != "" {
				values[key], key = text, ""
			}
		case xml.EndElement:
			depth--
		}
	}
}
