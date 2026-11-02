package codexmanaged

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// RouteMarker ends the openai_base_url line Kontext writes to send Codex's
// model traffic through its proxy, and only that line.
const RouteMarker = "# kontext-codex-proxy"

// ErrRouteNotEditable reports a config whose model traffic Kontext leaves
// alone, or one a line edit cannot change safely.
var ErrRouteNotEditable = errors.New("codex config: model route not editable")

// Route returns the URL of the openai_base_url line Kontext wrote, or "".
func Route(content string) string {
	for _, line := range strings.Split(content, "\n") {
		if url, ok := routeLine(line); ok {
			return url
		}
	}
	return ""
}

// RouteBlocker says why Kontext must leave a config's model traffic alone, or
// "" when it may route it: the person set openai_base_url, a model provider
// other than OpenAI's, or a ChatGPT backend of their own.
func RouteBlocker(content string) (string, error) {
	var config map[string]any
	if _, err := toml.Decode(content, &config); err != nil {
		return "", err
	}
	if _, set := config["openai_base_url"]; set && Route(content) == "" {
		return "openai_base_url is set", nil
	}
	if provider, set := config["model_provider"]; set && provider != "openai" {
		return fmt.Sprintf("model_provider is %v", provider), nil
	}
	if backend, set := config["chatgpt_base_url"].(string); set && strings.TrimRight(backend, "/") != "https://chatgpt.com/backend-api" {
		return "chatgpt_base_url is set", nil
	}
	return "", nil
}

// AddRoute returns content with Kontext's openai_base_url line set to url. The
// line goes first, where a top-level key always belongs.
func AddRoute(content, url string) (string, error) {
	var before, after map[string]any
	if _, err := toml.Decode(content, &before); err != nil {
		return "", err
	}
	if blocker, err := RouteBlocker(content); err != nil || blocker != "" {
		return "", fmt.Errorf("%w: %s", ErrRouteNotEditable, blocker)
	}
	if Route(content) == url {
		return content, nil
	}
	next := "openai_base_url = " + strconv.Quote(url) + " " + RouteMarker + "\n" + removeRoute(content)
	if _, err := toml.Decode(next, &after); err != nil {
		return "", fmt.Errorf("%w: %v", ErrRouteNotEditable, err)
	}
	if before == nil {
		before = map[string]any{}
	}
	before["openai_base_url"] = url
	if !reflect.DeepEqual(before, after) {
		return "", ErrRouteNotEditable
	}
	return next, nil
}

// RemoveRoute returns content without Kontext's openai_base_url line, and
// everything else as it was. A config that no longer parses, as when the
// person added an openai_base_url of their own, still loses the line: the
// rest of its bytes stay as they are.
func RemoveRoute(content string) (string, error) {
	if Route(content) == "" {
		return content, nil
	}
	var before, after map[string]any
	if _, err := toml.Decode(content, &before); err != nil {
		return removeRoute(content), nil
	}
	next := removeRoute(content)
	if _, err := toml.Decode(next, &after); err != nil {
		return "", fmt.Errorf("%w: %v", ErrRouteNotEditable, err)
	}
	delete(before, "openai_base_url")
	if after == nil {
		after = map[string]any{}
	}
	if !reflect.DeepEqual(before, after) {
		return "", ErrRouteNotEditable
	}
	return next, nil
}

func removeRoute(content string) string {
	lines := strings.SplitAfter(content, "\n")
	kept := lines[:0]
	for _, line := range lines {
		if _, ours := routeLine(line); !ours {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "")
}

// routeLine reads `openai_base_url = "<url>" # kontext-codex-proxy`.
func routeLine(line string) (string, bool) {
	line = strings.TrimSpace(line)
	body, marked := strings.CutSuffix(line, RouteMarker)
	if !marked {
		return "", false
	}
	key, value, found := strings.Cut(body, "=")
	if !found || strings.TrimSpace(key) != "openai_base_url" {
		return "", false
	}
	url, err := strconv.Unquote(strings.TrimSpace(value))
	if err != nil {
		return "", false
	}
	return url, true
}
