package codexmanaged

import (
	"errors"
	"testing"
)

const proxyURL = "http://127.0.0.1:49321/kx0123456789abcdef0123456789abcdef/backend-api/codex"

func TestAddAndRemoveRouteKeepEverythingElse(t *testing.T) {
	original := "# my settings\nmodel = \"gpt-6.1-sol\"\n\n[features]\nhooks = true # kontext-hooks\n\n[profiles.fast]\nmodel = \"gpt-5.4\"\n"
	routed, err := AddRoute(original, proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	if want := "openai_base_url = \"" + proxyURL + "\" " + RouteMarker + "\n" + original; routed != want {
		t.Fatalf("routed config:\n%s", routed)
	}
	if Route(routed) != proxyURL {
		t.Fatalf("Route = %q", Route(routed))
	}
	again, err := AddRoute(routed, proxyURL)
	if err != nil || again != routed {
		t.Fatalf("adding the same route again changed the config: %v\n%s", err, again)
	}
	moved, err := AddRoute(routed, "http://127.0.0.1:50000/kxother/backend-api/codex")
	if err != nil || Route(moved) != "http://127.0.0.1:50000/kxother/backend-api/codex" {
		t.Fatalf("new port: %v\n%s", err, moved)
	}
	removed, err := RemoveRoute(moved)
	if err != nil || removed != original {
		t.Fatalf("removing the route: %v\n%s", err, removed)
	}
	if unchanged, err := RemoveRoute(original); err != nil || unchanged != original {
		t.Fatalf("removing from a config without the route: %v", err)
	}
}

func TestAddRouteToAnEmptyConfig(t *testing.T) {
	routed, err := AddRoute("", proxyURL)
	if err != nil || Route(routed) != proxyURL {
		t.Fatalf("AddRoute = %q, %v", routed, err)
	}
	if removed, err := RemoveRoute(routed); err != nil || removed != "" {
		t.Fatalf("RemoveRoute = %q, %v", removed, err)
	}
}

func TestRouteLeavesTheirOwnTrafficAlone(t *testing.T) {
	cases := map[string]struct{ content, setting string }{
		"their base URL":        {"openai_base_url = \"https://llm-gateway.example/v1\"\n", SettingOpenAIBaseURL},
		"another provider":      {"model_provider = \"ollama\"\n", SettingModelProvider},
		"their ChatGPT backend": {"chatgpt_base_url = \"https://chatgpt.internal.example/backend-api/\"\n", SettingChatGPTBaseURL},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			content := c.content
			blocker, err := RouteBlocker(content)
			if err != nil || blocker.Setting != c.setting || blocker.Text == "" {
				t.Fatalf("RouteBlocker = %+v, %v", blocker, err)
			}
			if _, err := AddRoute(content, proxyURL); !errors.Is(err, ErrRouteNotEditable) {
				t.Fatalf("AddRoute error = %v", err)
			}
		})
	}
	for _, content := range []string{"model_provider = \"openai\"\n", "chatgpt_base_url = \"https://chatgpt.com/backend-api/\"\n"} {
		if blocker, err := RouteBlocker(content); err != nil || blocker != (Blocker{}) {
			t.Fatalf("RouteBlocker(%q) = %+v, %v", content, blocker, err)
		}
	}
}

func TestRouteNeedsOurMarker(t *testing.T) {
	// A line that only looks like ours is the person's.
	content := "openai_base_url = \"" + proxyURL + "\" # my proxy\n"
	if Route(content) != "" {
		t.Fatal("an unmarked line was read as Kontext's")
	}
	if removed, err := RemoveRoute(content); err != nil || removed != content {
		t.Fatalf("RemoveRoute changed a line Kontext did not write: %v", err)
	}
}

func TestAddRouteRefusesBrokenConfig(t *testing.T) {
	if _, err := AddRoute("model = \n", proxyURL); err == nil {
		t.Fatal("AddRoute accepted a config that does not parse")
	}
}

func TestRemoveRouteFromAConfigThatNoLongerParses(t *testing.T) {
	theirs := "model = \"gpt-6.1-sol\"\nopenai_base_url = \"https://gateway.example/v1\"\n"
	broken := "openai_base_url = \"" + proxyURL + "\" " + RouteMarker + "\n" + theirs
	removed, err := RemoveRoute(broken)
	if err != nil || removed != theirs {
		t.Fatalf("RemoveRoute = %q, %v", removed, err)
	}
}
