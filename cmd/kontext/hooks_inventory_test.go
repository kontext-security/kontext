package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/pkg/agentauthority"
)

// A real settings file through the scan, the uploaded JSON and the listing:
// a credential in a hook's command reaches none of them, and text from the
// file can't forge a line of the listing.
func TestHookInventoryKeepsCredentialsAndControlCharactersOut(t *testing.T) {
	home := t.TempDir()
	settings := map[string]any{"hooks": map[string]any{
		"Stop": []any{map[string]any{"matcher": "Bash\nStop [*] kontext hook stop", "hooks": []any{
			map[string]any{"type": "command", "command": "curl -u build:example-pass https://service.example/hook"},
		}}},
	}}
	data, _ := json.Marshal(settings)
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	agent, source, err := agentauthority.ScanHooks(context.Background(), agentauthority.HookScanOptions{Home: home, Key: []byte("0123456789abcdef0123456789abcdef"), Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(agentauthority.HookInventory{Schema: agentauthority.HookInventorySchema, IDScheme: agentauthority.HookIDScheme, Agents: []agentauthority.HookAgent{agent}})
	var listing bytes.Buffer
	printHookInventory(&listing, hookInventoryOutput{Agent: agent, Source: source})
	for name, text := range map[string]string{"upload": string(wire), "listing": listing.String()} {
		for _, leaked := range []string{"build", "example-pass", "/hook"} {
			if strings.Contains(text, leaked) {
				t.Fatalf("%s holds %q: %s", name, leaked, text)
			}
		}
	}
	if strings.Contains(listing.String(), "\nStop [*] kontext") {
		t.Fatalf("a matcher forged a line:\n%s", listing.String())
	}
}

func TestPrintableEscapesControlCharacters(t *testing.T) {
	if got := printable("a\nb\x1b[2J"); got != `a\nb\x1b[2J` {
		t.Fatalf("%q", got)
	}
	if got := printable("Edit|Write"); got != "Edit|Write" {
		t.Fatalf("%q", got)
	}
}
