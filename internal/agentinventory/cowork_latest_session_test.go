package agentinventory

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCoworkLatestSessionFixtures(t *testing.T) {
	now := time.Date(2026, 9, 22, 13, 0, 0, 0, time.FixedZone("fixture", 2*60*60))
	for _, tt := range []struct {
		name string
		want *bool
	}{
		{"host-matching", boolPointer(false)},
		{"host-no-match", boolPointer(false)},
		{"vm-sidecar", boolPointer(true)},
		{"remote-newer", boolPointer(true)},
		{"code-sessions-only", nil},
		{"empty", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fixture, err := filepath.Abs(filepath.Join("testdata", "cowork-latest", tt.name))
			if err != nil {
				t.Fatal(err)
			}
			var sessions []string
			data, err := os.ReadFile(filepath.Join(fixture, "sessions.json"))
			if err != nil {
				t.Fatalf("read sessions: %v", err)
			}
			if err := json.Unmarshal(data, &sessions); err != nil {
				t.Fatalf("decode sessions: %v", err)
			}
			inv := Scan(context.Background(), filepath.Join(fixture, "home"), nil, now, ScanOptions{
				Wired: map[string]func() Wired{"claude_cowork": func() Wired { return WiredYes }},
				HasCoworkSession: func(id string) (bool, error) {
					for _, session := range sessions {
						if session == id {
							return true, nil
						}
					}
					return false, nil
				},
			})
			var cowork *Agent
			for i := range inv.Agents {
				if inv.Agents[i].ID == "claude_cowork" {
					cowork = &inv.Agents[i]
				}
			}
			if tt.name == "code-sessions-only" {
				if cowork != nil {
					t.Fatalf("Cowork discovered from Code sessions: %+v", *cowork)
				}
				return
			}
			if cowork == nil {
				t.Fatal("Cowork not discovered")
			}
			if (cowork.Sandboxed == nil) != (tt.want == nil) || cowork.Sandboxed != nil && *cowork.Sandboxed != *tt.want {
				t.Fatalf("sandboxed=%v, want %v", cowork.Sandboxed, tt.want)
			}
		})
	}
}
