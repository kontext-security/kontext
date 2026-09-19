package agentinventory

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCoworkDiscovery(t *testing.T) {
	now := time.Date(2026, 9, 18, 16, 0, 0, 0, time.FixedZone("fixture", 2*60*60))
	boot := "[VM] 2026-09-18 15:59:00 [info] VM startup step: vm_boot completed\n"
	for _, tt := range []struct {
		name     string
		dirs     []string
		log      string
		sessions bool
		storeErr bool
		want     string
		golden   bool
	}{
		{"vm", []string{coworkVMBundle}, boot, false, false, "true", true},
		{"host", []string{coworkHostSessions}, "", true, false, "false", true},
		{"katana", []string{coworkHostSessions, coworkVMBundle}, boot, true, false, "false", true},
		{"neither", nil, "", false, false, "", true},
		{"not installed with sessions", nil, "", true, false, "", false},
		{"sessions directory only", []string{coworkVMSessions}, "", false, false, "null", false},
		{"host directory only", []string{coworkHostSessions}, "", false, false, "null", false},
		{"log only", nil, boot, false, false, "true", false},
		{"bundle only", []string{coworkVMBundle}, "", false, false, "null", false},
		{"old boot", []string{coworkVMBundle}, "[VM] 2026-08-18 15:59:00 [info] VM startup step: vm_boot completed\n", false, false, "null", false},
		{"future boot", []string{coworkVMBundle}, "[VM] 2026-09-19 15:59:00 [info] VM startup step: vm_boot completed\n", false, false, "null", false},
		{"start only", []string{coworkVMBundle}, "[VM] 2026-09-18 15:59:00 [info] startVM called\n", false, false, "null", false},
		{"store unreadable", []string{coworkVMBundle}, boot, false, true, "null", false},
		{"boot outside tail", []string{coworkVMBundle}, boot + strings.Repeat("x", 65536), false, false, "null", false},
		{"large log", []string{coworkVMBundle}, strings.Repeat("x", 2*1024*1024) + "\n" + boot, false, false, "true", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			home, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			for _, dir := range tt.dirs {
				if err := os.MkdirAll(filepath.Join(home, dir), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if tt.log != "" {
				path := filepath.Join(home, coworkVMLog)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(tt.log), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := filepath.WalkDir(home, func(path string, _ os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				return os.Chtimes(path, now, now)
			}); err != nil {
				t.Fatal(err)
			}
			inv := Scan(context.Background(), home, nil, now, ScanOptions{
				Wired: map[string]func() Wired{"claude_cowork": func() Wired { return WiredYes }},
				HasCoworkSessionsSince: func(since time.Time) (bool, error) {
					if tt.want == "" {
						t.Fatal("store queried for an absent agent")
					}
					if !since.Equal(now.Add(-30 * 24 * time.Hour)) {
						t.Fatalf("since=%s", since)
					}
					if tt.storeErr {
						return false, errors.New("store unavailable")
					}
					return tt.sessions, nil
				},
			})
			data, err := json.MarshalIndent(inv, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, '\n')
			if tt.want == "" {
				if len(inv.Agents) != 0 {
					t.Fatalf("not installed: %s", data)
				}
			} else if len(inv.Agents) != 1 || !strings.Contains(string(data), `"sandboxed": `+tt.want) || inv.Agents[0].Wired != WiredYes {
				t.Fatalf("want sandboxed=%s and hook fact unchanged: %s", tt.want, data)
			}
			if tt.golden {
				path := filepath.Join("testdata", "cowork-"+tt.name+".json")
				if os.Getenv("UPDATE_GOLDEN") == "1" {
					if err := os.WriteFile(path, data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				want, err := os.ReadFile(path)
				if err != nil || string(want) != string(data) {
					t.Fatalf("golden mismatch (%v):\n%s", err, data)
				}
			}
		})
	}
}

func TestCoworkSandboxWithoutStore(t *testing.T) {
	if got := coworkSandbox(context.Background(), t.TempDir(), time.Now(), nil); got != nil {
		t.Fatalf("sandboxed=%v without store", *got)
	}
}
