package agentinventory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCoworkDiscovery(t *testing.T) {
	now := time.Date(2026, 9, 18, 16, 0, 0, 0, time.FixedZone("fixture", 2*60*60))
	type sidecar struct {
		name, id string
		created  time.Time
		host     *bool
	}
	for _, tt := range []struct {
		name     string
		dirs     []string
		sidecars []sidecar
		sessions map[string]bool
		storeErr bool
		want     string
		golden   bool
	}{
		{"vm", nil, []sidecar{{"local_vm.json", "vm", now.Add(-time.Minute), boolPointer(false)}}, nil, false, "true", true},
		{"host", nil, []sidecar{{"local_host.json", "host", now.Add(-time.Minute), boolPointer(true)}}, map[string]bool{"host": true}, false, "false", true},
		{"katana", []string{coworkVMBundle}, []sidecar{{"local_old_vm.json", "old-vm", now.Add(-2 * time.Minute), boolPointer(false)}, {"local_host.json", "host", now.Add(-time.Minute), nil}}, map[string]bool{"host": true}, false, "false", true},
		{"neither", nil, nil, nil, false, "", true},
		{"host directory only", []string{coworkHostSessions}, nil, nil, false, "null", false},
		{"bundle only", []string{coworkVMBundle}, nil, nil, false, "null", false},
		{"old host sidecar", nil, []sidecar{{"local_old_host.json", "old-host", now.Add(-60 * 24 * time.Hour), nil}}, nil, false, "false", false},
		{"store unreadable", nil, []sidecar{{"local_host.json", "host", now.Add(-time.Minute), boolPointer(true)}}, nil, true, "null", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			home, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			for _, dir := range tt.dirs {
				if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			for _, fixture := range tt.sidecars {
				path := filepath.Join(home, coworkHostSessions, "account-fixture", "org-fixture", fixture.name)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				data, err := json.Marshal(coworkSidecar{CreatedAt: fixture.created.UnixMilli(), LastActivityAt: fixture.created.Add(time.Minute).UnixMilli(), HostLoopMode: fixture.host, CLISessionID: fixture.id})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, 0o600); err != nil {
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
				HasCoworkSession: func(id string) (bool, error) {
					if tt.want == "" {
						t.Fatal("store queried for an absent agent")
					}
					if tt.storeErr {
						return false, errors.New("store unavailable")
					}
					return tt.sessions[id], nil
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
					if err := os.WriteFile(path, data, 0o600); err != nil {
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
	home := t.TempDir()
	path := filepath.Join(home, coworkHostSessions, "account-fixture", "org-fixture", "local_host.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(coworkSidecar{CreatedAt: time.Now().UnixMilli(), CLISessionID: "fixture-host"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := coworkSandbox(context.Background(), home, time.Now(), nil); got != nil {
		t.Fatalf("sandboxed=%v without store", *got)
	}
}

func TestLatestRemoteCoworkSessionIgnoresFutureMarkers(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "Library/Logs/Claude/claude.ai-web.log")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	data := []byte("2026-09-18 15:59:00 [warn] [LOCAL_SESSION] remote_cowork.valid\n2026-09-18 16:01:00 [warn] [LOCAL_SESSION] remote_cowork.future\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 18, 16, 0, 0, 0, time.FixedZone("fixture", 2*60*60))
	got, found, err := latestRemoteCoworkSession(context.Background(), home, now)
	want := now.Add(-time.Minute)
	if err != nil || !found || !got.Equal(want) {
		t.Fatalf("latest=%s, found=%t, error=%v; want %s", got, found, err, want)
	}
}

func TestLatestRemoteCoworkSessionReadsPast64K(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "Library/Logs/Claude/claude.ai-web.log")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	marker := []byte("2026-09-18 15:59:00 [warn] [LOCAL_SESSION] remote_cowork.deep_marker\n")
	data := append(marker, bytes.Repeat([]byte("x"), 64*1024+1)...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 18, 16, 0, 0, 0, time.FixedZone("fixture", 2*60*60))
	got, found, err := latestRemoteCoworkSession(context.Background(), home, now)
	want := now.Add(-time.Minute)
	if err != nil || !found || !got.Equal(want) {
		t.Fatalf("latest=%s, found=%t, error=%v; want %s", got, found, err, want)
	}
}

func TestLatestCoworkSidecarUsesMtimeForUnreadableContent(t *testing.T) {
	now := time.Date(2026, 9, 18, 16, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name string
		data []byte
	}{
		{"oversized", bytes.Repeat([]byte("x"), 2*1024*1024)},
		{"unparseable", []byte("{")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			home, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(home, coworkHostSessions, "account-fixture", "org-fixture")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			old := filepath.Join(dir, "local_old_vm.json")
			data, err := json.Marshal(coworkSidecar{CreatedAt: now.Add(-2 * time.Hour).UnixMilli(), HostLoopMode: boolPointer(false), CLISessionID: "older-vm"})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(old, data, 0o600); err != nil {
				t.Fatal(err)
			}
			newer := filepath.Join(dir, "local_newer_host.json")
			if err := os.WriteFile(newer, tt.data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(newer, now.Add(-time.Minute), now.Add(-time.Minute)); err != nil {
				t.Fatal(err)
			}
			got := coworkSandbox(context.Background(), home, now, func(id string) (bool, error) {
				if id != "" {
					t.Fatalf("fallback session id=%q, want empty", id)
				}
				return false, nil
			})
			if got == nil || *got {
				t.Fatalf("sandboxed=%v, want false", got)
			}
		})
	}
}

func TestLatestCoworkSidecarBoundsFutureFallbackMtime(t *testing.T) {
	now := time.Date(2026, 9, 18, 16, 0, 0, 0, time.UTC)
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, coworkHostSessions, "account-fixture", "org-fixture")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	valid := filepath.Join(dir, "local_vm.json")
	data, err := json.Marshal(coworkSidecar{CreatedAt: now.Add(-time.Minute).UnixMilli(), HostLoopMode: boolPointer(false)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(valid, data, 0o600); err != nil {
		t.Fatal(err)
	}
	future := filepath.Join(dir, "local_future_host.json")
	if err := os.WriteFile(future, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(future, now.Add(time.Hour), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got := coworkSandbox(context.Background(), home, now, func(id string) (bool, error) {
		if id != "" {
			t.Fatalf("fallback session id=%q, want empty", id)
		}
		return false, nil
	})
	if got == nil || *got {
		t.Fatalf("sandboxed=%v, want false", got)
	}
}

func TestLatestCoworkSidecarEntryLimit(t *testing.T) {
	root := t.TempDir()
	for i := 0; i <= coworkSidecarEntryLimit; i++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("ignored-%04d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if sidecar, complete := latestCoworkSidecar(context.Background(), root, time.Now()); complete || sidecar != nil {
		t.Fatalf("sidecar=%+v, complete=%t", sidecar, complete)
	}
}
