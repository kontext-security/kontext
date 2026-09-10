package agentinventory

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestScan(t *testing.T) {
	now := time.Date(2026, 9, 9, 8, 20, 0, 0, time.UTC)
	activity := now.Add(-8 * time.Minute).Format(time.RFC3339)
	for _, name := range []string{"empty", "cursor", "outside home", "home override", "activity", "cap", "depth", "shallow sibling", "directory activity", "fifo", "symlink", "wired error", "cancelled", "path cap"} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			env := map[string]string{}
			wired := map[string]func() Wired{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := []Agent{}
			incomplete := false
			mkdir := func(rel string) string {
				path := filepath.Join(home, rel)
				if err := os.MkdirAll(path, 0o700); err != nil {
					t.Fatal(err)
				}
				return path
			}
			file := func(rel string, mtime time.Time) {
				mkdir(filepath.Dir(rel))
				path := filepath.Join(home, rel)
				if err := os.WriteFile(path, []byte("must not be read"), 0o000); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(path, mtime, mtime); err != nil {
					t.Fatal(err)
				}
			}
			if name != "empty" && name != "outside home" && name != "home override" && name != "cancelled" && name != "path cap" {
				mkdir(".cursor")
				want = []Agent{{ID: "cursor", ConfigPath: "~/.cursor", Wired: WiredUnsupported}}
			}
			switch name {
			case "home override":
				env["CODEX_HOME"] = home
				wired["codex"] = func() Wired { return WiredNo }
				want = []Agent{{ID: "codex", ConfigPath: "~/", Wired: WiredNo}}
			case "outside home":
				env["CODEX_HOME"] = t.TempDir()
				wired["codex"] = func() Wired { return WiredNo }
				want = []Agent{{ID: "codex", ConfigPath: env["CODEX_HOME"], Wired: WiredNo}}
			case "activity":
				file(".cursor/projects/old", now.Add(-time.Hour))
				file(".cursor/projects/a/b/new", now.Add(-8*time.Minute))
				want[0].LastActivityAt = &activity
			case "cap":
				for i := 0; i < 2500; i++ {
					file(fmt.Sprintf(".cursor/projects/%04d", i), now.Add(-8*time.Minute))
				}
				want[0].LastActivityAt = &activity
				incomplete = true
			case "depth", "shallow sibling":
				deep, shallow := now.Add(-8*time.Minute), now.Add(-time.Hour)
				if name == "shallow sibling" {
					deep, shallow = shallow, deep
				}
				file(".cursor/projects/a/b/c/deep", deep)
				file(".cursor/projects/a/b/c/d/too-deep", now)
				file(".cursor/projects/z", shallow)
				want[0].LastActivityAt = &activity
			case "directory activity":
				mkdir(".cursor/projects/a/b/c/d")
				want[0].LastActivityAt = &activity
			case "fifo":
				want[0].LastActivityAt = &activity
				root := mkdir(".cursor/projects")
				if err := syscall.Mkfifo(filepath.Join(root, "pipe"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				want[0].LastActivityAt = &activity
				file("outside/recent", now)
				root := mkdir(".cursor/projects")
				if err := os.Symlink(filepath.Join(home, "outside"), filepath.Join(root, "link")); err != nil {
					t.Fatal(err)
				}
			case "wired error":
				mkdir(".claude")
				wired["claude_code"] = func() Wired { return WiredError }
				want = append([]Agent{{ID: "claude_code", ConfigPath: "~/.claude", Wired: WiredError}}, want...)
			case "cancelled":
				cancel()
				incomplete = true
			case "path cap":
				rel := strings.Repeat(strings.Repeat("a", 100)+"/", 11)
				path := filepath.Join(home, rel)
				if err := os.MkdirAll(path, 0o700); err != nil {
					if runtime.GOOS != "darwin" {
						t.Fatal(err)
					}
					// Darwin rejects paths this long before discovery can stat them.
				}
				env["CODEX_HOME"] = path
			}
			// Directory mtimes are activity too. Keep fixture directories older
			// than files, except the directory-only and special-file cases.
			dirTime := now.Add(-2 * time.Hour)
			if name == "fifo" || name == "symlink" || name == "directory activity" {
				dirTime = now.Add(-8 * time.Minute)
			}
			if err := filepath.WalkDir(home, func(path string, entry os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if entry.IsDir() {
					return os.Chtimes(path, dirTime, dirTime)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			got := Scan(ctx, home, func(key string) string { return env[key] }, now, wired)
			if !reflect.DeepEqual(got, Inventory{Agents: want, ReportedAt: now.Format(time.RFC3339), Incomplete: incomplete}) {
				t.Fatalf("Scan = %+v, want agents %+v, incomplete %t", got, want, incomplete)
			}
		})
	}
}

func TestConfigResolution(t *testing.T) {
	home := t.TempDir()
	for _, tt := range []struct {
		id   string
		env  map[string]string
		want []string
	}{
		{"claude_code", map[string]string{"CLAUDE_CONFIG_DIR": " ~/custom "}, []string{"custom"}},
		{"gemini_cli", map[string]string{"GEMINI_CLI_HOME": "~/custom"}, []string{"custom/.gemini"}},
		{"amp", map[string]string{"XDG_CONFIG_HOME": "~/config"}, []string{"config/amp"}},
		{"opencode", map[string]string{"XDG_CONFIG_HOME": "~/config"}, []string{"config/opencode"}},
		{"opencode", map[string]string{"XDG_CONFIG_HOME": "~/config", "OPENCODE_CONFIG_DIR": "~/override"}, []string{"override"}},
		{"openclaw", map[string]string{"OPENCLAW_HOME": "~/custom"}, []string{"custom/.openclaw", "custom/.clawdbot"}},
		{"openclaw", map[string]string{"OPENCLAW_HOME": " null "}, []string{".openclaw", ".clawdbot"}},
		{"openclaw", map[string]string{"OPENCLAW_HOME": "undefined"}, []string{".openclaw", ".clawdbot"}},
		{"openclaw", map[string]string{"OPENCLAW_HOME": "~/custom", "OPENCLAW_STATE_DIR": "~/state"}, []string{"state"}},
		{"kiro", map[string]string{"KIRO_HOME": "~/custom"}, []string{"custom", ".kiro"}},
		{"crush", map[string]string{"CRUSH_GLOBAL_CONFIG": "~/custom/crush.json", "XDG_CONFIG_HOME": "~/config"}, []string{"custom"}},
		{"crush", map[string]string{"XDG_CONFIG_HOME": "~"}, []string{"crush"}},
		{"windsurf", nil, []string{".windsurf", ".codeium/windsurf"}},
	} {
		t.Run(tt.id+fmt.Sprint(tt.env), func(t *testing.T) {
			for _, d := range Catalog {
				if d.ID == tt.id {
					want := []string{}
					for _, path := range tt.want {
						want = append(want, filepath.Join(home, path))
					}
					if got := configDirs(d, home, func(key string) string { return tt.env[key] }); !reflect.DeepEqual(got, want) {
						t.Fatalf("dirs=%v, want %v", got, want)
					}
				}
			}
		})
	}
}

func TestCatalogAndWireContract(t *testing.T) {
	const ids = "claude_code,claude_cowork,codex,gemini_cli,cursor,windsurf,copilot_cli,opencode,openclaw,pi,kimi_code,qwen_code,cline,amp,auggie,kiro,goose,kilo,crush,junie,antigravity,factory_droid,grok_build,devin_cli,hermes"
	got := []string{}
	for _, d := range Catalog {
		got = append(got, d.ID)
	}
	if strings.Join(got, ",") != ids {
		t.Fatalf("catalog ids=%v", got)
	}
	activity := "2026-09-09T08:12:00Z"
	data, err := json.Marshal(Inventory{Agents: []Agent{{"claude_code", "~/.claude", WiredYes, &activity}, {"cursor", "~/.cursor", WiredUnsupported, nil}}, ReportedAt: "2026-09-09T08:20:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"agents":[{"id":"claude_code","config_path":"~/.claude","wired":"yes","last_activity_at":"2026-09-09T08:12:00Z"},{"id":"cursor","config_path":"~/.cursor","wired":"unsupported","last_activity_at":null}],"agents_reported_at":"2026-09-09T08:20:00Z"}`
	if string(data) != want {
		t.Fatalf("wire=%s", data)
	}
}

func TestScanEmptyHomeDuration(t *testing.T) {
	home := t.TempDir()
	start := time.Now()
	Scan(context.Background(), home, func(string) string { return "" }, start, nil)
	if elapsed := time.Since(start); elapsed >= 20*time.Millisecond {
		t.Fatalf("empty-home scan took %s; must be under 20 ms", elapsed)
	}
}

func BenchmarkScanEmptyHome(b *testing.B) {
	home := b.TempDir()
	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Scan(context.Background(), home, func(string) string { return "" }, now, nil)
	}
}

func TestLastActivityPrioritizesRecentDirectoriesWithoutPruningOldOnes(t *testing.T) {
	now := time.Date(2026, 9, 10, 9, 0, 0, 0, time.UTC)
	old := now.Add(-48 * time.Hour)
	want := now.Add(-time.Minute)
	for _, capped := range []bool{false, true} {
		t.Run(fmt.Sprintf("capped=%t", capped), func(t *testing.T) {
			root := t.TempDir()
			stamp := func(path string, at time.Time) {
				t.Helper()
				if err := os.Chtimes(path, at, at); err != nil {
					t.Fatal(err)
				}
			}
			write := func(path string, at time.Time) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, nil, 0o000); err != nil {
					t.Fatal(err)
				}
				stamp(path, at)
			}
			if capped {
				// Lexical order exhausts the budget before reaching today's folder.
				for i := 0; i < 2100; i++ {
					write(filepath.Join(root, "a-old", fmt.Sprint(i)), old)
				}
				write(filepath.Join(root, "z-recent", "session"), want)
				stamp(filepath.Join(root, "a-old"), old)
				stamp(filepath.Join(root, "z-recent"), now.Add(-time.Hour))
			} else {
				// Appending to a transcript does not change its parent's mtime.
				write(filepath.Join(root, "a-recent", "session"), now.Add(-time.Hour))
				write(filepath.Join(root, "z-old", "session"), old)
				stamp(filepath.Join(root, "a-recent"), now.Add(-time.Hour))
				stamp(filepath.Join(root, "z-old"), old)
				stamp(filepath.Join(root, "z-old", "session"), want)
			}
			stamp(root, old)
			got, incomplete := lastActivity(context.Background(), root)
			if got == nil || *got != want.Format(time.RFC3339) || incomplete != capped {
				t.Fatalf("activity=%v, incomplete=%t; want %s, incomplete=%t", got, incomplete, want.Format(time.RFC3339), capped)
			}
		})
	}
}
