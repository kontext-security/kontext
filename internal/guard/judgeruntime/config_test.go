package judgeruntime

import (
	"path/filepath"
	"testing"
)

// Managed mode is opt-in. Nothing defaults it on, so no path downloads a model
// or runs a llama-server child unless an operator asked for it.
func TestConfigFromEnvLeavesManagedOffByDefault(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "guard.db")

	cfg, err := ConfigFromEnv(dbPath)
	if err != nil {
		t.Fatalf("ConfigFromEnv() error = %v", err)
	}
	if cfg.Managed {
		t.Fatal("Managed = true, want false without an explicit opt-in")
	}
	if cfg.CacheDir != filepath.Join(filepath.Dir(dbPath), "judge-models") {
		t.Fatalf("CacheDir = %q, want db-adjacent judge-models", cfg.CacheDir)
	}
}

func TestConfigFromEnvManagedIsOptIn(t *testing.T) {
	t.Setenv("KONTEXT_JUDGE_MANAGED", "1")

	cfg, err := ConfigFromEnv(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatalf("ConfigFromEnv() error = %v", err)
	}
	if !cfg.Managed {
		t.Fatal("Managed = false, want true when explicitly opted in")
	}
}

func TestConfigFromEnvTreatsJudgeURLAsExternalByDefault(t *testing.T) {
	t.Setenv("KONTEXT_JUDGE_URL", "http://127.0.0.1:18080")
	t.Setenv("KONTEXT_JUDGE_MODEL", "qwen3")

	cfg, err := ConfigFromEnv(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatalf("ConfigFromEnv() error = %v", err)
	}
	if cfg.Managed {
		t.Fatal("Managed = true, want false for explicit judge URL")
	}
}
