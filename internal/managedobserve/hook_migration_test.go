package managedobserve

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kontext-security/kontext/internal/claudemanaged"
	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/hookinstall"
	"github.com/kontext-security/kontext/internal/managedconfig"
)

func migrationFixture(t *testing.T) hookMigration {
	t.Helper()
	dir := t.TempDir()
	m := hookMigration{version: "1.9.1", binary: filepath.Join(dir, "kontext"), hooksPath: filepath.Join(dir, "hooks.json"), statePath: filepath.Join(dir, "hook-migration.json"), canPrompt: func() bool { return true }}
	if err := os.WriteFile(m.binary, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	settings := claudemanaged.Template(m.binary)
	delete(settings.Hooks, "Stop")
	delete(settings.Hooks, "SubagentStop")
	data, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.hooksPath, data, 0644); err != nil {
		t.Fatal(err)
	}
	m.refresh = func(ctx context.Context, digest string) error {
		return hookinstall.RefreshClaude(m.hooksPath, m.binary, digest)
	}
	return m
}

func migrationReceipt(t *testing.T, m hookMigration) hookMigrationState {
	t.Helper()
	data, err := os.ReadFile(m.statePath)
	if err != nil {
		t.Fatal(err)
	}
	var state hookMigrationState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	return state
}

func TestHookMigrationChecksOnlyOncePerVersion(t *testing.T) {
	m := migrationFixture(t)
	calls := 0
	refresh := m.refresh
	m.refresh = func(ctx context.Context, digest string) error {
		calls++
		if state := migrationReceipt(t, m); state.Status != "pending" || state.Version != m.version {
			t.Fatalf("attempt not persisted before prompting: %+v", state)
		}
		return refresh(ctx, digest)
	}
	if err := m.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := migrationReceipt(t, m); state.Status != "complete" {
		t.Fatalf("not complete: %+v", state)
	}
	// Removing the file proves a normal restart doesn't even re-read hooks.
	if err := os.Remove(m.hooksPath); err != nil {
		t.Fatal(err)
	}
	if err := m.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("prompted %d times", calls)
	}
	m.version = "1.10.0"
	if err := m.run(context.Background()); err == nil {
		t.Fatal("new version did not inspect missing hooks")
	}
	if state := migrationReceipt(t, m); state.Version != m.version || state.Status != "pending" {
		t.Fatalf("new version receipt: %+v", state)
	}
}

func TestHookMigrationCurrentHooksNeedNoApproval(t *testing.T) {
	m := migrationFixture(t)
	data, err := claudemanaged.TemplateJSON(m.binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.hooksPath, data, 0644); err != nil {
		t.Fatal(err)
	}
	m.canPrompt = func() bool { t.Fatal("checked GUI for current hooks"); return false }
	m.refresh = func(context.Context, string) error { t.Fatal("prompted for current hooks"); return nil }
	for _, version := range []string{"1.9.1", "1.9.1", "1.10.0"} {
		m.version = version
		if err := m.run(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHookMigrationAddsUserLayerOnceAndPreservesSymlink(t *testing.T) {
	m := migrationFixture(t)
	m.userSettingsPath = filepath.Join(t.TempDir(), "settings.json")
	target := filepath.Join(t.TempDir(), "dotfiles.json")
	original := []byte(`{"permissions":{"allow":["Bash(ls *)"]},"hooks":{"Notification":[{"hooks":[{"type":"command","command":"echo personal"}]}]}}`)
	if err := os.WriteFile(target, original, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, m.userSettingsPath); err != nil {
		t.Fatal(err)
	}
	if err := m.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := migrationReceipt(t, m); state.Status != "complete" || !state.UserHooksComplete {
		t.Fatalf("receipt: %+v", state)
	}
	raw, err := os.ReadFile(target)
	if err != nil || !claudemanaged.CanonicalManagedHooks(raw, m.binary) {
		t.Fatalf("invalid user hooks: %v", err)
	}
	info, _ := os.Lstat(m.userSettingsPath)
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink replaced")
	}
	backups, _ := filepath.Glob(m.userSettingsPath + ".kontext-setup-backup-*")
	if len(backups) != 1 {
		t.Fatalf("backups: %v", backups)
	}
	backup, _ := os.ReadFile(backups[0])
	if string(backup) != string(original) {
		t.Fatal("backup does not preserve original settings")
	}
	// A deliberate deletion is not undone on every daemon restart.
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := m.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("re-enrolled user hooks on normal restart")
	}
}

func TestHookMigrationUpgradesOldCompletedReceipt(t *testing.T) {
	m := migrationFixture(t)
	raw, _ := claudemanaged.TemplateJSON(m.binary)
	if err := os.WriteFile(m.hooksPath, raw, 0644); err != nil {
		t.Fatal(err)
	}
	m.userSettingsPath = filepath.Join(t.TempDir(), "settings.json")
	if err := writeJSONBreadcrumb(m.statePath, hookMigrationState{Version: m.version, Status: "complete"}); err != nil {
		t.Fatal(err)
	}
	m.refresh = func(context.Context, string) error { t.Fatal("prompted for canonical managed hooks"); return nil }
	if err := m.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := migrationReceipt(t, m); !state.UserHooksComplete {
		t.Fatalf("old receipt did not migrate user hooks: %+v", state)
	}
}

func TestHookMigrationDoesNotAddUserHooksAfterDeclinedManagedRefresh(t *testing.T) {
	m := migrationFixture(t)
	m.userSettingsPath = filepath.Join(t.TempDir(), "settings.json")
	m.refresh = func(context.Context, string) error { return errors.New("cancelled") }
	if err := m.run(context.Background()); err == nil {
		t.Fatal("ignored declined refresh")
	}
	if _, err := os.Stat(m.userSettingsPath); !os.IsNotExist(err) {
		t.Fatal("added potentially different handlers after declined refresh")
	}
}

func TestHookMigrationUserFailureRemainsPending(t *testing.T) {
	m := migrationFixture(t)
	raw, _ := claudemanaged.TemplateJSON(m.binary)
	if err := os.WriteFile(m.hooksPath, raw, 0644); err != nil {
		t.Fatal(err)
	}
	m.userSettingsPath = filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(m.userSettingsPath, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	m.refresh = func(context.Context, string) error { t.Fatal("prompted for user settings failure"); return nil }
	for range 2 {
		if err := m.run(context.Background()); err == nil {
			t.Fatal("reported successful user migration with malformed settings")
		}
	}
	if state := migrationReceipt(t, m); state.Status != "pending" || state.UserHooksComplete || state.LastError == "" {
		t.Fatalf("receipt: %+v", state)
	}
	got, _ := os.ReadFile(m.userSettingsPath)
	if string(got) != "{" {
		t.Fatal("replaced malformed user settings")
	}
}

func TestSystemDaemonSkipsUserHookMigration(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, "custom-claude"))
	runSelfServeHookMigration(context.Background(), managedconfig.LoadedConfig{Scope: managedconfig.ScopeSystem}, "1.14.0", diagnostic.Logger{})
	entries, err := os.ReadDir(home)
	if err != nil || len(entries) != 0 {
		t.Fatalf("system daemon created user state: %v %v", entries, err)
	}
}

func TestHookMigrationCancellationDoesNotPromptOnRestart(t *testing.T) {
	m := migrationFixture(t)
	before, _ := os.ReadFile(m.hooksPath)
	calls := 0
	m.refresh = func(context.Context, string) error { calls++; return errors.New("user cancelled") }
	for range 3 {
		if err := m.run(context.Background()); err == nil {
			t.Fatal("lost pending status")
		}
	}
	after, _ := os.ReadFile(m.hooksPath)
	if calls != 1 || string(before) != string(after) {
		t.Fatalf("calls=%d or hooks changed", calls)
	}
	if state := migrationReceipt(t, m); state.Status != "pending" || state.LastError != "user cancelled" {
		t.Fatalf("receipt: %+v", state)
	}
}

func TestHookMigrationDefersUntilInteractiveStartup(t *testing.T) {
	m := migrationFixture(t)
	m.canPrompt = func() bool { return false }
	if err := m.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := migrationReceipt(t, m); state.Status != "awaiting_login" {
		t.Fatalf("receipt: %+v", state)
	}
	m.canPrompt = func() bool { return true }
	if err := m.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := migrationReceipt(t, m); state.Status != "complete" {
		t.Fatalf("receipt: %+v", state)
	}
}

func TestHookMigrationOverlappingStartsOnlyPromptOnce(t *testing.T) {
	m := migrationFixture(t)
	started, finish := make(chan struct{}), make(chan struct{})
	m.refresh = func(context.Context, string) error { close(started); <-finish; return errors.New("cancelled") }
	done := make(chan error, 1)
	go func() { done <- m.run(context.Background()) }()
	<-started
	if err := m.run(context.Background()); err == nil {
		t.Error("expected pending approval")
	}
	close(finish)
	<-done
}

func TestHookMigrationVerifiesPrivilegedResult(t *testing.T) {
	m := migrationFixture(t)
	m.refresh = func(context.Context, string) error { return nil }
	if err := m.run(context.Background()); err == nil {
		t.Fatal("reported successful migration without updated hooks")
	}
	if state := migrationReceipt(t, m); state.Status != "pending" {
		t.Fatalf("receipt: %+v", state)
	}
}

func TestHookMigrationCorruptReceiptDoesNotResetPromptGuard(t *testing.T) {
	m := migrationFixture(t)
	if err := os.WriteFile(m.statePath, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	m.refresh = func(context.Context, string) error { t.Fatal("prompted with corrupt receipt"); return nil }
	if err := m.run(context.Background()); err == nil {
		t.Fatal("ignored invalid receipt")
	}
}

func TestLegacySelfServeCoworkCanStartBeforeHookMigration(t *testing.T) {
	m := migrationFixture(t)
	swapManagedSettingsPaths(t, m.hooksPath, filepath.Join(t.TempDir(), "absent"))
	cfg := managedconfig.Config{LegacyCoworkEnabled: true}
	if err := requireManagedHooksForLegacyCowork(cfg, managedconfig.ScopeUser); err != nil {
		t.Fatalf("old self-serve hooks prevented migration from starting: %v", err)
	}
	if err := requireManagedHooksForLegacyCowork(cfg, managedconfig.ScopeSystem); err == nil {
		t.Fatal("relaxed system installation checks")
	}
	if present, ok := managedObserveHooksFact(); !ok || present.Present {
		t.Fatalf("reported incomplete hooks as healthy: present=%v ok=%v", present, ok)
	}
	if err := os.WriteFile(managedSettingsFilePath, []byte(`{"disableAllHooks":true}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := requireManagedHooksForLegacyCowork(cfg, managedconfig.ScopeUser); err == nil {
		t.Fatal("ignored administrator's disabled hooks")
	}
}
