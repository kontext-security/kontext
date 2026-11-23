//go:build darwin

package managedobserve

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/agentinventory"
	"github.com/kontext-security/kontext/internal/claudemanaged"
	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/endpointconfig"
	"github.com/kontext-security/kontext/internal/hermetic"
	"github.com/kontext-security/kontext/internal/managedconfig"
	"github.com/kontext-security/kontext/internal/managedstream"
)

// On a packaged Mac the reconciler reports the package's drop-in: in place,
// then, once removed, needing the package pushed again (the daemon never
// writes it), and the local opt-out over both, even over a drop-in that names
// another binary. A kick runs the pass at once.
func TestReconcilerReportsThePackagesDropIn(t *testing.T) {
	home := t.TempDir()
	hermetic.SetHome(t, home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("CODEX_HOME", "")
	for _, d := range agentinventory.Catalog {
		if d.ConfigEnv != "" {
			t.Setenv(d.ConfigEnv, "")
		}
	}
	config := filepath.Join(t.TempDir(), "managed.json")
	if err := os.WriteFile(config, managedConfigJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(managedconfig.EnvPath, config)
	loaded, err := managedconfig.Load()
	if err != nil || loaded.Scope == managedconfig.ScopeUser {
		t.Fatalf("config %+v: %v", loaded, err)
	}
	binary := hermetic.KontextBinary(t, t.TempDir())
	previousBinary, previousExe := managedHookBinary, executablePath
	managedHookBinary, executablePath = binary, func() (string, error) { return binary, nil }
	t.Cleanup(func() { managedHookBinary, executablePath = previousBinary, previousExe })
	dropIn := filepath.Join(t.TempDir(), "20-kontext.json")
	swapManagedSettingsPaths(t, dropIn, filepath.Join(filepath.Dir(dropIn), "managed-settings.json"))
	managedHookDropIn = dropIn
	t.Cleanup(func() { managedHookDropIn = "" })
	template, err := claudemanaged.TemplateJSON(binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dropIn, template, 0o644); err != nil {
		t.Fatal(err)
	}

	nonce := "AAAAAAAAAAAAAAAAAAAAAA"
	reconciler := newHookReconciler(func() (endpointconfig.HookState, string) {
		return endpointconfig.HookState{Desired: endpointconfig.HookStateInstalled, Generation: 1, RepairNonce: &nonce}, "owner"
	})
	kick := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runHookWatch(ctx, loaded, diagnostic.Logger{}, func() {}, hookWatchOptions{reconciler: reconciler, kick: kick})
	}()
	t.Cleanup(func() { cancel(); <-done })

	expect := func(status string) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			if report, sent := reconciler.take("owner"); report != nil {
				sent()
				want := managedstream.HookActionResult{Agent: "claude_code", ScopeKind: "managed_dropin", Status: status}
				if report.Generation == 1 && *report.RepairNonce == nonce && len(report.Results) == 1 && report.Results[0] == want {
					return
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("no %s report", status)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	expect(managedstream.HookInPlace)

	if err := os.Remove(dropIn); err != nil {
		t.Fatal(err)
	}
	kick <- struct{}{}
	expect(managedstream.HookNeedsPrivileged)
	if _, err := os.Lstat(dropIn); err == nil {
		t.Fatal("the daemon wrote the package's drop-in")
	}

	// A drop-in naming another binary is pushed, and the admin opts this
	// Mac out locally: the opt-out is what the cloud hears.
	other, err := claudemanaged.TemplateJSON(hermetic.KontextBinary(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dropIn, other, 0o644); err != nil {
		t.Fatal(err)
	}
	optOut := strings.Replace(string(managedConfigJSON), `"mode":"observe"`, `"mode":"observe","hook_repair":false`, 1)
	if err := os.WriteFile(config, []byte(optOut), 0o600); err != nil {
		t.Fatal(err)
	}
	kick <- struct{}{}
	expect(managedstream.HookAdminOff)
}
