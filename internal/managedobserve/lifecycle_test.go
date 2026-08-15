package managedobserve

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	guardhookruntime "github.com/kontext-security/kontext-cli/internal/guard/hookruntime"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/localruntime"
)

func TestLifecycleMissingSocketKickstartsAndFailsOpenObserve(t *testing.T) {
	kickstarts := 0
	lifecycle := Lifecycle{
		SocketPath: filepath.Join(t.TempDir(), "missing.sock"),
		Label:      DefaultLaunchdLabel,
		Kickstart: func(context.Context, string) error {
			kickstarts++
			return nil
		},
	}

	result := lifecycle.Process(context.Background(), hook.Event{
		HookName: hook.HookPreToolUse,
		ToolName: "Bash",
	})

	if kickstarts != 1 {
		t.Fatalf("kickstarts = %d, want 1", kickstarts)
	}
	if result.Decision != hook.DecisionAllow || result.Mode != string(guardhookruntime.ModeObserve) {
		t.Fatalf("result = %+v, want observe allow", result)
	}
}

func TestLifecyclePollsAfterKickstartWithinDeadline(t *testing.T) {
	socketPath := filepath.Join("/tmp", fmt.Sprintf("kontext-managedobserve-delayed-test-%d.sock", time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	ready := make(chan struct{})
	done := make(chan struct{})

	lifecycle := Lifecycle{
		SocketPath: socketPath,
		Label:      DefaultLaunchdLabel,
		Kickstart: func(context.Context, string) error {
			go func() {
				time.Sleep(50 * time.Millisecond)
				ln, err := net.Listen("unix", socketPath)
				if err != nil {
					close(done)
					return
				}
				defer ln.Close()
				defer close(done)
				close(ready)
				for i := 0; i < 2; i++ {
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					if i == 0 {
						_ = conn.Close()
						continue
					}
					var req localruntime.EvaluateRequest
					if err := localruntime.ReadMessage(conn, &req); err == nil {
						_ = localruntime.WriteMessage(conn, localruntime.EvaluateResult{
							Decision: "deny",
							Allowed:  false,
							Reason:   "delayed policy",
						})
					}
					_ = conn.Close()
				}
			}()
			return nil
		},
	}

	result := lifecycle.Process(context.Background(), hook.Event{HookName: hook.HookPreToolUse})
	if result.Decision != hook.DecisionAllow || result.Mode != string(guardhookruntime.ModeObserve) {
		t.Fatalf("result = %+v, want observe allow", result)
	}
	if result.Reason != "Kontext observe mode: would deny; delayed policy" {
		t.Fatalf("reason = %q, want delayed daemon result", result.Reason)
	}
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("delayed daemon did not start")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("delayed daemon did not receive request")
	}
}

func TestLifecycleKickstartFailureIsDiagnosedAndFailsOpen(t *testing.T) {
	var output bytes.Buffer
	lifecycle := Lifecycle{
		SocketPath: filepath.Join(t.TempDir(), "missing.sock"),
		Label:      DefaultLaunchdLabel,
		Kickstart: func(context.Context, string) error {
			return errors.New("launchd refused")
		},
		Diagnostic: diagnostic.New(&output, true),
	}

	result := lifecycle.Process(context.Background(), hook.Event{
		HookName: hook.HookPreToolUse,
		ToolName: "Bash",
	})

	if result.Decision != hook.DecisionAllow || result.Mode != string(guardhookruntime.ModeObserve) {
		t.Fatalf("result = %+v, want observe allow", result)
	}
	if !strings.Contains(output.String(), "managed observe kickstart: launchd refused") {
		t.Fatalf("diagnostic output = %q, want kickstart failure", output.String())
	}
}

func TestLifecycleHealthySocketDoesNotKickstart(t *testing.T) {
	socketPath := filepath.Join("/tmp", fmt.Sprintf("kontext-managedobserve-test-%d.sock", time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2; i++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var req localruntime.EvaluateRequest
		if err := localruntime.ReadMessage(conn, &req); err != nil {
			return
		}
		_ = localruntime.WriteMessage(conn, localruntime.EvaluateResult{
			Decision: "deny",
			Allowed:  false,
			Reason:   "policy deny",
		})
	}()

	lifecycle := Lifecycle{
		SocketPath: socketPath,
		Label:      DefaultLaunchdLabel,
		Kickstart: func(context.Context, string) error {
			t.Fatal("kickstart should not be called")
			return nil
		},
	}
	result := lifecycle.Process(context.Background(), hook.Event{HookName: hook.HookPreToolUse})
	if result.Decision != hook.DecisionAllow || result.Mode != string(guardhookruntime.ModeObserve) {
		t.Fatalf("result = %+v, want observe allow", result)
	}
	if result.Reason != "Kontext observe mode: would deny; policy deny" {
		t.Fatalf("reason = %q, want observe deny reason", result.Reason)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server did not receive request")
	}
}

func TestLifecycleEnforcePassesDaemonDenyThroughToAgent(t *testing.T) {
	socketPath := filepath.Join("/tmp", fmt.Sprintf("kontext-managedobserve-enforce-test-%d.sock", time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2; i++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var req localruntime.EvaluateRequest
		if err := localruntime.ReadMessage(conn, &req); err != nil {
			return
		}
		// In enforce the guard server returns the authoritative decision
		// without an observe transform; the wrapper must not downgrade it.
		_ = localruntime.WriteMessage(conn, localruntime.EvaluateResult{
			Decision: "deny",
			Allowed:  false,
			Reason:   "local Cedar policy decision",
			Mode:     "enforce",
		})
	}()

	lifecycle := Lifecycle{
		SocketPath: socketPath,
		Label:      DefaultLaunchdLabel,
		Mode:       "enforce",
		Kickstart: func(context.Context, string) error {
			t.Fatal("kickstart should not be called")
			return nil
		},
	}
	result := lifecycle.Process(context.Background(), hook.Event{HookName: hook.HookPreToolUse})
	if result.Decision != hook.DecisionDeny {
		t.Fatalf("result = %+v, want enforce deny passed through", result)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server did not receive request")
	}
}

func TestLifecycleEnforceFailsClosedWhenDaemonUnavailable(t *testing.T) {
	socketPath := filepath.Join("/tmp", fmt.Sprintf("kontext-managedobserve-enforce-down-%d.sock", time.Now().UnixNano()))
	lifecycle := Lifecycle{
		SocketPath: socketPath,
		Label:      DefaultLaunchdLabel,
		Mode:       "enforce",
		Kickstart:  func(context.Context, string) error { return nil },
	}
	result := lifecycle.Process(context.Background(), hook.Event{HookName: hook.HookPreToolUse})
	if result.Decision != hook.DecisionDeny {
		t.Fatalf("result = %+v, want enforce fail-closed deny when daemon unavailable", result)
	}
}

func TestLifecycleEnforceFailsClosedWhenDaemonDropsRPC(t *testing.T) {
	socketPath := filepath.Join("/tmp", fmt.Sprintf("kontext-managedobserve-enforce-rpc-%d.sock", time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 3 {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			_ = connection.Close()
		}
	}()

	lifecycle := Lifecycle{
		SocketPath: socketPath,
		Label:      DefaultLaunchdLabel,
		Mode:       "enforce",
		Kickstart: func(context.Context, string) error {
			t.Fatal("kickstart should not be called")
			return nil
		},
	}
	result := lifecycle.Process(context.Background(), hook.Event{HookName: hook.HookPreToolUse})
	if result.Decision != hook.DecisionDeny {
		t.Fatalf("result = %+v, want enforce fail-closed deny after RPC failure", result)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server did not receive RPC")
	}
}

func TestLifecycleEnforceRejectsNonAuthoritativeDaemonResult(t *testing.T) {
	t.Parallel()

	lifecycle := Lifecycle{Mode: "enforce"}
	event := hook.Event{HookName: hook.HookPreToolUse}
	tests := []struct {
		name   string
		result hook.Result
	}{
		{name: "missing decision", result: hook.Result{Mode: "enforce"}},
		{name: "missing mode", result: hook.Result{Decision: hook.DecisionAllow}},
		{name: "stale observe daemon", result: hook.Result{Decision: hook.DecisionAllow, Mode: "observe"}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := lifecycle.finalize(event, test.result)
			if result.Decision != hook.DecisionDeny || result.Mode != "enforce" {
				t.Fatalf("finalize() = %+v, want enforce fail-closed deny", result)
			}
		})
	}
}

func TestLifecycleEnforceUnavailableNonBlockingHookDoesNotDeny(t *testing.T) {
	t.Parallel()

	lifecycle := Lifecycle{Mode: "enforce"}
	result := lifecycle.daemonUnavailable(hook.Event{HookName: hook.HookPostToolUse})
	if result.Decision != hook.DecisionAllow || result.Mode != "enforce" {
		t.Fatalf("daemonUnavailable() = %+v, want enforce allow for non-blocking hook", result)
	}
}

func TestLifecycleNeverRejectsPromptSubmit(t *testing.T) {
	lifecycle := Lifecycle{Mode: "enforce"}
	event := hook.Event{HookName: hook.HookUserPromptSubmit}
	for name, result := range map[string]hook.Result{
		"unstamped daemon allow": {Decision: hook.DecisionAllow},
		"daemon deny":            {Decision: hook.DecisionDeny},
		"daemon unavailable":     lifecycle.daemonUnavailable(event),
	} {
		t.Run(name, func(t *testing.T) {
			final := lifecycle.finalize(event, result)
			if final.Decision != hook.DecisionAllow || final.Mode != "enforce" {
				t.Fatalf("prompt result = %+v, want enforce-stamped allow", final)
			}
		})
	}
}

func TestObserveResultFormatsBlockingPromptSubmit(t *testing.T) {
	result := guardhookruntime.ObserveResult(hook.Event{HookName: hook.HookUserPromptSubmit}, hook.Result{
		Decision: hook.DecisionDeny,
		Reason:   "prompt policy",
	})

	if result.Decision != hook.DecisionAllow || result.Mode != string(guardhookruntime.ModeObserve) {
		t.Fatalf("result = %+v, want observe allow", result)
	}
	if result.Reason != "Kontext observe mode: would deny; prompt policy" {
		t.Fatalf("reason = %q, want observe deny reason", result.Reason)
	}
}

func TestActiveRequiresValidManagedConfig(t *testing.T) {
	t.Setenv("KONTEXT_MANAGED_CONFIG", filepath.Join(t.TempDir(), "missing.json"))
	if Active() {
		t.Fatal("Active() = true for missing config")
	}

	path := filepath.Join(t.TempDir(), "managed.json")
	if err := os.WriteFile(path, []byte(`{
  "version": "managed-install-v1",
  "cloud_url": "https://app.kontext.dev",
  "mode": "observe",
  "agent": "claude",
  "credentials": {"install_token_ref": "env:KONTEXT_INSTALL_TOKEN"}
}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	t.Setenv("KONTEXT_MANAGED_CONFIG", path)
	if !Active() {
		t.Fatal("Active() = false for valid config")
	}
}

func TestLifecycleRemotePassesThroughEnforceStampedDecisions(t *testing.T) {
	t.Parallel()

	lifecycle := Lifecycle{Mode: "remote"}
	event := hook.Event{HookName: hook.HookPreToolUse}

	deny := lifecycle.finalize(event, hook.Result{Decision: hook.DecisionDeny, Mode: "enforce", Reason: "policy deny"})
	if deny.Decision != hook.DecisionDeny || deny.Mode != "enforce" {
		t.Fatalf("finalize(deny) = %+v, want authoritative deny passed through", deny)
	}

	allow := lifecycle.finalize(event, hook.Result{Decision: hook.DecisionAllow, Mode: "enforce"})
	if allow.Decision != hook.DecisionAllow || allow.Mode != "enforce" {
		t.Fatalf("finalize(allow) = %+v, want authoritative allow passed through", allow)
	}
}

func TestLifecycleRemoteDowngradesUnstampedDecisionsToObserve(t *testing.T) {
	t.Parallel()

	lifecycle := Lifecycle{Mode: "remote"}
	event := hook.Event{HookName: hook.HookPreToolUse}
	tests := []struct {
		name   string
		result hook.Result
	}{
		{name: "unstamped deny", result: hook.Result{Decision: hook.DecisionDeny, Reason: "would deny"}},
		{name: "observe stamped deny", result: hook.Result{Decision: hook.DecisionDeny, Mode: "observe", Reason: "would deny"}},
		{name: "enforce stamp without decision", result: hook.Result{Mode: "enforce"}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := lifecycle.finalize(event, test.result)
			if result.Decision != hook.DecisionAllow || result.Mode != string(guardhookruntime.ModeObserve) {
				t.Fatalf("finalize() = %+v, want observe allow", result)
			}
		})
	}
}

func TestLifecycleRemoteNormalizesEnforceStampOnNonBlockingHook(t *testing.T) {
	t.Parallel()

	lifecycle := Lifecycle{Mode: "remote"}
	result := lifecycle.finalize(hook.Event{HookName: hook.HookPostToolUse}, hook.Result{Decision: hook.DecisionDeny, Mode: "enforce"})
	if result.Decision != hook.DecisionAllow || result.Mode != "enforce" {
		t.Fatalf("finalize() = %+v, want allow for non-blocking hook", result)
	}
}

func TestLifecycleRemoteUnavailableFailsClosedWhileEnforcing(t *testing.T) {
	t.Parallel()

	lifecycle := Lifecycle{Mode: "remote", RemoteEnforce: func() bool { return true }}
	result := lifecycle.daemonUnavailable(hook.Event{HookName: hook.HookPreToolUse})
	if result.Decision != hook.DecisionDeny || result.Mode != "enforce" {
		t.Fatalf("daemonUnavailable() = %+v, want fail-closed deny while distribution claims enforce", result)
	}

	nonBlocking := lifecycle.daemonUnavailable(hook.Event{HookName: hook.HookPostToolUse})
	if nonBlocking.Decision != hook.DecisionAllow {
		t.Fatalf("daemonUnavailable(non-blocking) = %+v, want allow", nonBlocking)
	}
}

func TestLifecycleRemoteUnavailableFailsOpenWithoutEnforceClaim(t *testing.T) {
	t.Parallel()

	for name, lifecycle := range map[string]Lifecycle{
		"no enforce claim": {Mode: "remote", RemoteEnforce: func() bool { return false }},
		"no probe":         {Mode: "remote"},
	} {
		lifecycle := lifecycle
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := lifecycle.daemonUnavailable(hook.Event{HookName: hook.HookPreToolUse})
			if result.Decision != hook.DecisionAllow || result.Mode != string(guardhookruntime.ModeObserve) {
				t.Fatalf("daemonUnavailable() = %+v, want observe fail-open", result)
			}
		})
	}
}
