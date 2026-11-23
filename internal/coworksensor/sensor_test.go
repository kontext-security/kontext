package coworksensor

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/localruntime"
	"github.com/kontext-security/kontext/internal/managedstream"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	// Keep the Unix socket below macOS's path length limit.
	dir, err := os.MkdirTemp("/tmp", "edr-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cfg := Config{CloudURL: "https://example.test", TokenFile: filepath.Join(dir, "token"), InstallationID: "ins_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", StateDir: filepath.Join(dir, "state"), RuntimeDir: filepath.Join(dir, "run"), Interval: 20 * time.Millisecond}
	if err := os.WriteFile(cfg.TokenFile, []byte("test-install-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestConfigRejectsUnsafeFilesAndOrigins(t *testing.T) {
	cfg := testConfig(t)
	path := filepath.Join(filepath.Dir(cfg.TokenFile), "config.json")
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("accepted public configuration")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link); err == nil {
		t.Fatal("accepted symlink")
	}
	for _, origin := range []string{"http://example.test", "https://user:secret@example.test", "https://example.test/private", "https://example.test?token=secret"} {
		cfg.CloudURL = origin
		cfg.AllowHTTPLoopback = true
		if cfg.validate() == nil {
			t.Errorf("accepted unsafe origin %q", origin)
		}
	}
}

func TestHookScopeRejectsOtherServicesAndStripsFileReads(t *testing.T) {
	for _, kind := range []string{localruntime.CompactRequestType, localruntime.CodexProxyRequestType, localruntime.BrowserRequestType, "unknown"} {
		if FilterRequest(&localruntime.EvaluateRequest{Type: kind}) == nil {
			t.Errorf("accepted %s", kind)
		}
	}
	for _, event := range []string{"UserPromptSubmit", "Stop", "Notification", ""} {
		if FilterRequest(&localruntime.EvaluateRequest{Type: "evaluate", SessionID: "test", HookEvent: event}) == nil {
			t.Errorf("accepted %s", event)
		}
	}
	req := localruntime.EvaluateRequest{Type: "evaluate", SessionID: "cowork-test", HookEvent: "PreToolUse", Agent: "codex", TranscriptPath: "/private/data", AgentTranscriptPath: "/private/other", UserRequest: "private prompt", ToolSchemas: json.RawMessage(`{}`), CodexProxy: json.RawMessage(`{}`), Browser: json.RawMessage(`{}`)}
	if err := FilterRequest(&req); err != nil {
		t.Fatal(err)
	}
	if req.Agent != "cowork" || req.TranscriptPath != "" || req.AgentTranscriptPath != "" || req.UserRequest != "" || req.ToolSchemas != nil || req.CodexProxy != nil || req.Browser != nil {
		t.Fatalf("unsafe fields survived: %+v", req)
	}
}

func TestSensorAuthenticatesAndReportsOnlyObserveHooks(t *testing.T) {
	cfg := testConfig(t)
	payloads := make(chan managedstream.Payload, 100)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != managedstream.DefaultEndpoint || r.Header.Get("Authorization") != "Bearer test-install-token" {
			t.Errorf("unexpected endpoint or authentication: %s", r.URL.Path)
			w.WriteHeader(401)
			return
		}
		var p managedstream.Payload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Error(err)
		}
		select {
		case payloads <- p:
		default:
			t.Error("unexpected request volume")
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"quarantined":[],"altered":[],"mode":"enforce","compaction_enabled":true}`)
	}))
	defer server.Close()
	cfg.CloudURL = server.URL
	cfg.AllowHTTPLoopback = true
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, "test", io.Discard) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("shutdown: %v", err)
		}
	}()
	select {
	case <-payloads:
	case <-ctx.Done():
		t.Fatal("startup did not authenticate")
	}
	client := localruntime.NewClient(filepath.Join(cfg.RuntimeDir, "sensor.sock"))
	for _, name := range []hook.HookName{hook.HookSessionStart, hook.HookPreToolUse, hook.HookPostToolUse, hook.HookSessionEnd} {
		result, err := client.Process(ctx, hook.Event{SessionID: "cowork-smoke", Agent: "cowork", HookName: name, ToolName: "Bash", ToolUseID: "harmless-tool", ToolInput: map[string]any{"command": "ls /tmp/empty-cowork-fixture"}})
		if err != nil {
			t.Fatal(err)
		}
		if result.Decision != hook.DecisionAllow || result.CompactToolOutput || result.UpdatedInput != nil {
			t.Fatalf("sensor changed execution: %+v", result)
		}
	}
	// The cross-user socket must not offer compaction or proxy functionality.
	conn, err := net.Dial("unix", client.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := localruntime.WriteMessage(conn, localruntime.EvaluateRequest{Type: localruntime.CodexProxyRequestType}); err != nil {
		t.Fatal(err)
	}
	var denied localruntime.EvaluateResult
	if err := localruntime.ReadMessage(conn, &denied); err != nil {
		t.Fatal(err)
	}
	if !denied.Allowed || denied.Mode != "observe" || denied.CompactToolOutput {
		t.Fatalf("unsafe unsupported response: %+v", denied)
	}
	for {
		select {
		case p := <-payloads:
			if len(p.Actions) == 0 {
				continue
			}
			data, _ := json.Marshal(p)
			if !strings.Contains(string(data), "cowork-smoke") || !strings.Contains(string(data), "harmless-tool") {
				continue
			}
			if len(p.Turns) != 0 || len(p.ToolUsage) != 0 || strings.Contains(string(data), "test-install-token") {
				t.Fatal("uploaded out-of-scope content")
			}
			info, err := os.Stat(client.SocketPath)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0666 {
				t.Fatalf("socket mode=%o", info.Mode().Perm())
			}
			return
		case <-ctx.Done():
			t.Fatal("tool call never reached ledger uploader")
		}
	}
}

func TestRejectedCredentialNeverBecomesReady(t *testing.T) {
	cfg := testConfig(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	defer server.Close()
	cfg.CloudURL = server.URL
	cfg.AllowHTTPLoopback = true
	err := run(context.Background(), cfg, "test", io.Discard)
	if err == nil {
		t.Fatal("accepted revoked credential")
	}
	if _, err := os.Stat(filepath.Join(cfg.RuntimeDir, "ready.json")); !os.IsNotExist(err) {
		t.Fatal("failed sensor reported ready")
	}
}
