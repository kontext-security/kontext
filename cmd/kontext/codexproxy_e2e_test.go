package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/codexmanaged"
	"github.com/kontext-security/kontext/internal/codexroute"
)

// A real Codex whose config routes it to a Kontext proxy port nothing
// listens on, as once macOS stopped Kontext's background items, stops its
// session at the start hook, which takes the line away, instead of
// reconnecting for good. scripts/codex-proxy-e2e.sh runs it with a Codex
// binary and a kontext build; nothing calls a model or leaves the Mac.
func TestCodexOnADeadRouteStopsAtItsStart(t *testing.T) {
	codex, kontext := os.Getenv("KONTEXT_CODEX_E2E_BIN"), os.Getenv("KONTEXT_HOOK_E2E_BIN")
	if codex == "" || kontext == "" {
		t.Skip("set KONTEXT_CODEX_E2E_BIN and KONTEXT_HOOK_E2E_BIN to run Codex end to end (see scripts/codex-proxy-e2e.sh)")
	}
	root, err := os.MkdirTemp("/tmp", "kx-dead-route-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	home, workspace := filepath.Join(root, "home"), filepath.Join(root, "workspace")
	codexHome := filepath.Join(home, ".codex")
	for _, dir := range []string{codexHome, workspace} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	routed, err := codexmanaged.AddRoute("model = \"gpt-6.1-sol\"\ncli_auth_credentials_store = \"file\"\nweb_search = \"disabled\"\n\n[features]\nhooks = true\n",
		codexroute.BaseURL(port, strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(codexHome, "config.toml")
	hook := "'" + kontext + "' hook --agent codex --mode observe --socket '" + filepath.Join(root, "none.sock") + "' session-start"
	hooks, err := json.Marshal(map[string]any{"hooks": map[string]any{"SessionStart": []any{
		map[string]any{"hooks": []any{map[string]any{"type": "command", "command": hook, "timeout": 20}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(root, "sandbox.sb")
	for path, content := range map[string]string{
		configPath:                             routed,
		filepath.Join(codexHome, "auth.json"):  `{"auth_mode":"apikey","OPENAI_API_KEY":"sk-e2e-00000000000000000000"}`,
		filepath.Join(codexHome, "hooks.json"): string(hooks),
		profile: "(version 1)\n(allow default)\n(deny network-outbound)\n(allow network-outbound (remote ip \"localhost:*\"))\n" +
			"(allow network-outbound (remote unix-socket))\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sandbox-exec", "-f", profile, codex, "exec", "--dangerously-bypass-hook-trust",
		"--skip-git-repo-check", "--sandbox", "read-only", "--color", "never", "Reply with the single word: pong")
	cmd.Dir = workspace
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=" + home, "CODEX_HOME=" + codexHome, "NO_COLOR=1", "LANG=en_US.UTF-8"}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("Codex kept reconnecting to a port nothing answers on:\n%s", stderr.String())
	}
	if err != nil || !strings.Contains(stderr.String(), "hook: SessionStart Stopped") || strings.Contains(stderr.String(), "Reconnecting") {
		t.Fatalf("codex exec: %v\nstderr:\n%s", err, stderr.String())
	}
	if data, err := os.ReadFile(configPath); err != nil || codexmanaged.Route(string(data)) != "" {
		t.Fatalf("the line stayed (%v):\n%s", err, data)
	}
}
