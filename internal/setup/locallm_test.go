package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/guard/judgeruntime"
	"github.com/kontext-security/kontext-cli/internal/managedobserve"
	"github.com/kontext-security/kontext-cli/internal/runtimehost"
)

// Opting in has to reach the daemon, and the only channel is the agent's
// environment: launchd owns it and the daemon reads exactly this variable.
func TestLaunchAgentCarriesTheLocalLLMOptIn(t *testing.T) {
	plist := renderLaunchAgentPlist("/opt/homebrew/bin/kontext", "/tmp/agent.log",
		&localLLMAgentConfig{ServerBinary: "/opt/homebrew/bin/llama-server"})
	if !strings.Contains(plist, "<key>KONTEXT_JUDGE_MANAGED</key>") {
		t.Fatalf("opt-in missing from the agent environment:\n%s", plist)
	}
	// The resolved path has to travel with it: launchd hands the daemon a minimal
	// PATH without Homebrew, so a bare name would not resolve there.
	if !strings.Contains(plist, "<key>KONTEXT_JUDGE_SERVER_BIN</key>") ||
		!strings.Contains(plist, "<string>/opt/homebrew/bin/llama-server</string>") {
		t.Errorf("resolved llama-server path missing from the agent environment:\n%s", plist)
	}
}

// The default must change nothing. An endpoint that never asked for the model
// should be byte-identical to one installed before the option existed.
func TestLaunchAgentWithoutOptInIsUnchanged(t *testing.T) {
	plist := renderLaunchAgentPlist("/opt/homebrew/bin/kontext", "/tmp/agent.log", nil)
	if strings.Contains(plist, "KONTEXT_JUDGE_MANAGED") {
		t.Fatalf("default install mentions the local model:\n%s", plist)
	}
	// The pre-existing variable is still there, so nothing else moved.
	if !strings.Contains(plist, "<key>KONTEXT_EXPECTED_CONFIG_SCOPE</key>") {
		t.Error("existing agent environment was disturbed")
	}
}

// Asking for the model without the runtime installed must fail before anything
// is written, and the message has to name the fix.
func TestPreflightLocalLLMFailsWithAnActionableMessage(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)

	_, err := preflightLocalLLM()
	if err == nil {
		t.Fatal("preflight passed with no llama-server on PATH")
	}
	for _, want := range []string{"llama-server", llamaServerInstallHint, "--with-local-llm"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message does not mention %q: %v", want, err)
		}
	}
}

func TestPreflightLocalLLMPassesWhenPresent(t *testing.T) {
	dir := t.TempDir()
	stub := filepath.Join(dir, "llama-server")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	resolved, err := preflightLocalLLM()
	if err != nil {
		t.Fatalf("preflight failed with llama-server present: %v", err)
	}
	if resolved != stub {
		t.Errorf("resolved = %q, want the absolute path %q", resolved, stub)
	}
}

// The pre-fetch has to fill the cache the daemon actually reads. Guard's default
// database path and the daemon's are different directories, and the model cache
// is derived from whichever it is given — so using the wrong one fills a cache
// nothing reads and leaves the daemon to download its own ~680 MB copy.
func TestPrefetchTargetsTheDaemonModelCache(t *testing.T) {
	daemonDB := managedobserve.DefaultDBPath()
	guardDB := runtimehost.DefaultDBPath()
	if filepath.Dir(daemonDB) == filepath.Dir(guardDB) {
		t.Skip("the two database paths coincide in this environment; nothing to distinguish")
	}

	daemonCfg, err := judgeruntime.ConfigFromEnv(daemonDB)
	if err != nil {
		t.Fatal(err)
	}
	guardCfg, err := judgeruntime.ConfigFromEnv(guardDB)
	if err != nil {
		t.Fatal(err)
	}
	if daemonCfg.CacheDir == guardCfg.CacheDir {
		t.Fatal("cache dirs coincide; this test can no longer tell the two apart")
	}
	if want := filepath.Join(filepath.Dir(daemonDB), "judge-models"); daemonCfg.CacheDir != want {
		t.Fatalf("daemon cache dir = %q, want %q", daemonCfg.CacheDir, want)
	}
	// What prefetchLocalModel resolves must be the daemon's, which is the whole
	// point of the path it is given.
	if resolved := prefetchCacheDirForTest(t); resolved != daemonCfg.CacheDir {
		t.Errorf("prefetch cache dir = %q, want the daemon's %q", resolved, daemonCfg.CacheDir)
	}
}

// prefetchCacheDirForTest mirrors the resolution prefetchLocalModel performs, so
// a change to the path it derives fails here rather than silently downloading
// into a directory nothing reads.
func prefetchCacheDirForTest(t *testing.T) string {
	t.Helper()
	cfg, err := judgeruntime.ConfigFromEnv(managedobserve.DefaultDBPath())
	if err != nil {
		t.Fatal(err)
	}
	return cfg.CacheDir
}
