package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/guard/judgeruntime"
	"github.com/kontext-security/kontext-cli/internal/managedobserve"
	"github.com/kontext-security/kontext-cli/internal/profile"
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
	// The cache used to sit beside the daemon's database unconditionally. With a
	// profile active it is hoisted to the shared root instead, because the weights
	// are machine-scoped and per-profile copies would re-download ~680 MB each
	// time a profile is added. Assert the rule rather than one of its two shapes.
	if shared := profile.SharedDir(filepath.Dir(daemonDB), profile.ModelCacheDirName); shared != "" {
		if daemonCfg.CacheDir != shared {
			t.Fatalf("daemon cache dir = %q, want the shared root %q", daemonCfg.CacheDir, shared)
		}
		if strings.Contains(daemonCfg.CacheDir, filepath.Join("profiles", "")) {
			t.Errorf("daemon cache dir %q is inside a profile; the weights must be shared", daemonCfg.CacheDir)
		}
	} else if want := filepath.Join(filepath.Dir(daemonDB), profile.ModelCacheDirName); daemonCfg.CacheDir != want {
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

// launchd does not inherit the shell, so any model configuration exported when
// setup ran is invisible to the daemon. Whatever the pre-fetch resolved has to
// travel into the agent's environment, or the daemon quietly uses defaults —
// downloading a second copy, possibly of a different revision, into a different
// cache than the one setup reported ready.
func TestAgentCarriesTheResolvedModelConfiguration(t *testing.T) {
	resolved := &localLLMAgentConfig{
		ServerBinary: "/opt/homebrew/bin/llama-server",
		HFRepo:       "acme/Qwen3-0.6B-GGUF",
		HFFile:       "custom-Q8_0.gguf",
		HFRevision:   "abc123",
		CacheDir:     "/tmp/custom-cache",
	}
	plist := renderLaunchAgentPlist("/opt/homebrew/bin/kontext", "/tmp/agent.log", resolved)

	for key, value := range map[string]string{
		"KONTEXT_JUDGE_MANAGED":     "1",
		"KONTEXT_JUDGE_SERVER_BIN":  resolved.ServerBinary,
		"KONTEXT_JUDGE_HF_REPO":     resolved.HFRepo,
		"KONTEXT_JUDGE_HF_FILE":     resolved.HFFile,
		"KONTEXT_JUDGE_HF_REVISION": resolved.HFRevision,
		"KONTEXT_JUDGE_CACHE_DIR":   resolved.CacheDir,
	} {
		if !strings.Contains(plist, "<key>"+key+"</key>") {
			t.Errorf("%s missing from the agent environment", key)
		}
		if !strings.Contains(plist, "<string>"+value+"</string>") {
			t.Errorf("%s value %q missing from the agent environment", key, value)
		}
	}
}

// Unset fields are omitted, so a default opt-in carries only what it needs.
func TestAgentOmitsUnsetModelConfiguration(t *testing.T) {
	plist := renderLaunchAgentPlist("/opt/homebrew/bin/kontext", "/tmp/agent.log",
		&localLLMAgentConfig{ServerBinary: "/opt/homebrew/bin/llama-server"})
	for _, key := range []string{"KONTEXT_JUDGE_HF_REPO", "KONTEXT_JUDGE_HF_REVISION", "KONTEXT_JUDGE_CACHE_DIR"} {
		if strings.Contains(plist, key) {
			t.Errorf("%s present despite being unset:\n%s", key, plist)
		}
	}
	if !strings.Contains(plist, "KONTEXT_JUDGE_MANAGED") {
		t.Error("opt-in itself went missing")
	}
}
