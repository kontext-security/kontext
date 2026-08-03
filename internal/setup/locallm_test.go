package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Opting in has to reach the daemon, and the only channel is the agent's
// environment: launchd owns it and the daemon reads exactly this variable.
func TestLaunchAgentCarriesTheLocalLLMOptIn(t *testing.T) {
	plist := renderLaunchAgentPlist("/opt/homebrew/bin/kontext", "/tmp/agent.log", true)
	if !strings.Contains(plist, "<key>KONTEXT_JUDGE_MANAGED</key>") {
		t.Fatalf("opt-in missing from the agent environment:\n%s", plist)
	}
	if !strings.Contains(plist, "<string>1</string>") {
		t.Error("opt-in present but not enabled")
	}
}

// The default must change nothing. An endpoint that never asked for the model
// should be byte-identical to one installed before the option existed.
func TestLaunchAgentWithoutOptInIsUnchanged(t *testing.T) {
	plist := renderLaunchAgentPlist("/opt/homebrew/bin/kontext", "/tmp/agent.log", false)
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

	err := preflightLocalLLM()
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

	if err := preflightLocalLLM(); err != nil {
		t.Fatalf("preflight failed with llama-server present: %v", err)
	}
}
