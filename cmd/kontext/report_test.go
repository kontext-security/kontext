package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/agentinventory"
	"github.com/kontext-security/kontext/internal/managedstream"
	"github.com/kontext-security/kontext/pkg/agentauthority"
)

func TestReportJSONFixtureProfile(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	t.Setenv("KONTEXT_MANAGED_STREAM_STATE", statePath)
	data, err := os.ReadFile("../../pkg/agentauthority/testdata/contract/authority-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var authority agentauthority.Report
	if err := json.Unmarshal(data, &authority); err != nil {
		t.Fatal(err)
	}
	// The latest Cowork session ran on the host.
	sandboxed := false
	agents := []agentinventory.Agent{
		{ID: "claude_code", ConfigPath: "~/.claude", Wired: agentinventory.WiredYes},
		{ID: "claude_cowork", ConfigPath: "~/Library/Application Support/Claude/local-agent-mode-sessions", Wired: agentinventory.WiredYes, Sandboxed: &sandboxed},
	}
	report := managedstream.Report{Agents: &agents, AgentsReportedAt: "2026-09-16T12:00:00Z", Authority: &authority}
	if err := managedstream.SaveState(statePath, managedstream.State{LastReport: report}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	cmd := reportCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile("testdata/report.json", out.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile("testdata/report.json")
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != string(want) {
		t.Fatalf("report snapshot mismatch:\n%s", out.String())
	}
	// Reading report is offline and must not rewrite the persisted send state.
	before, _ := os.ReadFile(statePath)
	out.Reset()
	plain := reportCmd()
	plain.SetOut(&out)
	plain.SetArgs(nil)
	if err := plain.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "Claude Code:") != 1 {
		t.Fatal("agent appears more than once")
	}
	after, _ := os.ReadFile(statePath)
	if !bytes.Equal(before, after) {
		t.Fatal("report changed stream state")
	}
	for _, text := range []string{"Claude Code:", "Environment:", "Ambient credentials:", "values never read", "Coverage:", "1 MCP server, 1 plugin, prompts bypassed", "gh (github.com, sam-example)", "codex: config.toml parse error", "limits [claude_code: projects limited to 32]"} {
		if !bytes.Contains(out.Bytes(), []byte(text)) {
			t.Fatalf("missing %s", text)
		}
	}
}
