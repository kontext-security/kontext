package run

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type claudeSettings struct {
	Hooks map[string][]hookGroup `json:"hooks"`
}

type hookGroup struct {
	Matcher string    `json:"matcher,omitempty"`
	Hooks   []hookDef `json:"hooks"`
}

type hookDef struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Timeout int    `json:"timeout,omitempty"`
}

func commandHookGroups(command string) []hookGroup {
	return []hookGroup{{
		Matcher: "*",
		Hooks: []hookDef{{
			Type:    "command",
			Command: command,
			Timeout: 10,
		}},
	}}
}

// GenerateSettings creates a Claude Code settings.json with Kontext hooks
// and returns the path to the generated file.
func GenerateSettings(sessionDir, kontextBinary, agentName string) (string, error) {
	hookCmd := fmt.Sprintf("%s hook --agent %s", kontextBinary, agentName)
	return writeClaudeSettings(sessionDir, hookCmd)
}

// GenerateLocalSettings creates a Claude Code settings.json that connects
// hooks to the wrapper-owned local runtime socket.
func GenerateLocalSettings(sessionDir, kontextBinary, agentName, socketPath, mode string) (string, error) {
	hookCmd := fmt.Sprintf(
		"%s hook --agent %s --mode %s --socket %s",
		shellQuote(kontextBinary),
		shellQuote(agentName),
		shellQuote(mode),
		shellQuote(socketPath),
	)
	return writeClaudeSettings(sessionDir, hookCmd)
}

func writeClaudeSettings(sessionDir, hookCmd string) (string, error) {
	settings := claudeSettings{
		Hooks: map[string][]hookGroup{
			"PreToolUse":  commandHookGroups(hookCmd),
			"PostToolUse": commandHookGroups(hookCmd),
			// UserPromptSubmit supplies the agent task recorded alongside
			// observe-mode risk-classifier verdicts.
			"UserPromptSubmit": commandHookGroups(hookCmd),
		},
	}

	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal settings: %w", err)
	}

	settingsPath := filepath.Join(sessionDir, "settings.json")
	if err := os.WriteFile(settingsPath, data, 0600); err != nil {
		return "", fmt.Errorf("write settings: %w", err)
	}

	return settingsPath, nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func VerifyBlockingHookSettings(settingsPath, kontextBinary, agentName string) error {
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		return fmt.Errorf("read settings: %w", err)
	}

	var settings claudeSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		return fmt.Errorf("parse settings: %w", err)
	}

	wantCommand := fmt.Sprintf("%s hook --agent %s", kontextBinary, agentName)
	for _, group := range settings.Hooks["PreToolUse"] {
		for _, hook := range group.Hooks {
			if hook.Type == "command" && hook.Command == wantCommand && hook.Timeout > 0 {
				return nil
			}
		}
	}

	return fmt.Errorf("PreToolUse command hook missing for %s", strings.TrimSpace(wantCommand))
}
