package hookinstall

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kontext-security/kontext/internal/claudemanaged"
)

// diagnoseClaudeUser checks the user copy against what installation writes:
// the current template, repeating each handler machine-wide settings declare.
// A handler that differs from a machine-wide one runs twice.
func diagnoseClaudeUser(out io.Writer, path, binary string, machine [][]byte) bool {
	raw, err := os.ReadFile(path)
	if err == nil && !claudemanaged.UserHooksMatch(raw, binary, machine...) {
		err = errors.New("Kontext handlers differ from the machine-wide settings or the current template; differing handlers can execute twice")
	}
	if err != nil {
		fmt.Fprintf(out, "Claude Code user hooks: %v (%s). Run `kontext hooks install --scope user`.\n", err, path)
		return false
	}
	return true
}

// mirroredClaudeBinary accepts a user copy whose handlers name several
// binaries when it is exactly what installation writes for the machine-wide
// sources.
func mirroredClaudeBinary(raw []byte, machine [][]byte) (string, bool) {
	if claudemanaged.DisablesAllHooks(raw) {
		return "", false
	}
	for _, binary := range claudemanaged.KontextBinaries(raw) {
		if executable(binary) && claudemanaged.UserHooksMatch(raw, binary, machine...) {
			return binary, true
		}
	}
	return "", false
}

// diagnoseClaudeSources is deliberately an offline configuration check. A cache
// can belong to a different account/provider and does not establish which policy
// an interactive Claude session selected. Never fetch policy or run a session
// (and its SessionStart hooks) from doctor.
func diagnoseClaudeSources(out io.Writer, dropin, userPath string) bool {
	healthy := true
	root := filepath.Dir(filepath.Dir(dropin))
	paths := []string{filepath.Join(root, "managed-settings.json")}
	entries, err := os.ReadDir(filepath.Dir(dropin))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(out, "Claude Code managed hook sources: unreadable (%v)\n", err)
		healthy = false
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".") && strings.HasSuffix(entry.Name(), ".json") {
			paths = append(paths, filepath.Join(filepath.Dir(dropin), entry.Name()))
		}
	}
	disabledAt, managedOnlyAt := "", ""
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		var settings map[string]any
		if err == nil && len(bytes.TrimSpace(raw)) == 0 {
			settings = map[string]any{}
		} else if err == nil {
			err = json.Unmarshal(raw, &settings)
			if err == nil && settings == nil {
				err = errors.New("settings must be a JSON object")
			}
		}
		if err != nil {
			fmt.Fprintf(out, "Claude Code managed hook source: invalid or unreadable (%s; %v)\n", path, err)
			healthy = false
			continue
		}
		// File-based settings merge in filename order; a later false clears a
		// previous true. Do not mistake any occurrence of true for the result.
		for key, location := range map[string]*string{"disableAllHooks": &disabledAt, "allowManagedHooksOnly": &managedOnlyAt} {
			if value, exists := settings[key]; exists && value == nil {
				*location = ""
			}
			if value, ok := settings[key].(bool); ok {
				*location = ""
				if value {
					*location = path
				}
			} else if value, exists := settings[key]; exists && value != nil {
				fmt.Fprintf(out, "Claude Code managed hook source: %s must be a Boolean (%s); check `claude doctor` for Claude's validation result\n", key, path)
				healthy = false
			}
		}
	}
	if disabledAt != "" {
		fmt.Fprintf(out, "Claude Code managed hook configuration: disableAllHooks=true (%s); hooks cannot run when this managed source is selected\n", disabledAt)
		healthy = false
	}
	if managedOnlyAt != "" {
		fmt.Fprintf(out, "Claude Code user hook fallback: restricted by allowManagedHooksOnly=true (%s) when this managed source is selected\n", managedOnlyAt)
	}
	cache := filepath.Join(filepath.Dir(userPath), "remote-settings.json")
	if _, err := os.Lstat(cache); err == nil {
		fmt.Fprintf(out, "Claude Code remote managed settings: cache found (%s); if active, remote policy can skip local drop-ins or restrict user hooks. Confirm Setting sources and Skipped sources in Claude `/status`; cache presence alone does not prove an active policy. If `/status` skips the drop-ins and the remote policy sets allowManagedHooksOnly, an organization Owner can add \"managedSourcesBehavior\": \"merge\" to the claude.ai managed settings so the Kontext drop-in loads with it.\n", cache)
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(out, "Claude Code remote managed settings: cache unavailable (%v); policy selection unverified\n", err)
	}
	fmt.Fprintln(out, "Claude Code hook activation: unverified (installed files do not confirm execution; start a fresh session, check `/status` and `/hooks`, then confirm a tool event in Kontext)")
	return healthy
}
