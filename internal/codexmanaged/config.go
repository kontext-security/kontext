package codexmanaged

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kontext-security/kontext/internal/agenthooks"
)

// Codex gates its hook engine behind a feature flag that is off by default:
// hooks in ~/.codex/hooks.json never fire until `[features].hooks = true` is
// set in ~/.codex/config.toml (`codex_hooks` is the deprecated alias). Setup
// installs the hooks, so it also flips this flag on — otherwise we would
// install hooks that silently never run.

// ErrFeaturesNotEditable is returned when config.toml carries `features` in a
// form we will not edit by hand (an inline table or dotted top-level key),
// rather than risk corrupting the user's file. Callers should treat it as a
// warning and tell the user to set the flag themselves.
var ErrFeaturesNotEditable = errors.New("codex config.toml uses a [features] form that cannot be edited automatically")

var (
	tomlTableRe          = regexp.MustCompile(`^\s*\[([^\[\]]+)\]\s*(#.*)?$`)
	tomlInlineFeaturesRe = regexp.MustCompile(`^\s*features\s*=`)
)

// UserConfigPath returns ~/.codex/config.toml, creating ~/.codex.
func UserConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	codexDir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(codexDir, "config.toml"), nil
}

// UserConfigPathNoCreate returns ~/.codex/config.toml without creating ~/.codex.
func UserConfigPathNoCreate() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".codex", "config.toml"), nil
}

// EnsureHooksEnabled turns on `[features].hooks` in the config.toml at path,
// preserving the rest of the file. It is idempotent: already-enabled configs
// (including the `codex_hooks` alias) are left untouched and report changed
// false. A missing file is created. The existing file is backed up before it
// is rewritten.
func EnsureHooksEnabled(path, backupLabel string) (changed bool, err error) {
	raw, err := os.ReadFile(path)
	missing := errors.Is(err, fs.ErrNotExist)
	if err != nil && !missing {
		return false, err
	}
	content := ""
	if !missing {
		content = string(raw)
	}

	if hooksFeatureEnabled(content) {
		return false, nil
	}

	next, err := enableHooksFeature(content)
	if err != nil {
		return false, err
	}
	if next == content {
		return false, nil
	}

	if !missing {
		if err := agenthooks.BackupFile(path, backupLabel); err != nil {
			return false, err
		}
	}
	if err := agenthooks.WriteRawFile(path, []byte(next)); err != nil {
		return false, err
	}
	return true, nil
}

// HooksEnabled reports whether the Codex hook engine is enabled at path. It is
// read-only so callers such as doctor never create or rewrite config.toml.
func HooksEnabled(path string) (bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	return hooksFeatureEnabled(string(raw)), nil
}

// hooksFeatureEnabled reports whether config.toml already turns the Codex hook
// engine on, via either the canonical `hooks` key or the deprecated
// `codex_hooks` alias, in `[features]` table or top-level dotted form.
func hooksFeatureEnabled(content string) bool {
	table := ""
	for _, line := range strings.Split(content, "\n") {
		if m := tomlTableRe.FindStringSubmatch(line); m != nil {
			table = strings.TrimSpace(m[1])
			continue
		}
		key, value, ok := parseTOMLAssignment(line)
		if !ok {
			continue
		}
		switch table {
		case "features":
			if (key == "hooks" || key == "codex_hooks") && value == "true" {
				return true
			}
		case "":
			if (key == "features.hooks" || key == "features.codex_hooks") && value == "true" {
				return true
			}
		}
	}
	return false
}

// enableHooksFeature returns content with `[features].hooks = true` ensured.
// It inserts or flips the key inside an existing `[features]` table, or appends
// a new table when none exists. It refuses (ErrFeaturesNotEditable) when
// `features` appears as a top-level dotted key or inline table, where a blind
// append would produce a duplicate-key TOML error.
func enableHooksFeature(content string) (string, error) {
	lines := strings.Split(content, "\n")

	headerIdx := -1
	for i, line := range lines {
		if m := tomlTableRe.FindStringSubmatch(line); m != nil && strings.TrimSpace(m[1]) == "features" {
			headerIdx = i
			break
		}
	}

	if headerIdx == -1 {
		for _, line := range lines {
			if tomlInlineFeaturesRe.MatchString(line) {
				return "", ErrFeaturesNotEditable
			}
			if key, _, ok := parseTOMLAssignment(line); ok && strings.HasPrefix(key, "features.") {
				return "", ErrFeaturesNotEditable
			}
		}
		return appendFeaturesTable(content), nil
	}

	// Walk the table body (until the next table header) for an existing hooks key.
	for j := headerIdx + 1; j < len(lines); j++ {
		if tomlTableRe.MatchString(lines[j]) {
			break
		}
		key, value, ok := parseTOMLAssignment(lines[j])
		if !ok || key != "hooks" {
			continue
		}
		if value == "true" {
			return content, nil
		}
		lines[j] = leadingWhitespace(lines[j]) + "hooks = true"
		return strings.Join(lines, "\n"), nil
	}

	inserted := make([]string, 0, len(lines)+1)
	inserted = append(inserted, lines[:headerIdx+1]...)
	inserted = append(inserted, "hooks = true")
	inserted = append(inserted, lines[headerIdx+1:]...)
	return strings.Join(inserted, "\n"), nil
}

func appendFeaturesTable(content string) string {
	block := "[features]\nhooks = true\n"
	if strings.TrimSpace(content) == "" {
		return block
	}
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + "\n" + block
}

// parseTOMLAssignment extracts a key and the leading token of its value from a
// `key = value` line. It ignores comments and blank lines. Quoted keys are
// unquoted; string values are returned verbatim up to the first space or
// comment, which is enough to recognize a boolean `true`.
func parseTOMLAssignment(line string) (key, value string, ok bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "[") {
		return "", "", false
	}
	eq := strings.IndexByte(trimmed, '=')
	if eq < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(trimmed[:eq])
	key = strings.Trim(key, `"'`)
	if key == "" {
		return "", "", false
	}
	rawValue := strings.TrimSpace(trimmed[eq+1:])
	value = rawValue
	if cut := strings.IndexAny(rawValue, " \t#"); cut >= 0 {
		value = rawValue[:cut]
	}
	return key, value, true
}

func leadingWhitespace(line string) string {
	return line[:len(line)-len(strings.TrimLeft(line, " \t"))]
}
