// Package hookinstall owns the hook set shared by setup, packages, and doctor.
package hookinstall

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/kontext-security/kontext/internal/agenthooks"
	"github.com/kontext-security/kontext/internal/claudemanaged"
	"github.com/kontext-security/kontext/internal/codexmanaged"
)

type Scope string

const (
	User   Scope = "user"
	System Scope = "system"
)
const SystemConfigPath = "/etc/codex/config.toml"
const BackupLabel = "kontext-setup"
const featureMarker = " # kontext-hooks-original:"

type File struct {
	Kind, Path string
	Scope      Scope
}
type Definition struct {
	Agent, Name string
	Files       []File
	Validate    func([]byte) (string, error)
}

// Definitions is the only list of installations. Claude uses its managed
// system drop-in even for self-serve; Codex follows the requested scope.
func Definitions(scope Scope, home string) ([]Definition, error) {
	return definitions(scope, home, os.Getenv("CODEX_HOME"))
}

func definitions(scope Scope, home, codexHome string) ([]Definition, error) {
	if scope != User && scope != System {
		return nil, fmt.Errorf("invalid scope %q: want user or system", scope)
	}
	codexDir := filepath.Dir(SystemConfigPath)
	if scope == User {
		if !filepath.IsAbs(home) {
			return nil, errors.New("cannot resolve an absolute home directory")
		}
		codexDir = filepath.Join(home, ".codex")
		if codexHome != "" {
			codexDir = codexHome
		}
		if !filepath.IsAbs(codexDir) {
			return nil, errors.New("CODEX_HOME must be an absolute path")
		}
	}
	return []Definition{
		{Agent: "claude_code", Name: "Claude Code", Files: []File{{"claude", claudemanaged.ManagedSettingsDropInPath, System}}, Validate: validateClaude},
		{Agent: "codex", Name: "Codex", Files: []File{{"codex", filepath.Join(codexDir, "hooks.json"), scope}, {"feature", filepath.Join(codexDir, "config.toml"), scope}}, Validate: codexmanaged.ValidateInstalled},
	}, nil
}

func validateClaude(data []byte) (string, error) {
	binary, ok := claudemanaged.ManagedObserveHookBinary(data)
	if !ok {
		return "", errors.New("incomplete or disabled")
	}
	return binary, claudemanaged.Validate(data, binary)
}

type Result struct {
	File           File
	Action, Reason string
	Err            error
}
type Options struct {
	Scope        Scope
	Home, Binary string
	DryRun       bool
	Out          io.Writer
	// Setup keeps its existing messages, nonfatal feature warning, and uninstall
	// behavior. The command uses strict errors and removes its own feature flag.
	Setup        bool
	KeepClaude   bool
	ClaudePath   string
	WriteClaude  func(string, []byte) error
	RemoveClaude func(string) error
	Report       func(Result)
	// AfterClaude preserves self-serve legacy cleanup between the two agents.
	AfterClaude func() error
}

type change struct {
	result        Result
	before, after []byte
	missing       bool
}

func Install(opts Options) error { return run(opts, false) }
func Remove(opts Options) error  { return run(opts, true) }

func run(opts Options, remove bool) error {
	codexHome := os.Getenv("CODEX_HOME")
	// Setup historically writes ~/.codex regardless of CODEX_HOME. Preserve
	// existing self-serve paths while the explicit commands follow Codex.
	if opts.Setup {
		codexHome = ""
	}
	defs, err := definitions(opts.Scope, opts.Home, codexHome)
	if err != nil {
		return err
	}
	return runDefinitions(opts, defs, remove)
}

func runDefinitions(opts Options, defs []Definition, remove bool) error {
	if !remove && (!filepath.IsAbs(opts.Binary) || filepath.Base(opts.Binary) != "kontext" || strings.ContainsAny(opts.Binary, "\n\r\x00")) {
		return errors.New("binary must be an absolute path to a kontext executable")
	}
	if !remove && !opts.DryRun && !opts.Setup && !executable(opts.Binary) {
		return fmt.Errorf("hook binary is not executable: %s", opts.Binary)
	}
	var changes []change
	for _, def := range defs {
		for _, file := range def.Files {
			if file.Kind == "claude" && opts.ClaudePath != "" {
				file.Path = opts.ClaudePath
			}
			c, err := plan(file, opts, remove)
			c.result.File = file
			if err != nil {
				c.result.Action = "error"
				c.result.Err = err
				if !opts.Setup || !(file.Kind == "feature" || remove && file.Kind == "codex") {
					return fmt.Errorf("%s: %w", file.Path, err)
				}
			}
			changes = append(changes, c)
		}
	}
	// Plan every file before writing, so a foreign Claude drop-in or malformed
	// Codex config cannot leave a partially installed hook set.
	for _, c := range changes {
		r := c.result
		if r.Err == nil && r.Action != "skip" && !opts.DryRun {
			if err := apply(c, opts); err != nil {
				r.Err = err
				r.Action = "error"
				if !opts.Setup || !(r.File.Kind == "feature" || remove && r.File.Kind == "codex") {
					return err
				}
			}
		}
		if opts.Report != nil {
			opts.Report(r)
		}
		if r.File.Kind == "claude" && opts.AfterClaude != nil && !opts.DryRun {
			if err := opts.AfterClaude(); err != nil {
				return err
			}
		}
		if opts.Out != nil {
			action := r.Action
			if opts.DryRun && action != "skip" {
				action = "would-" + action
			}
			fmt.Fprintf(opts.Out, "%s\t%s\t%s\t%s\n", action, r.File.Scope, r.File.Path, r.Reason)
		}
	}
	return nil
}

func plan(file File, opts Options, remove bool) (change, error) {
	c := change{result: Result{File: file, Action: "skip", Reason: "unchanged"}}
	if remove && (file.Kind == "claude" && opts.KeepClaude || file.Kind == "feature" && opts.Setup) {
		c.result.Reason = "kept"
		return c, nil
	}
	info, err := os.Lstat(file.Path)
	if err == nil && file.Scope == System && !info.Mode().IsRegular() {
		return c, errors.New("refusing non-regular system file")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return c, err
	}
	c.before, err = os.ReadFile(file.Path)
	c.missing = errors.Is(err, os.ErrNotExist)
	if err != nil && !c.missing {
		return c, err
	}
	err = nil
	if remove && c.missing {
		c.result.Reason = "absent"
		return c, nil
	}
	switch file.Kind {
	case "claude":
		if !c.missing && !claudemanaged.IsManagedSettingsDropIn(c.before) {
			if remove {
				c.result.Reason = "foreign"
				return c, nil
			}
			return c, errors.New("Claude Code managed hooks ownership is unknown; refusing to overwrite")
		}
		if !remove {
			c.after, err = claudemanaged.TemplateJSON(opts.Binary)
		}
	case "codex":
		settings := map[string]any{}
		if !c.missing {
			err = json.Unmarshal(c.before, &settings)
		}
		if err != nil {
			return c, err
		}
		if settings == nil {
			return c, errors.New("hooks must be a JSON object")
		}
		before, _ := json.Marshal(settings)
		if remove {
			err = codexmanaged.RemoveManagedHooks(settings)
		} else {
			err = codexmanaged.MergeManagedHooks(settings, opts.Binary)
		}
		if err != nil {
			return c, err
		}
		after, _ := json.Marshal(settings)
		if bytes.Equal(before, after) && !opts.Setup {
			return c, nil
		}
		c.after, err = json.MarshalIndent(settings, "", "  ")
		c.after = append(c.after, '\n')
		// Only delete an empty file when all of its content was our hooks.
		if remove && !opts.Setup && len(settings) == 0 {
			c.after = nil
		}
	case "feature":
		if remove {
			c.after, err = removeFeature(c.before)
		} else {
			var next string
			next, err = codexmanaged.EnableHooksFeature(string(c.before))
			c.after = []byte(next)
			if err == nil && !opts.Setup && !bytes.Equal(c.before, c.after) {
				c.after = markFeature(c.before, c.after)
			}
		}
	}
	if err != nil {
		return c, err
	}
	if bytes.Equal(c.before, c.after) && !(remove && opts.Setup && file.Kind == "codex") {
		return c, nil
	}
	c.result.Action = "write"
	c.result.Reason = "stale"
	if c.missing {
		c.result.Reason = "missing"
	}
	if remove {
		c.result.Reason = "owned"
		if c.after == nil {
			c.result.Action = "remove"
		}
	}
	return c, nil
}

func apply(c change, opts Options) error {
	file := c.result.File
	// Catch changes since planning before replacing the file.
	if file.Scope == System {
		info, err := os.Lstat(file.Path)
		if err == nil && !info.Mode().IsRegular() {
			return fmt.Errorf("%s is no longer a regular file", file.Path)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	current, err := os.ReadFile(file.Path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if c.missing != errors.Is(err, os.ErrNotExist) || !bytes.Equal(current, c.before) {
		return fmt.Errorf("%s changed during hook installation; retry", file.Path)
	}
	if file.Kind == "claude" {
		if c.after == nil && opts.RemoveClaude != nil {
			return opts.RemoveClaude(file.Path)
		}
		if c.after != nil && opts.WriteClaude != nil {
			return opts.WriteClaude(file.Path, c.after)
		}
	}
	if err := os.MkdirAll(filepath.Dir(file.Path), 0755); err != nil {
		return err
	}
	if file.Kind != "claude" {
		if err := agenthooks.BackupFile(file.Path, BackupLabel); err != nil {
			return err
		}
	}
	if c.after == nil {
		return os.Remove(file.Path)
	}
	if err := agenthooks.WriteRawFile(file.Path, c.after); err != nil {
		return err
	}
	if file.Scope == System {
		return os.Chmod(file.Path, 0644)
	}
	return nil
}

// Store only the changed line, never a snapshot of unrelated user configuration.
func markFeature(before, after []byte) []byte {
	oldLines, newLines := strings.Split(string(before), "\n"), strings.Split(string(after), "\n")
	for i, line := range newLines {
		if strings.TrimSpace(line) != "hooks = true" {
			continue
		}
		// EnableHooksFeature changes exactly one key. Locate the old line by the
		// common prefix, which also handles inserting a missing table/key.
		if i < len(oldLines) && oldLines[i] == line {
			continue
		}
		original := ""
		if len(oldLines) == len(newLines) {
			original = oldLines[i]
		}
		newLines[i] = line + featureMarker + base64.StdEncoding.EncodeToString([]byte(original))
		if i > 0 && strings.TrimSpace(newLines[i-1]) == "[features]" && !strings.Contains(string(before), "[features]") {
			newLines[i-1] += " # kontext-hooks"
		}
		break
	}
	return []byte(strings.Join(newLines, "\n"))
}

func removeFeature(raw []byte) ([]byte, error) {
	if _, _, err := codexmanaged.HooksFeature(string(raw)); err != nil {
		return nil, err
	}
	lines := strings.Split(string(raw), "\n")
	for i, line := range lines {
		at := strings.Index(line, featureMarker)
		if at < 0 || strings.TrimSpace(line[:at]) != "hooks = true" {
			continue
		}
		original, err := base64.StdEncoding.DecodeString(line[at+len(featureMarker):])
		if err != nil || bytes.ContainsAny(bytes.TrimSuffix(original, []byte("\r")), "\r\n") {
			return raw, nil
		}
		if len(original) > 0 {
			lines[i] = string(original)
		} else {
			lines = append(lines[:i], lines[i+1:]...)
		}
		// Drop our table header only when no assignments remain in that table.
		for j, line := range lines {
			if line != "[features] # kontext-hooks" {
				continue
			}
			empty := true
			for _, following := range lines[j+1:] {
				trimmed := strings.TrimSpace(following)
				if trimmed == "" || strings.HasPrefix(trimmed, "#") {
					continue
				}
				empty = strings.HasPrefix(trimmed, "[")
				break
			}
			if empty {
				lines = append(lines[:j], lines[j+1:]...)
			}
			break
		}
		next := strings.Join(lines, "\n")
		var before, after map[string]any
		if _, err := toml.Decode(string(raw), &before); err != nil {
			return nil, err
		}
		if _, err := toml.Decode(next, &after); err != nil {
			return nil, err
		}
		// A marker copied into a string or another table is not ownership. Prove
		// the edit changes only the canonical feature flag before accepting it.
		for _, config := range []map[string]any{before, after} {
			if features, ok := config["features"].(map[string]any); ok {
				delete(features, "hooks")
				if len(features) == 0 {
					delete(config, "features")
				}
			}
		}
		if !reflect.DeepEqual(before, after) {
			return raw, nil
		}
		if strings.TrimSpace(next) == "" {
			return nil, nil
		}
		return []byte(next), nil
	}
	return raw, nil
}
