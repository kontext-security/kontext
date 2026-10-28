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
	"github.com/kontext-security/kontext/internal/cursormanaged"
	"github.com/kontext-security/kontext/internal/privacyfolder"
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

// Definitions is the only list of installations. Self-serve writes only files
// in the user's home, so neither setup nor the daemon ever asks for an
// administrator; organization packages keep the machine-wide files.
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
	claude := File{"claude", claudemanaged.ManagedSettingsDropInPath, System}
	cursor := File{"cursor", cursormanaged.SystemHooksPath, System}
	if scope == User {
		path, err := claudemanaged.UserSettingsPathNoCreate(home)
		if err != nil {
			return nil, err
		}
		claude = File{"claude-user", path, User}
		cursor = File{"cursor", filepath.Join(home, ".cursor", "hooks.json"), User}
	}
	return []Definition{
		{Agent: "claude_code", Name: "Claude Code", Files: []File{claude}, Validate: validateClaude},
		{Agent: "codex", Name: "Codex", Files: []File{{"codex", filepath.Join(codexDir, "hooks.json"), scope}, {"feature", filepath.Join(codexDir, "config.toml"), scope}}, Validate: codexmanaged.ValidateInstalled},
		{Agent: "cursor", Name: "Cursor", Files: []File{cursor}, Validate: cursormanaged.ValidateInstalled},
	}, nil
}

// Machine-wide files a user-scope install reads but never writes (test seams).
var (
	machineClaudeDropIn = claudemanaged.ManagedSettingsDropInPath
	machineCursorHooks  = cursormanaged.SystemHooksPath
)

// machineClaudeSources returns Claude's machine-wide managed settings:
// managed-settings.json and every drop-in, including the one an earlier
// self-serve setup wrote. A user copy repeats the Kontext handlers they
// declare, so each runs once.
func machineClaudeSources(opts Options) [][]byte {
	dropIn := opts.ClaudePath
	if dropIn == "" {
		dropIn = machineClaudeDropIn
	}
	var sources [][]byte
	for _, path := range claudemanaged.MachineSettingsFiles(dropIn, filepath.Join(filepath.Dir(filepath.Dir(dropIn)), "managed-settings.json")) {
		// The daemon's repair runs in the background, where a file linked into
		// ~/Documents or iCloud would prompt for folder access.
		if privacyfolder.Guarded("", path) {
			continue
		}
		if raw, err := os.ReadFile(path); err == nil {
			sources = append(sources, raw)
		}
	}
	return sources
}

// machineCursorCoverage lists the Cursor events whose machine-wide Kontext
// hook can run. A hook naming a deleted binary covers nothing.
func machineCursorCoverage(opts Options) map[string]bool {
	path := opts.CursorPath
	if path == "" {
		path = machineCursorHooks
	}
	if privacyfolder.Guarded("", path) {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	covered := map[string]bool{}
	for event, binary := range cursormanaged.Coverage(raw) {
		if !privacyfolder.Guarded("", binary) && executable(binary) {
			covered[event] = true
		}
	}
	return covered
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
	Setup bool
	// KeepSystem leaves machine-wide files alone on removal (an
	// organization-managed install owns them).
	KeepSystem bool
	// ClaudePath and CursorPath override the machine-wide files: where system
	// scope writes, and what user scope checks for hooks an earlier self-serve
	// setup put there.
	ClaudePath, CursorPath string
	// WriteSystem and RemoveSystem change machine-wide files for an
	// unprivileged caller; nil writes them directly (root). The last argument
	// fails when the file changed since planning; call it after any password
	// prompt.
	WriteSystem  func(path string, data []byte, unchanged func() error) error
	RemoveSystem func(path string, unchanged func() error) error
	Report       func(Result)
	// Skip leaves a file out entirely, e.g. one the caller must not read.
	Skip func(File) bool
	// NoBackup skips the timestamped backup before a change. The daemon's
	// repairs only re-add Kontext's own entries; a backup per repair would
	// pile up while something keeps removing them.
	NoBackup bool
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
			if opts.Skip != nil && opts.Skip(file) {
				continue
			}
			if file.Kind == "claude" && opts.ClaudePath != "" {
				file.Path = opts.ClaudePath
			}
			if file.Kind == "cursor" && file.Scope == System && opts.CursorPath != "" {
				file.Path = opts.CursorPath
			}
			c, err := plan(file, opts, remove)
			c.result.File = file
			if err != nil {
				c.result.Action = "error"
				c.result.Err = err
				if !setupTolerates(opts, file.Kind, remove) {
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
				if !setupTolerates(opts, r.File.Kind, remove) {
					return err
				}
			}
		}
		if opts.Report != nil {
			opts.Report(r)
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

// setupTolerates lists the files setup reports instead of failing on: the
// optional Codex feature flag, and any file an uninstall cannot clean.
func setupTolerates(opts Options, kind string, remove bool) bool {
	return opts.Setup && (kind == "feature" || remove && (kind == "codex" || kind == "cursor" || kind == "claude-user"))
}

func plan(file File, opts Options, remove bool) (change, error) {
	c := change{result: Result{File: file, Action: "skip", Reason: "unchanged"}}
	if remove && (file.Scope == System && opts.KeepSystem || file.Kind == "feature" && opts.Setup) {
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
	// A dangling link in the home folder reads as missing but cannot be
	// written; fail while planning, before any file changes.
	if err == nil && file.Scope == User && info.Mode()&os.ModeSymlink != 0 {
		if _, err := filepath.EvalSymlinks(file.Path); err != nil {
			return c, fmt.Errorf("resolve %s symlink: %w", file.Path, err)
		}
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
	case "codex", "claude-user", "cursor":
		binary := opts.Binary
		var machine [][]byte
		if file.Kind == "claude-user" && !remove {
			machine = machineClaudeSources(opts)
		}
		// Cursor runs every hooks.json it finds and does not deduplicate, so the
		// user file leaves out the events an earlier setup's machine-wide file
		// already covers.
		var covered map[string]bool
		if file.Kind == "cursor" && file.Scope == User && !remove {
			covered = machineCursorCoverage(opts)
		}
		removeHere := remove || len(covered) == len(cursormanaged.Events)
		if file.Kind == "claude-user" && !remove && claudemanaged.UserHooksMatch(c.before, binary, machine...) {
			return c, nil
		}
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
		if file.Kind == "claude-user" && remove {
			err = claudemanaged.RemoveManagedHooks(settings)
		} else if file.Kind == "claude-user" {
			_, err = claudemanaged.MergeManagedHooksMirroring(settings, binary, machine...)
		} else if file.Kind == "cursor" && removeHere {
			err = cursormanaged.RemoveManagedHooks(settings)
		} else if file.Kind == "cursor" {
			err = cursormanaged.MergeManagedHooksExcept(settings, binary, covered)
		} else if remove {
			err = codexmanaged.RemoveManagedHooks(settings)
		} else {
			err = codexmanaged.MergeManagedHooks(settings, opts.Binary)
		}
		if err != nil {
			return c, err
		}
		after, _ := json.Marshal(settings)
		// Setup rewrites Codex's file as is; a machine-wide file is only
		// rewritten when Kontext's entries change, so a rerun asks for no password.
		if bytes.Equal(before, after) && (!opts.Setup || file.Kind == "claude-user" || file.Kind == "cursor") {
			return c, nil
		}
		c.after, err = json.MarshalIndent(settings, "", "  ")
		c.after = append(c.after, '\n')
		// Only delete an empty file when all of its content was our hooks. A
		// dotfiles symlink stays; its target gets the emptied settings.
		if removeHere && (!opts.Setup || file.Kind == "cursor") && len(settings) == 0 && file.Kind != "claude-user" && info.Mode()&os.ModeSymlink == 0 {
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
	unchanged := func() error {
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
		return nil
	}
	if err := unchanged(); err != nil {
		return err
	}
	// ponytail: the privileged writer keeps no backup; Kontext only changes its
	// own entries in a machine-wide file.
	if file.Scope == System {
		if c.after == nil && opts.RemoveSystem != nil {
			return opts.RemoveSystem(file.Path, unchanged)
		}
		if c.after != nil && opts.WriteSystem != nil {
			return opts.WriteSystem(file.Path, c.after, unchanged)
		}
	}
	if err := os.MkdirAll(filepath.Dir(file.Path), 0755); err != nil {
		return err
	}
	if file.Kind != "claude" && !opts.NoBackup {
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
