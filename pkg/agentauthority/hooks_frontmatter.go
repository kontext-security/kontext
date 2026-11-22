package agentauthority

import (
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/kontext-security/kontext/pkg/agentauthority/readers"
)

// Scope kinds for hooks a skill or subagent declares in its frontmatter
// (ENG-1104).
const (
	HookScopeSkill    = "skill"
	HookScopeSubagent = "subagent"
)

// HookReasonWhileActive: the hook runs only while its skill or subagent is
// active. A skill's hooks run for the rest of the session once it is
// invoked; a subagent's while it runs (Claude Code hooks reference, hook
// scopes).
const HookReasonWhileActive = "while_active"

// Bounds on frontmatter folders: each one is listed, never walked past
// these.
const (
	// maxFrontmatterFiles is the most skills or subagent files read from
	// one folder.
	maxFrontmatterFiles = 64
	// maxAgentDepth is how deep a subagents folder is listed: Claude Code
	// reads it recursively.
	maxAgentDepth = 3
	// maxAgentListings is the most folders listed under one subagents
	// folder.
	maxAgentListings = 32
)

func frontmatterKind(kind string) bool { return kind == HookScopeSkill || kind == HookScopeSubagent }

// frontmatterScopes reads the skills and subagents under dir (a .claude
// folder, or a plugin's install folder) for hooks. from is the scope kind
// whose rules those hooks follow: managed, user, project or plugin. A plugin
// subagent can't declare hooks, so a plugin's agents are not read.
func (s *hookScan) frontmatterScopes(dir, from string, plugin *pluginRef) {
	s.frontmatterFrom = from
	defer func() { s.frontmatterFrom = "" }()
	skills := filepath.Join(dir, "skills")
	s.only()
	read := 0
	for _, entry := range s.g.entries(skills) {
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			// Never followed: what it holds goes unread, so the scan
			// isn't complete.
			s.source.Fail(ReasonUnsupportedFormat)
			continue
		}
		if !entry.IsDir() {
			continue
		}
		if read >= maxFrontmatterFiles {
			s.source.Fail(ReasonWalkLimit)
			s.agent.Truncated = true
			break
		}
		read++
		// The folder was listed, not the file: a folder without SKILL.md
		// is no skill, not a vanished file.
		path := filepath.Join(skills, name, "SKILL.md")
		// A plugin skill is keyed under its install, not its cache path: an
		// update keeps the scope, and two installs of one plugin don't share
		// one.
		canonical := filepath.Clean(path)
		if plugin != nil && plugin.canonical != "" {
			canonical = plugin.canonical + "|skill|" + name
		}
		s.frontmatterScope(HookScopeSkill, path, canonical, false, plugin)
	}
	if from == HookScopePlugin {
		return
	}
	read = 0
	listings := 0
	var walk func(folder string, depth int)
	walk = func(folder string, depth int) {
		if listings >= maxAgentListings {
			s.source.Fail(ReasonWalkLimit)
			s.agent.Truncated = true
			return
		}
		listings++
		s.only()
		for _, entry := range s.g.entries(folder) {
			name := entry.Name()
			if strings.HasPrefix(name, ".") {
				continue
			}
			path := filepath.Join(folder, name)
			if entry.Type()&fs.ModeSymlink != 0 {
				s.source.Fail(ReasonUnsupportedFormat)
				continue
			}
			if entry.IsDir() {
				if depth+1 < maxAgentDepth {
					walk(path, depth+1)
				} else {
					s.source.Fail(ReasonWalkLimit)
					s.agent.Truncated = true
				}
				continue
			}
			if !strings.HasSuffix(name, ".md") {
				continue
			}
			if read >= maxFrontmatterFiles {
				s.source.Fail(ReasonWalkLimit)
				s.agent.Truncated = true
				return
			}
			read++
			s.frontmatterScope(HookScopeSubagent, path, filepath.Clean(path), true, nil)
		}
	}
	walk(filepath.Join(dir, "agents"), 0)
}

// frontmatterScope reads one file's hooks into a scope. A file that declares
// none and read cleanly lists no scope, so skills without hooks don't use
// the scope cap; one that couldn't be read is listed, so its hooks stay.
func (s *hookScan) frontmatterScope(kind, path, canonical string, listed bool, plugin *pluginRef) {
	h, id := s.scope(kind, canonical)
	if h == nil {
		return
	}
	var settings readers.HookSettings
	var ok bool
	if listed {
		settings, ok = readListed(s.g, s.agent.ID, path, readers.FrontmatterHooks)
	} else {
		settings, ok = readConfig(s.g, s.agent.ID, path, readers.FrontmatterHooks)
	}
	before := len(s.agent.Hooks)
	if ok {
		hooks := settings.Hooks
		if kind == HookScopeSubagent {
			hooks = subagentEvents(hooks)
		}
		s.records(id, kind, hooks, plugin, -1)
	}
	if result := h.Result(s.opts.Now); len(s.agent.Hooks) == before && result.Status == StatusComplete {
		// Read and empty: listed after every scope with hooks, so a skill
		// whose last hook was removed is seen without it.
		s.emptyFrontmatter = append(s.emptyFrontmatter, HookScope{ID: id, Kind: kind, Status: result.Status, Reasons: []string{}, CheckedAt: result.FinishedAt})
		s.only()
		return
	}
	s.closeScope(h, id, kind)
}

// listEmptyFrontmatter lists the skills and subagents read cleanly with no
// hooks while the scope cap allows. One left out carries no hook, so the
// scan isn't truncated for it; a hook it held before is withdrawn as soon
// as the scan is complete.
func (s *hookScan) listEmptyFrontmatter() {
	for _, scope := range s.emptyFrontmatter {
		if len(s.agent.Scopes) >= MaxHookScopes {
			break
		}
		s.agent.Scopes = append(s.agent.Scopes, scope)
	}
}

// subagentEvents names a subagent's Stop hooks as Claude Code runs them:
// SubagentStop.
func subagentEvents(hooks map[string][]readers.HookGroup) map[string][]readers.HookGroup {
	stop, ok := hooks["Stop"]
	if !ok {
		return hooks
	}
	out := make(map[string][]readers.HookGroup, len(hooks))
	for event, groups := range hooks {
		if event != "Stop" {
			out[event] = groups
		}
	}
	out["SubagentStop"] = append(out["SubagentStop"], stop...)
	return out
}
