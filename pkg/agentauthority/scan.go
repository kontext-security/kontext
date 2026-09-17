package agentauthority

import (
	"context"
	"encoding/json"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kontext-security/kontext/pkg/agentauthority/readers"
)

// Scan accepts already-discovered locations and an injected runtime snapshot.
// It never discovers arbitrary projects, executes commands, or uses the network.
func Scan(ctx context.Context, home string, env Environment, agents []AgentLocation, now time.Time) Report {
	return scan(ctx, home, env, agents, now, managedRoot)
}

func scan(ctx context.Context, home string, env Environment, agents []AgentLocation, now time.Time, managed string) Report {
	// Keep agent addresses stable while detail and skill reads wait for configs.
	r := Report{SchemaVersion: "authority/v1", ScannedAt: now.UTC().Format(time.RFC3339), Agents: make([]Agent, 0, len(agents)), Environment: env, Credentials: []Credential{}, Coverage: Coverage{UnknownFormat: []string{}, Errors: []string{}}}
	g := guard{ctx: ctx, home: filepath.Clean(home), managed: managed, roots: []string{filepath.Clean(home), managed}, report: &r}
	root := readers.ClaudeRoot{}
	if data := g.read(filepath.Join(home, ".claude.json")); data != nil {
		var err error
		root, err = readers.Claude(data)
		if err != nil {
			g.parseError("claude_code", ".claude.json")
		}
	}
	projects := keys(root.Projects)
	if len(projects) > 32 {
		r.Coverage.Limits = append(r.Coverage.Limits, "claude_code: projects limited to 32")
		projects = projects[:32]
	}
	for _, project := range projects {
		if filepath.IsAbs(project) {
			g.roots = append(g.roots, filepath.Clean(project))
		}
	}
	g.credentials(projects)
	for _, location := range agents {
		if ctx.Err() != nil {
			r.Truncated = true
			break
		}
		id := safe(location.ID, 128)
		if id == "" {
			continue
		}
		r.Agents = append(r.Agents, Agent{ID: id, MCPServers: []MCPServer{}, Plugins: []Plugin{}, Skills: []Skill{}, Hooks: []Hook{}, Subagents: []Subagent{}, Permissions: Permissions{Allow: []Grant{}}})
		a := &r.Agents[len(r.Agents)-1]
		base := location.ConfigPath
		if strings.HasPrefix(base, "~/") {
			base = filepath.Join(home, base[2:])
		}
		switch id {
		case "claude_code":
			g.claude(a, base, root, projects)
		case "codex":
			if data := g.read(filepath.Join(base, "config.toml")); data != nil {
				c, err := readers.Codex(data)
				if err != nil {
					g.parseError(id, "config.toml")
				} else {
					g.servers(a, c.MCPServers, filepath.Join(base, "config.toml"), "user", nil)
					mode := c.SandboxMode
					if mode != "read-only" && mode != "workspace-write" && mode != "danger-full-access" {
						mode = ""
					}
					a.Permissions.Codex = &CodexPermissions{SandboxMode: pointer(mode), ApprovalPolicy: pointer(safe(c.ApprovalPolicy, 128))}
				}
			}
			g.scanSkills = append(g.scanSkills, func() { g.skills(a, filepath.Join(base, "skills")) })
		case "claude_cowork":
			g.desktop(a)
		case "cursor":
			g.generic(a, filepath.Join(base, "mcp.json"), "mcpServers")
		case "windsurf":
			g.generic(a, filepath.Join(home, ".codeium/windsurf/mcp_config.json"), "mcpServers")
		case "copilot_cli":
			g.generic(a, filepath.Join(base, "mcp-config.json"), "mcpServers")
			g.generic(a, filepath.Join(home, "Library/Application Support/Code/User/mcp.json"), "servers")
		case "gemini_cli":
			g.generic(a, filepath.Join(base, "settings.json"), "mcpServers")
		case "antigravity":
			g.generic(a, filepath.Join(home, ".gemini/antigravity/mcp_config.json"), "mcpServers")
		case "kiro":
			g.generic(a, filepath.Join(base, "settings/mcp.json"), "mcpServers")
		case "amp":
			g.generic(a, filepath.Join(base, "settings.json"), "amp.mcpServers")
		case "opencode":
			g.generic(a, filepath.Join(base, "opencode.json"), "mcp")
		default:
			r.Coverage.UnknownFormat = append(r.Coverage.UnknownFormat, id)
		}
	}
	for _, read := range g.scanDetails {
		read()
	}
	for _, read := range g.scanSkills {
		read()
	}
	if ctx.Err() != nil {
		r.Truncated = true
	}
	r.finish()
	return r
}
func keys[T any](m map[string]T) []string {
	result := make([]string, 0, len(m))
	for key := range m {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}
func (g *guard) parseError(id, file string) {
	if len(g.report.Coverage.Errors) < 200 {
		g.report.Coverage.Errors = append(g.report.Coverage.Errors, safe(id+": "+file+" parse error", 256))
	}
}
func (g *guard) generic(a *Agent, path, key string) {
	if data := g.read(path); data != nil {
		servers, err := readers.GenericMCP(data, key)
		if err != nil {
			g.parseError(a.ID, filepath.Base(path))
			return
		}
		g.servers(a, servers, path, "user", nil)
	}
}
func (g *guard) servers(a *Agent, entries map[string]readers.MCP, source, scope string, project *string) {
	for _, key := range keys(entries) {
		if len(a.MCPServers) >= 64 {
			g.skip()
			return
		}
		if g.ctx.Err() != nil {
			g.report.Truncated = true
			return
		}
		entry := entries[key]
		name := safe(key, 128)
		if !validText(name) {
			continue
		}
		server := MCPServer{Name: name, Args: []string{}, Source: safe(g.source(source), 1024), Scope: scope, Project: project}
		if entry.Command != "" {
			server.Transport = "stdio"
			server.Command = pointer(safe(filepath.Base(entry.Command), 128))
		} else if entry.URL != "" {
			u, err := url.Parse(entry.URL)
			if err != nil || u.Hostname() == "" {
				continue
			}
			server.Transport = "http"
			server.URLHost = pointer(safe(u.Hostname(), 128))
		} else {
			continue
		}
		server.Args = safeArgs(entry.Args[:min(6, len(entry.Args))])
		if server.Command == nil && server.URLHost == nil {
			continue
		}
		a.MCPServers = append(a.MCPServers, server)
	}
}
func (g *guard) claude(a *Agent, base string, root readers.ClaudeRoot, projects []string) {
	g.servers(a, root.MCPServers, filepath.Join(g.home, ".claude.json"), "user", nil)
	enabled := map[string]bool{}
	for _, path := range []string{filepath.Join(base, "settings.json"), filepath.Join(base, "settings.local.json"), filepath.Join(g.managed, "managed-settings.json")} {
		g.settings(a, path, enabled)
	}
	for _, entry := range g.entries(filepath.Join(g.managed, "managed-settings.d")) {
		if strings.HasSuffix(entry.Name(), ".json") {
			g.settings(a, filepath.Join(g.managed, "managed-settings.d", entry.Name()), enabled)
		}
	}
	g.plugins(a, base, enabled)
	for _, project := range projects {
		label := pointer(safe(filepath.Base(project), 128))
		g.servers(a, root.Projects[project].MCPServers, filepath.Join(g.home, ".claude.json"), "project", label)
		path := filepath.Join(project, ".mcp.json")
		if data := g.read(path); data != nil {
			entries, err := readers.GenericMCP(data, "mcpServers")
			if err == nil {
				g.servers(a, entries, path, "project", label)
			} else {
				g.parseError(a.ID, ".mcp.json")
			}
		}
	}
	g.scanDetails = append(g.scanDetails, func() { g.subagents(a, filepath.Join(base, "agents")) })
	g.scanSkills = append(g.scanSkills, func() { g.skills(a, filepath.Join(base, "skills")) })
}
func (g *guard) settings(a *Agent, path string, enabled map[string]bool) {
	data := g.read(path)
	if data == nil {
		return
	}
	c, err := readers.Settings(data)
	if err != nil {
		g.parseError(a.ID, filepath.Base(path))
		return
	}
	if c.Permissions.DefaultMode != nil {
		a.Permissions.DefaultMode = pointer(safe(*c.Permissions.DefaultMode, 128))
	}
	for _, pattern := range c.Permissions.Allow {
		if risk := grantRisk(pattern); risk != "" {
			if clean := safeGrant(pattern); clean != "" {
				a.Permissions.Allow = append(a.Permissions.Allow, Grant{clean, risk})
			}
		}
	}
	a.Permissions.DenyCount += len(c.Permissions.Deny)
	if c.Sandbox.Enabled != nil {
		a.Permissions.Sandbox.Enabled = c.Sandbox.Enabled
	}
	if c.Sandbox.AllowUnsandboxed != nil {
		a.Permissions.Sandbox.AllowUnsandboxed = c.Sandbox.AllowUnsandboxed
	}
	a.Permissions.Sandbox.AllowedDomains += len(c.Sandbox.Network.AllowedDomains)
	for key, value := range c.EnabledPlugins {
		if enabled != nil {
			enabled[key] = value
		}
	}
	for _, event := range keys(c.Hooks) {
		for _, matcher := range c.Hooks[event] {
			for _, hook := range matcher.Hooks {
				if hook.Type != "command" {
					continue
				}
				parts := strings.Fields(hook.Command)
				if len(parts) == 0 {
					continue
				}
				words := []string{safe(filepath.Base(strings.Trim(parts[0], "\"'")), 128)}
				words = append(words, safeArgs(parts[1:min(len(parts), 7)])...)
				command := safe(strings.Join(words, " "), 128)
				if command != "" {
					a.Hooks = append(a.Hooks, Hook{safe(event, 128), command, safe(g.source(path), 1024)})
				}
			}
		}
	}
}
func safeGrant(pattern string) string {
	if !strings.HasPrefix(pattern, "Bash(") {
		return safe(pattern, 128)
	}
	words := strings.Fields(strings.TrimSuffix(strings.TrimPrefix(pattern, "Bash("), ")"))
	words = safeArgs(words)
	if len(words) == 0 {
		return ""
	}
	return safe("Bash("+strings.Join(words, " ")+")", 128)
}
func grantRisk(pattern string) string {
	if pattern == "Bash" || pattern == "Bash(*)" {
		return "any_shell"
	}
	if pattern == "WebFetch" || pattern == "WebFetch(*)" {
		return "network"
	}
	if !strings.HasPrefix(pattern, "Bash(") {
		return ""
	}
	command := strings.TrimSuffix(strings.TrimPrefix(pattern, "Bash("), ")")
	parts := strings.FieldsFunc(command, func(r rune) bool { return r == ' ' || r == ':' || r == '*' })
	if len(parts) == 0 {
		return ""
	}
	word := filepath.Base(parts[0])
	switch word {
	case "bash", "sh", "zsh", "node", "perl", "ruby":
		return "any_shell"
	case "sudo", "su", "doas":
		return "sudo"
	case "rm", "rmdir", "shred":
		return "delete"
	case "chmod", "chown":
		return "ownership"
	case "kill", "pkill", "killall":
		return "kill"
	case "curl", "wget", "nc", "ssh", "scp":
		remainder := strings.TrimLeft(command[len(parts[0]):], ": ")
		for _, arg := range strings.Fields(remainder) {
			if arg == "*" || strings.HasPrefix(arg, "-") {
				continue
			}
			u, err := url.Parse(arg)
			if err != nil || u.Scheme == "" || u.Host != "*" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
				return ""
			}
		}
		return "network"
	}
	if strings.HasPrefix(word, "python") {
		return "any_shell"
	}
	if strings.HasPrefix(command, "git push --force") || strings.HasPrefix(command, "git push -f") || strings.HasPrefix(command, "git reset --hard") || strings.HasPrefix(command, "git clean -f") {
		return "git_force"
	}
	return ""
}
func (g *guard) skills(a *Agent, dir string) {
	for _, entry := range g.entries(dir) {
		path := filepath.Join(dir, entry.Name(), "SKILL.md")
		if data := g.read(path); data != nil {
			if name := safe(entry.Name(), 128); name != "" {
				a.Skills = append(a.Skills, Skill{name, safe(g.source(dir), 1024)})
			}
		}
	}
}
func (g *guard) subagents(a *Agent, dir string) {
	for _, entry := range g.entries(dir) {
		if !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		data := g.read(filepath.Join(dir, entry.Name()))
		if data == nil {
			continue
		}
		wildcard := true
		lines := strings.Split(string(data), "\n")
		if len(lines) > 0 && strings.TrimSpace(lines[0]) == "---" {
			for _, line := range lines[1:] {
				if strings.TrimSpace(line) == "---" {
					break
				}
				if strings.HasPrefix(line, "tools:") {
					value := strings.TrimSpace(strings.TrimPrefix(line, "tools:"))
					wildcard = value == "" || strings.Contains(value, "*")
					break
				}
			}
		}

		if name := safe(strings.TrimSuffix(entry.Name(), ".md"), 128); name != "" {
			a.Subagents = append(a.Subagents, Subagent{name, wildcard})
		}
	}
}
func (g *guard) desktop(a *Agent) {
	base := filepath.Join(g.home, "Library/Application Support/Claude")
	g.generic(a, filepath.Join(base, "claude_desktop_config.json"), "mcpServers")
	for _, entry := range g.entries(filepath.Join(base, "Claude Extensions")) {
		data := g.read(filepath.Join(base, "Claude Extensions", entry.Name(), "manifest.json"))
		if data == nil {
			continue
		}
		e, err := readers.DesktopExtension(data)
		if err != nil {
			g.parseError(a.ID, "manifest.json")
			continue
		}
		if name := safe(e.Name, 128); name != "" {
			a.Plugins = append(a.Plugins, Plugin{Name: name, Enabled: true})
		}
	}
}
func (g *guard) plugins(a *Agent, base string, enabled map[string]bool) {
	data := g.read(filepath.Join(base, "plugins/installed_plugins.json"))
	if data == nil {
		return
	}
	var index struct {
		Plugins map[string][]struct {
			InstallPath string `json:"installPath"`
		} `json:"plugins"`
	}
	if json.Unmarshal(data, &index) != nil {
		g.parseError(a.ID, "installed_plugins.json")
		return
	}
	for _, key := range keys(index.Plugins) {
		for _, entry := range index.Plugins[key] {
			if !within(filepath.Join(base, "plugins/cache"), entry.InstallPath) {
				g.skip()
				continue
			}
			manifest := g.read(filepath.Join(entry.InstallPath, ".claude-plugin/plugin.json"))
			if manifest == nil {
				continue
			}
			var meta struct {
				Name string `json:"name"`
			}
			if json.Unmarshal(manifest, &meta) != nil {
				g.parseError(a.ID, "plugin.json")
				continue
			}
			name := safe(meta.Name, 128)
			if name == "" {
				continue
			}
			market := ""
			if _, value, ok := strings.Cut(key, "@"); ok {
				market = safe(value, 128)
			}
			active := true
			if value, ok := enabled[key]; ok {
				active = value
			}
			plugin := Plugin{Name: name, Marketplace: pointer(market), Enabled: active}
			// Inventory plugin contents even when disabled; only enabled MCPs imply reach.
			scratch := Agent{ID: a.ID, MCPServers: []MCPServer{}, Skills: []Skill{}, Hooks: []Hook{}, Subagents: []Subagent{}, Permissions: Permissions{Allow: []Grant{}}}
			if data := g.read(filepath.Join(entry.InstallPath, ".mcp.json")); data != nil {
				entries, err := readers.GenericMCP(data, "mcpServers")
				if err == nil {
					g.servers(&scratch, entries, filepath.Join(entry.InstallPath, ".mcp.json"), "plugin", nil)
				} else {
					g.parseError(a.ID, ".mcp.json")
				}
			}
			plugin.MCPServers = len(scratch.MCPServers)
			pluginIndex := len(a.Plugins)
			a.Plugins = append(a.Plugins, plugin)
			g.scanDetails = append(g.scanDetails, func() {
				for _, item := range g.entries(filepath.Join(entry.InstallPath, "agents")) {
					if item.Type().IsRegular() && strings.HasSuffix(item.Name(), ".md") {
						a.Plugins[pluginIndex].Subagents++
					}
				}
				g.settings(&scratch, filepath.Join(entry.InstallPath, "hooks/hooks.json"), nil)
				a.Plugins[pluginIndex].Hooks = len(scratch.Hooks)
			})
			g.scanSkills = append(g.scanSkills, func() {
				for _, item := range g.entries(filepath.Join(entry.InstallPath, "skills")) {
					if item.IsDir() {
						a.Plugins[pluginIndex].Skills++
					}
				}
			})
			if active {
				a.MCPServers = append(a.MCPServers, scratch.MCPServers...)
			}
		}
	}
}
