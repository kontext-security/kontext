package agentauthority

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kontext-security/kontext/pkg/agentauthority/readers"
)

// Scanner keeps parsed files in memory between scans. The daemon owns its lifetime.
// BeginRead applies the daemon's disk policy on each filesystem worker thread.
type Scanner struct {
	mu        sync.Mutex
	cache     map[string]fileResult
	BeginRead func() func()
}

func Scan(ctx context.Context, home string, env Environment, agents []AgentLocation, now time.Time) Report {
	return new(Scanner).Scan(ctx, home, env, agents, now)
}

func (s *Scanner) Scan(ctx context.Context, home string, env Environment, agents []AgentLocation, now time.Time) Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache == nil {
		s.cache = make(map[string]fileResult)
	}
	return scanCached(ctx, home, env, agents, now, managedRoot, s.cache, s.BeginRead)
}

func scan(ctx context.Context, home string, env Environment, agents []AgentLocation, now time.Time, managed string) Report {
	return scanCached(ctx, home, env, agents, now, managed, nil, nil)
}

func scanCached(ctx context.Context, home string, env Environment, agents []AgentLocation, now time.Time, managed string, cache map[string]fileResult, beginRead func() func()) Report {
	// Read only the fixed configuration roots; never add paths found in content.
	r := Report{SchemaVersion: "authority/v1", ScannedAt: now.UTC().Format(time.RFC3339), Agents: make([]Agent, 0, len(agents)), Environment: env, Credentials: []Credential{}, Coverage: Coverage{UnknownFormat: []string{}, Errors: []string{}}}
	g := guard{ctx: ctx, home: filepath.Clean(home), managed: managed, roots: allowedRoots(home, managed), report: &r, cache: cache, beginRead: beginRead, seen: map[string]bool{}}
	// Environment overrides authorize exact config files only within home.
	clineData := filepath.Join(home, ".cline/data")
	if dir := strings.TrimSpace(os.Getenv("CLINE_DIR")); dir != "" {
		clineData = filepath.Join(configPath(home, dir), "data")
	}
	if dir := strings.TrimSpace(os.Getenv("CLINE_DATA_DIR")); dir != "" {
		clineData = configPath(home, dir)
	}
	if within(home, clineData) {
		g.roots = append(g.roots, filepath.Join(clineData, "globalState.json"), filepath.Join(clineData, "settings/cline_mcp_settings.json"))
	}
	opencodeDir := strings.TrimSpace(os.Getenv("OPENCODE_CONFIG_DIR"))
	if opencodeDir != "" {
		opencodeDir = configPath(home, opencodeDir)
		if within(home, opencodeDir) {
			g.roots = append(g.roots, filepath.Join(opencodeDir, "opencode.json"), filepath.Join(opencodeDir, "opencode.jsonc"))
		}
	}
	g.credentials()
	root, _ := readConfig(&g, "claude_code", filepath.Join(home, ".claude.json"), readers.Claude)
	projects := keys(root.Projects)
	if len(projects) > 32 {
		r.Coverage.Limits = append(r.Coverage.Limits, "claude_code: projects limited to 32")
		projects = projects[:32]
	}
	for _, location := range agents {
		if ctx.Err() != nil {
			r.Truncated = true
			break
		}
		id := safe(location.ID, 128)
		if id == "" {
			continue
		}
		r.Agents = append(r.Agents, Agent{ID: id, MCPServers: []MCPServer{}, Plugins: []Plugin{}, Permissions: Permissions{Allow: []Grant{}}})
		a := &r.Agents[len(r.Agents)-1]
		base := location.ConfigPath
		if strings.HasPrefix(base, "~/") {
			base = filepath.Join(home, base[2:])
		}
		switch id {
		case "claude_code":
			g.claude(a, base, root, projects)
		case "codex":
			if c, ok := readConfig(&g, id, filepath.Join(base, "config.toml"), readers.Codex); ok {
				g.servers(a, c.MCPServers, filepath.Join(base, "config.toml"), "user", nil)
				mode := c.SandboxMode
				if mode != "read-only" && mode != "workspace-write" && mode != "danger-full-access" {
					mode = ""
				}
				a.Permissions.Codex = &CodexPermissions{SandboxMode: pointer(mode), ApprovalPolicy: pointer(safe(c.ApprovalPolicy, 128))}
			}
		case "claude_cowork":
			g.desktop(a)
		case "cursor":
			g.generic(a, filepath.Join(base, "mcp.json"), "mcpServers")
			path := filepath.Join(home, "Library/Application Support/Cursor/User/globalStorage/state.vscdb")
			if enabled, ok := readConfig(&g, id, path, parseJSON[*bool], "cursor"); ok && enabled != nil {
				mode := "default"
				if *enabled {
					mode = "auto"
				}
				a.Permissions.DefaultMode = pointer(safe(mode, 128))
			}
		case "windsurf":
			g.generic(a, filepath.Join(home, ".codeium/windsurf/mcp_config.json"), "mcpServers")
			g.permissionConfig(a, filepath.Join(home, "Library/Application Support/Windsurf/User/settings.json"), readers.Windsurf)
		case "cline":
			g.generic(a, filepath.Join(clineData, "settings/cline_mcp_settings.json"), "mcpServers")
			g.permissionConfig(a, filepath.Join(clineData, "globalState.json"), readers.Cline)
		case "copilot_cli":
			g.generic(a, filepath.Join(base, "mcp-config.json"), "mcpServers")
			g.generic(a, filepath.Join(home, "Library/Application Support/Code/User/mcp.json"), "servers")
		case "gemini_cli":
			g.permissionConfig(a, filepath.Join(base, "settings.json"), readers.Gemini)
		case "antigravity":
			g.generic(a, filepath.Join(home, ".gemini/antigravity/mcp_config.json"), "mcpServers")
		case "kiro":
			g.generic(a, filepath.Join(base, "settings/mcp.json"), "mcpServers")
		case "amp":
			g.generic(a, filepath.Join(base, "settings.json"), "amp.mcpServers")
		case "opencode":
			if opencodeDir != "" {
				base = opencodeDir
			}
			g.layeredPermissions(a, base, []string{"opencode.json", "opencode.jsonc"}, readers.OpenCode)
		case "openclaw":
			// The canonical filename wins over the legacy Clawdbot filename.
			for _, name := range []string{"openclaw.json", "clawdbot.json"} {
				path := filepath.Join(base, name)
				if c, ok := readConfig(&g, id, path, readers.OpenClaw); ok {
					g.servers(a, c.MCPServers, path, "user", nil)
					g.catalogPlugins(a, filepath.Join(base, "extensions"), "openclaw.plugin.json", readers.OpenClawManifest, c.PluginStates, c.PluginsDefault)
					a.Permissions.DefaultMode = pointer(safe(c.DefaultMode, 128))
					break
				}
			}
		case "qwen_code":
			g.permissionConfig(a, filepath.Join(base, "settings.json"), readers.Qwen)
			states, _ := readConfig(&g, id, filepath.Join(base, "extensions/extension-enablement.json"), readers.QwenLegacyPluginStates)
			if current, ok := readConfig(&g, id, filepath.Join(base, "extension-store/state.json"), readers.QwenPluginStates); ok {
				states = current
			}
			g.catalogPlugins(a, filepath.Join(base, "extensions"), "qwen-extension.json", readers.ManifestJSON, states, true)
		case "goose":
			g.permissionConfig(a, filepath.Join(base, "config.yaml"), readers.Goose)
		case "factory_droid":
			g.permissionConfig(a, filepath.Join(base, "settings.json"), readers.Factory)
			g.generic(a, filepath.Join(base, "mcp.json"), "mcpServers")
		case "devin_cli":
			g.layeredPermissions(a, base, []string{"config.json", "mcp_config.json"}, readers.Devin)
		case "kimi_code":
			for _, key := range []string{"KIMI_CODE_HOME", "KIMI_SHARE_DIR"} {
				if dir := strings.TrimSpace(os.Getenv(key)); dir != "" {
					base = configPath(home, dir)
					if within(home, base) {
						g.roots = append(g.roots, filepath.Join(base, "config.toml"), filepath.Join(base, "mcp.json"))
					}
					break
				}
			}
			g.permissionConfig(a, filepath.Join(base, "config.toml"), readers.Kimi)
			g.generic(a, filepath.Join(base, "mcp.json"), "mcpServers")
		case "auggie":
			g.permissionConfig(a, filepath.Join(base, "settings.json"), readers.Auggie)
		case "kilo":
			g.layeredPermissions(a, base, []string{"config.json", "kilo.json", "kilo.jsonc", "opencode.json", "opencode.jsonc"}, readers.OpenCode)
		case "crush":
			path := filepath.Join(base, "crush.json")
			if override := strings.TrimSpace(os.Getenv("CRUSH_GLOBAL_CONFIG")); override != "" {
				path = configPath(home, override)
				if !strings.HasSuffix(path, ".json") {
					path = filepath.Join(path, "crush.json")
				}
				if within(home, path) {
					g.roots = append(g.roots, path)
				}
			}
			g.permissionConfig(a, path, readers.Crush)
		case "junie":
			g.permissionConfig(a, filepath.Join(base, "config.json"), readers.Junie)
			g.generic(a, filepath.Join(base, "mcp/mcp.json"), "mcpServers")
		case "grok_build":
			g.permissionConfig(a, filepath.Join(base, "config.toml"), readers.Grok)
		case "hermes":
			c := g.permissionConfig(a, filepath.Join(base, "config.yaml"), readers.Hermes)
			g.catalogPlugins(a, filepath.Join(base, "plugins"), "plugin.yaml", readers.ManifestYAML, c.PluginStates, false)
		case "pi":
			// Pi has no native MCP configuration or persisted approval toggle.
			states, _ := readConfig(&g, id, filepath.Join(base, "settings.json"), readers.PiPluginStates)
			root := filepath.Join(base, "npm/node_modules")
			g.catalogPlugins(a, root, "package.json", readers.PiManifest, states, false)
			for _, entry := range g.entries(root) {
				if strings.HasPrefix(entry.Name(), "@") {
					g.catalogPlugins(a, filepath.Join(root, entry.Name()), "package.json", readers.PiManifest, states, false)
				}
			}
		default:
			r.Coverage.UnknownFormat = append(r.Coverage.UnknownFormat, id)
		}
	}
	if ctx.Err() != nil {
		r.Truncated = true
	}
	for path := range cache {
		if !g.seen[path] {
			delete(cache, path)
		}
	}
	r.finish()
	return r
}
func configPath(home, path string) string {
	if path == "~" {
		return home
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, path[2:])
	}
	if !filepath.IsAbs(path) {
		return filepath.Join(home, path)
	}
	return filepath.Clean(path)
}

func (g *guard) permissionConfig(a *Agent, path string, parse func([]byte) (readers.PermissionConfig, error)) readers.PermissionConfig {
	if c, ok := readConfig(g, a.ID, path, parse); ok {
		g.servers(a, c.MCPServers, path, "user", nil)
		if c.DefaultMode != "" {
			a.Permissions.DefaultMode = pointer(safe(c.DefaultMode, 128))
		}
		return c
	}
	return readers.PermissionConfig{}
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
	if servers, ok := readConfig(g, a.ID, path, func(data []byte) (map[string]readers.MCP, error) { return readers.GenericMCP(data, key) }); ok {
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
			server.Transport = pointer("stdio")
			server.Command = pointer(safe(filepath.Base(entry.Command), 128))
		} else if entry.URL != "" {
			u, err := url.Parse(entry.URL)
			if err != nil || u.Hostname() == "" {
				continue
			}
			server.Transport = pointer("http")
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
		config := root.Projects[project]
		names := append(keys(config.MCPServers), config.EnabledMcpjsonServers...)
		seen := map[string]bool{}
		for _, raw := range names {
			name := safe(raw, 128)
			if !validText(name) || seen[name] {
				continue
			}
			seen[name] = true
			a.MCPServers = append(a.MCPServers, MCPServer{Name: name, Args: []string{}, Source: "~/.claude.json", Scope: "project", Project: pointer(safe(filepath.Base(project), 128))})
		}
	}
}
func (g *guard) settings(a *Agent, path string, enabled map[string]bool) {
	c, ok := readConfig(g, a.ID, path, readers.Settings)
	if !ok {
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
func (g *guard) desktop(a *Agent) {
	base := filepath.Join(g.home, "Library/Application Support/Claude")
	g.generic(a, filepath.Join(base, "claude_desktop_config.json"), "mcpServers")
	for _, entry := range g.entries(filepath.Join(base, "Claude Extensions")) {
		e, ok := readConfig(g, a.ID, filepath.Join(base, "Claude Extensions", entry.Name(), "manifest.json"), readers.DesktopExtension)
		if !ok {
			continue
		}
		if name := safe(e.Name, 128); name != "" {
			a.Plugins = append(a.Plugins, Plugin{Name: name, Enabled: true})
		}
	}
}
func (g *guard) plugins(a *Agent, base string, enabled map[string]bool) {
	type pluginIndex struct {
		Plugins map[string][]struct {
			InstallPath string `json:"installPath"`
		} `json:"plugins"`
	}
	index, ok := readConfig(g, a.ID, filepath.Join(base, "plugins/installed_plugins.json"), parseJSON[pluginIndex])
	if !ok {
		return
	}
	for _, key := range keys(index.Plugins) {
		for _, entry := range index.Plugins[key] {
			if !within(filepath.Join(base, "plugins/cache"), entry.InstallPath) {
				g.skip()
				continue
			}
			type pluginMeta struct {
				Name string `json:"name"`
			}
			meta, ok := readConfig(g, a.ID, filepath.Join(entry.InstallPath, ".claude-plugin/plugin.json"), parseJSON[pluginMeta])
			if !ok {
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
			scratch := Agent{ID: a.ID, MCPServers: []MCPServer{}, Permissions: Permissions{Allow: []Grant{}}}
			path := filepath.Join(entry.InstallPath, ".mcp.json")
			if entries, ok := readConfig(g, a.ID, path, func(data []byte) (map[string]readers.MCP, error) { return readers.GenericMCP(data, "mcpServers") }); ok {
				g.servers(&scratch, entries, path, "plugin", nil)
			}
			plugin.MCPServers = len(scratch.MCPServers)
			a.Plugins = append(a.Plugins, plugin)
			if active {
				a.MCPServers = append(a.MCPServers, scratch.MCPServers...)
			}
		}
	}
}

// Merge by raw server name before redaction. Do not mutate cached parser results.
func (g *guard) layeredPermissions(a *Agent, base string, files []string, parse func([]byte) (readers.PermissionConfig, error)) {
	configs := make([]readers.PermissionConfig, len(files))
	owners := map[string]int{}
	for i, file := range files {
		if c, ok := readConfig(g, a.ID, filepath.Join(base, file), parse); ok {
			configs[i] = c
			if c.DefaultMode != "" {
				a.Permissions.DefaultMode = pointer(safe(c.DefaultMode, 128))
			}
			for name := range c.MCPServers {
				owners[name] = i
			}
		}
	}
	for i, c := range configs {
		entries := map[string]readers.MCP{}
		for name, server := range c.MCPServers {
			if owners[name] == i {
				entries[name] = server
			}
		}
		g.servers(a, entries, filepath.Join(base, files[i]), "user", nil)
	}
}

func (g *guard) catalogPlugins(a *Agent, root, manifest string, parse func([]byte) (string, error), states map[string]bool, defaultEnabled bool) {
	for _, entry := range g.entries(root) {
		if !entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
			continue
		}
		name, ok := readConfig(g, a.ID, filepath.Join(root, entry.Name(), manifest), parse)
		if !ok || name == "" {
			continue
		}
		enabled, present := states[name]
		if !present {
			enabled = defaultEnabled
		}
		if name = safe(name, 128); name != "" {
			a.Plugins = append(a.Plugins, Plugin{Name: name, Enabled: enabled})
		}
	}
}
