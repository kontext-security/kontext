// Package mcpconfig finds the URL an agent's configuration gives an MCP
// server, so the tool catalog can identify the server by where it points
// instead of by the name the operator gave it. It reuses the agent config
// parsers in pkg/agentauthority/readers.
//
// Sources, highest precedence first:
//
//   - Claude Code: the managed managed-mcp.json (it takes exclusive control
//     when deployed), then the session project's local entry in
//     ~/.claude.json (projects[dir].mcpServers) and its .mcp.json, then the
//     user mcpServers in ~/.claude.json, then installed plugins' MCP
//     servers. The project is the deepest directory at or above the hook's
//     cwd that ~/.claude.json records.
//   - Claude Cowork: Claude Desktop's claude_desktop_config.json.
//   - Codex: config.toml [mcp_servers].
//
// The first source that defines a server wins whole, so a stdio entry
// shadows a URL in a lower scope. A server that no source lists, a stdio
// server, a URL that does not parse and a lookup that stalls all return "",
// and the catalog falls back to the server name.
package mcpconfig

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kontext-security/kontext/pkg/agentauthority/readers"
)

// ManagedMCPPath is where Claude Code reads the managed MCP config on macOS.
const ManagedMCPPath = "/Library/Application Support/ClaudeCode/managed-mcp.json"

// maxConfigBytes bounds one config read. ~/.claude.json grows with history.
const maxConfigBytes = 64 << 20

// lookupTimeout bounds one lookup, so a config on a stalled mount (a
// network drive, an evicted cloud file) costs a hook this long at most.
// maxLookups bounds the lookups still blocked on such a file.
const (
	lookupTimeout = 250 * time.Millisecond
	maxLookups    = 4
)

// Resolver caches parsed config files by modification time and size, so a
// hook pays one stat per file unless the file changed. It is safe for
// concurrent use. The zero value reads the current user's home directory
// and the system managed config.
type Resolver struct {
	Home    string
	Managed string

	mu      sync.Mutex
	cache   map[string]cachedFile
	once    sync.Once
	lookups chan struct{}
}

type cachedFile struct {
	modTime time.Time
	size    int64
	value   any
	ok      bool
}

// ServerURL returns the configured URL of the MCP server behind toolName
// (mcp__<server>__<tool>) for the agent that reported it, or "". A lookup
// that does not finish within lookupTimeout returns "".
func (r *Resolver) ServerURL(agent, cwd, toolName string) string {
	if !strings.HasPrefix(toolName, "mcp__") {
		return ""
	}
	r.once.Do(func() { r.lookups = make(chan struct{}, maxLookups) })
	timer := time.NewTimer(lookupTimeout)
	defer timer.Stop()
	select {
	case r.lookups <- struct{}{}:
	case <-timer.C:
		return ""
	}
	result := make(chan string, 1)
	go func() {
		defer func() { <-r.lookups }()
		result <- r.lookup(agent, cwd, toolName)
	}()
	select {
	case url := <-result:
		return url
	case <-timer.C:
		return ""
	}
}

func (r *Resolver) lookup(agent, cwd, toolName string) string {
	rest, ok := strings.CutPrefix(toolName, "mcp__")
	if !ok {
		return ""
	}
	server, _, ok := strings.Cut(rest, "__")
	if !ok || server == "" {
		return ""
	}
	home := r.Home
	if home == "" {
		var err error
		if home, err = os.UserHomeDir(); err != nil {
			return ""
		}
	}
	switch agent {
	case "claude", "claude-code", "claude_code":
		return r.claude(home, cwd, server)
	case "cowork", "claude-cowork", "claude_cowork":
		url, _ := find(r.servers(filepath.Join(home, "Library/Application Support/Claude/claude_desktop_config.json")), server)
		return url
	case "codex":
		dir := os.Getenv("CODEX_HOME")
		if dir == "" {
			dir = filepath.Join(home, ".codex")
		}
		config, _ := load(r, filepath.Join(dir, "config.toml"), readers.Codex)
		url, _ := find(config.MCPServers, server)
		return url
	}
	return ""
}

func (r *Resolver) claude(home, cwd, server string) string {
	managed := r.Managed
	if managed == "" {
		managed = ManagedMCPPath
	}
	// The first source that defines the server wins whole, as in Claude
	// Code: a stdio entry shadows a URL in a lower scope.
	if url, found := find(r.servers(managed), server); found {
		return url
	}
	configDir := filepath.Join(home, ".claude")
	userConfig := filepath.Join(home, ".claude.json")
	if dir := os.Getenv("CLAUDE_CONFIG_DIR"); dir != "" {
		configDir = dir
		userConfig = filepath.Join(dir, ".claude.json")
	}
	root, _ := load(r, userConfig, readers.Claude)
	project := projectRoot(root, cwd)
	url, found := r.claudeScopes(root, configDir, project, server)
	if !filepath.IsAbs(cwd) {
		return url
	}
	// Local and project scope belong to the session's project, taken as the
	// deepest directory Claude Code has recorded in ~/.claude.json. Another
	// ancestor that defines the server differently may be the real project
	// (a launch in a subdirectory), so the URL is then unknown.
	for dir := filepath.Clean(cwd); ; dir = filepath.Dir(dir) {
		for _, scope := range r.projectScopes(root, dir) {
			if dir == project {
				break
			}
			if otherURL, defines := find(scope, server); defines && (!found || otherURL != url) {
				return ""
			}
		}
		if dir == filepath.Dir(dir) {
			break
		}
	}
	return url
}

// claudeScopes resolves server through the session project's local and
// project scope, then user scope, then plugins.
func (r *Resolver) claudeScopes(root readers.ClaudeRoot, configDir, project, server string) (string, bool) {
	if project != "" {
		for _, scope := range r.projectScopes(root, project) {
			if url, found := find(scope, server); found {
				return url, true
			}
		}
	}
	if url, found := find(root.MCPServers, server); found {
		return url, true
	}
	return r.plugin(configDir, server)
}

// projectScopes returns dir's local entries in ~/.claude.json and its
// .mcp.json, in Claude Code's precedence.
func (r *Resolver) projectScopes(root readers.ClaudeRoot, dir string) []map[string]readers.MCP {
	return []map[string]readers.MCP{root.Projects[dir].MCPServers, r.servers(filepath.Join(dir, ".mcp.json"))}
}

func projectRoot(root readers.ClaudeRoot, cwd string) string {
	if !filepath.IsAbs(cwd) {
		return ""
	}
	for dir := filepath.Clean(cwd); ; dir = filepath.Dir(dir) {
		if _, ok := root.Projects[dir]; ok {
			return dir
		}
		if dir == filepath.Dir(dir) {
			return ""
		}
	}
}

// plugin resolves a plugin's MCP server, which Claude Code names
// plugin_<plugin>_<server>. Installed records do not say which installation
// of a plugin name is active, so when installations disagree about the
// server the URL is unknown.
func (r *Resolver) plugin(configDir, server string) (string, bool) {
	if !strings.HasPrefix(server, "plugin_") {
		return "", false
	}
	type installed struct {
		Plugins map[string][]struct {
			InstallPath string `json:"installPath"`
		} `json:"plugins"`
	}
	type manifest struct {
		Name string `json:"name"`
	}
	index, _ := load(r, filepath.Join(configDir, "plugins/installed_plugins.json"), parseJSON[installed])
	cacheDir := filepath.Join(configDir, "plugins/cache") + string(filepath.Separator)
	urls := map[string]bool{}
	for _, entries := range index.Plugins {
		for _, entry := range entries {
			// Read only inside the plugin cache, never a path a file names.
			path := filepath.Clean(entry.InstallPath)
			if !strings.HasPrefix(path, cacheDir) {
				continue
			}
			meta, ok := load(r, filepath.Join(path, ".claude-plugin/plugin.json"), parseJSON[manifest])
			if !ok || meta.Name == "" {
				continue
			}
			prefix := "plugin_" + normalize(meta.Name) + "_"
			name, ok := strings.CutPrefix(server, prefix)
			if !ok {
				continue
			}
			// A plugin declares servers in .mcp.json or inline in plugin.json.
			for _, file := range []string{".mcp.json", ".claude-plugin/plugin.json"} {
				if url, found := find(r.servers(filepath.Join(path, file)), name); found {
					urls[url] = true
					break
				}
			}
		}
	}
	if len(urls) != 1 {
		return "", len(urls) > 1
	}
	for url := range urls {
		return url, true
	}
	return "", false
}

func (r *Resolver) servers(path string) map[string]readers.MCP {
	servers, _ := load(r, path, func(data []byte) (map[string]readers.MCP, error) {
		return readers.GenericMCP(data, "mcpServers")
	})
	return servers
}

// find returns the URL of the configured server whose name the agent turns
// into server ("" for a stdio server), and whether one is configured.
// Claude Code and Codex replace every character outside [A-Za-z0-9_-] with
// "_" in tool names; two names that normalize alike leave the URL unknown.
func find(servers map[string]readers.MCP, server string) (string, bool) {
	if config, ok := servers[server]; ok {
		return strings.TrimSpace(config.URL), true
	}
	url, found := "", false
	for name, config := range servers {
		if normalize(name) != server {
			continue
		}
		if found && strings.TrimSpace(config.URL) != url {
			return "", true
		}
		url, found = strings.TrimSpace(config.URL), true
	}
	return url, found
}

func normalize(name string) string {
	return strings.Map(func(r rune) rune {
		if r == '_' || r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return '_'
	}, name)
}

// load reads and parses path through the cache. Missing, unreadable,
// oversized and malformed files yield the zero value: a config the daemon
// cannot read leaves the server unidentified, never fails the hook.
func load[T any](r *Resolver, path string, parse func([]byte) (T, error)) (T, bool) {
	var zero T
	// One file can be read as two shapes (plugin.json), so the key has both.
	key := fmt.Sprintf("%s\x00%T", path, zero)
	info, err := os.Stat(path)
	r.mu.Lock()
	if r.cache == nil {
		r.cache = map[string]cachedFile{}
	}
	cached, hit := r.cache[key]
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxConfigBytes {
		delete(r.cache, key)
		r.mu.Unlock()
		return zero, false
	}
	r.mu.Unlock()
	if hit && cached.modTime.Equal(info.ModTime()) && cached.size == info.Size() {
		value, _ := cached.value.(T)
		return value, cached.ok
	}
	value, err := readFile(path)
	var parsed T
	ok := err == nil
	if ok {
		parsed, err = parse(value)
		ok = err == nil
	}
	if !ok {
		parsed = zero
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[key] = cachedFile{modTime: info.ModTime(), size: info.Size(), value: parsed, ok: ok}
	return parsed, ok
}

// readFile opens without blocking, so a FIFO planted as .mcp.json in a
// project cannot stall the hook, and reads only regular files.
func readFile(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, os.ErrInvalid
	}
	return io.ReadAll(io.LimitReader(file, maxConfigBytes))
}

func parseJSON[T any](data []byte) (T, error) {
	var value T
	err := json.Unmarshal(data, &value)
	return value, err
}
