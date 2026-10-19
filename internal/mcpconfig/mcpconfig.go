// Package mcpconfig finds the URL an agent's configuration gives an MCP
// server, so the tool catalog can identify the server by where it points
// instead of by the name the operator gave it. It reuses the agent config
// parsers in pkg/agentauthority/readers.
//
// Sources, highest precedence first:
//
//   - Claude Code: the managed managed-mcp.json (it takes exclusive control
//     when deployed), then for the hook's cwd and each parent directory the
//     local entry in ~/.claude.json (projects[dir].mcpServers) and the
//     project .mcp.json, nearest directory first, then the user
//     mcpServers in ~/.claude.json, then installed plugins' MCP servers.
//   - Claude Cowork: Claude Desktop's claude_desktop_config.json.
//   - Codex: config.toml [mcp_servers].
//
// A server that no source lists, a stdio server and a URL that does not
// parse all return "", and the catalog falls back to the server name.
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

// Resolver caches parsed config files by modification time and size, so a
// hook pays one stat per file unless the file changed. It is safe for
// concurrent use. The zero value reads the current user's home directory
// and the system managed config.
type Resolver struct {
	Home    string
	Managed string

	mu    sync.Mutex
	cache map[string]cachedFile
}

type cachedFile struct {
	modTime time.Time
	size    int64
	value   any
	ok      bool
}

// ServerURL returns the configured URL of the MCP server behind toolName
// (mcp__<server>__<tool>) for the agent that reported it, or "".
func (r *Resolver) ServerURL(agent, cwd, toolName string) string {
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
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cache == nil {
		r.cache = map[string]cachedFile{}
	}
	switch agent {
	case "claude", "claude-code", "claude_code":
		return r.claude(home, cwd, server)
	case "cowork", "claude-cowork", "claude_cowork":
		return find(r.servers(filepath.Join(home, "Library/Application Support/Claude/claude_desktop_config.json")), server)
	case "codex":
		dir := os.Getenv("CODEX_HOME")
		if dir == "" {
			dir = filepath.Join(home, ".codex")
		}
		config, _ := load(r, filepath.Join(dir, "config.toml"), readers.Codex)
		return find(config.MCPServers, server)
	}
	return ""
}

func (r *Resolver) claude(home, cwd, server string) string {
	managed := r.Managed
	if managed == "" {
		managed = ManagedMCPPath
	}
	if url := find(r.servers(managed), server); url != "" {
		return url
	}
	configDir := filepath.Join(home, ".claude")
	userConfig := filepath.Join(home, ".claude.json")
	if dir := os.Getenv("CLAUDE_CONFIG_DIR"); dir != "" {
		configDir = dir
		userConfig = filepath.Join(dir, ".claude.json")
	}
	root, _ := load(r, userConfig, readers.Claude)
	if filepath.IsAbs(cwd) {
		for dir := filepath.Clean(cwd); ; dir = filepath.Dir(dir) {
			if url := find(root.Projects[dir].MCPServers, server); url != "" {
				return url
			}
			if url := find(r.servers(filepath.Join(dir, ".mcp.json")), server); url != "" {
				return url
			}
			if dir == filepath.Dir(dir) {
				break
			}
		}
	}
	if url := find(root.MCPServers, server); url != "" {
		return url
	}
	return r.plugin(configDir, server)
}

// plugin resolves a plugin's MCP server, which Claude Code names
// plugin_<plugin>_<server>.
func (r *Resolver) plugin(configDir, server string) string {
	if !strings.HasPrefix(server, "plugin_") {
		return ""
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
				if url := find(r.servers(filepath.Join(path, file)), name); url != "" {
					return url
				}
			}
		}
	}
	return ""
}

func (r *Resolver) servers(path string) map[string]readers.MCP {
	servers, _ := load(r, path, func(data []byte) (map[string]readers.MCP, error) {
		return readers.GenericMCP(data, "mcpServers")
	})
	return servers
}

// find returns the URL of the configured server whose name the agent turns
// into server. Claude Code and Codex replace every character outside
// [A-Za-z0-9_-] with "_" in tool names.
func find(servers map[string]readers.MCP, server string) string {
	if config, ok := servers[server]; ok {
		return strings.TrimSpace(config.URL)
	}
	for name, config := range servers {
		if normalize(name) == server {
			return strings.TrimSpace(config.URL)
		}
	}
	return ""
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
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxConfigBytes {
		delete(r.cache, key)
		return zero, false
	}
	if cached, ok := r.cache[key]; ok && cached.modTime.Equal(info.ModTime()) && cached.size == info.Size() {
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
