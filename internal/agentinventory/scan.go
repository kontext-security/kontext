package agentinventory

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type ScanOptions struct {
	Wired                  map[string]func() Wired
	HasCoworkSessionsSince func(time.Time) (bool, error)
}

// Scan reads activity metadata and the guarded Cowork VM log tail. The daemon
// injects hook and session facts, keeping discovery independent of its store.
func Scan(ctx context.Context, home string, env func(string) string, now time.Time, opts ScanOptions) Inventory {
	inv := Inventory{Agents: []Agent{}, ReportedAt: now.UTC().Format(time.RFC3339)}
	for _, descriptor := range Catalog {
		if ctx.Err() != nil {
			inv.Incomplete = true
			break
		}
		var config string
		for _, candidate := range configDirs(descriptor, home, env) {
			info, err := os.Stat(candidate)
			if err != nil {
				continue
			}
			if info.IsDir() || (descriptor.ID == "claude_cowork" && info.Mode().IsRegular() && candidate == filepath.Join(home, coworkVMLog)) {
				config = candidate
				break
			}
		}
		if config == "" {
			continue
		}
		path := config
		if rel, err := filepath.Rel(home, config); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			path = "~/"
			if rel != "." {
				path += filepath.ToSlash(rel)
			}
		}
		// Do not truncate a path into a different location or reject the whole
		// heartbeat at the API's 1024-character boundary.
		if len(path) > 1024 {
			continue
		}
		agent := Agent{ID: descriptor.ID, ConfigPath: path, Wired: WiredUnsupported}
		if descriptor.ID == "claude_cowork" {
			agent.Sandboxed = coworkSandbox(ctx, home, now, opts.HasCoworkSessionsSince)
		}
		if descriptor.ID == "claude_code" || descriptor.ID == "claude_cowork" || descriptor.ID == "codex" {
			agent.Wired = WiredError
			if evaluate := opts.Wired[descriptor.ID]; evaluate != nil {
				agent.Wired = evaluate()
			}
		}
		if descriptor.ActivityRoot != "" && (descriptor.ID != "claude_cowork" || config == filepath.Join(home, coworkHostSessions)) {
			root := descriptor.ActivityRoot
			if strings.HasPrefix(root, "<config>") {
				root = filepath.Join(config, strings.TrimPrefix(strings.TrimPrefix(root, "<config>"), "/"))
			} else if descriptor.ID == "opencode" && envValue(env, "XDG_DATA_HOME") != "" {
				root = filepath.Join(expand(home, envValue(env, "XDG_DATA_HOME")), "opencode/storage")
			} else {
				root = filepath.Join(home, root)
			}
			var incomplete bool
			agent.LastActivityAt, incomplete = lastActivity(ctx, root)
			inv.Incomplete = inv.Incomplete || incomplete
		}
		inv.Agents = append(inv.Agents, agent)
	}
	if ctx.Err() != nil {
		inv.Incomplete = true
	}
	return inv
}

func envValue(env func(string) string, key string) string {
	if env == nil || key == "" {
		return ""
	}
	return strings.TrimSpace(env(key))
}

func expand(home, path string) string {
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

func configDirs(d Descriptor, home string, env func(string) string) []string {
	if d.ID == "cline" {
		if dataDir := envValue(env, "CLINE_DATA_DIR"); dataDir != "" {
			return []string{expand(home, dataDir)}
		}
	}
	value := envValue(env, d.ConfigEnv)
	if value != "" {
		base := expand(home, value)
		switch d.ConfigEnv {
		case "GEMINI_CLI_HOME":
			return []string{filepath.Join(base, ".gemini")}
		case "XDG_CONFIG_HOME":
			return []string{filepath.Join(base, strings.TrimPrefix(d.ConfigDirs[0], ".config/"))}
		case "CRUSH_GLOBAL_CONFIG":
			return []string{filepath.Dir(base)}
		case "KIRO_HOME":
			return []string{base, filepath.Join(home, ".kiro")}
		default:
			return []string{base}
		}
	}
	if d.ID == "opencode" || d.ID == "crush" {
		if xdg := envValue(env, "XDG_CONFIG_HOME"); xdg != "" {
			return []string{filepath.Join(expand(home, xdg), d.ID)}
		}
	}
	if d.ID == "openclaw" {
		if base := envValue(env, "OPENCLAW_HOME"); base != "" && base != "undefined" && base != "null" {
			home = expand(home, base)
		}
	}
	paths := make([]string, 0, len(d.ConfigDirs))
	for _, rel := range d.ConfigDirs {
		paths = append(paths, filepath.Join(home, rel))
	}
	return paths
}

func lastActivity(ctx context.Context, root string) (*string, bool) {
	ctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	var newest time.Time
	var incomplete bool
	visited := 0
	info, err := os.Lstat(root)
	if err != nil || (!info.IsDir() && !info.Mode().IsRegular()) {
		return nil, ctx.Err() != nil
	}
	newest = info.ModTime()
	var walk func(string, int)
	walk = func(dir string, depth int) {
		if incomplete || ctx.Err() != nil {
			incomplete = true
			return
		}
		file, err := os.Open(dir)
		if err != nil {
			return
		}
		defer file.Close()
		var directories []fs.FileInfo
		for {
			if ctx.Err() != nil {
				incomplete = true
				return
			}
			// Bound reads as well as metadata work, including very wide roots.
			entries, readErr := file.ReadDir(min(64, 2001-visited))
			for _, entry := range entries {
				visited++
				if visited > 2000 || ctx.Err() != nil {
					incomplete = true
					return
				}
				if !entry.IsDir() && entry.Type() != 0 {
					continue
				}
				info, err := entry.Info()
				if err != nil || (!info.IsDir() && !info.Mode().IsRegular()) {
					continue
				}
				if info.ModTime().After(newest) {
					newest = info.ModTime()
				}
				if info.IsDir() && depth+1 < 4 {
					directories = append(directories, info)
				}
			}
			if readErr != nil {
				break
			}
		}
		// ponytail: directory mtimes prioritize the bounded sample, not prove
		// subtree freshness. Never prune an old directory based on its mtime:
		// appending to an existing transcript leaves that directory unchanged.
		sort.Slice(directories, func(i, j int) bool {
			if directories[i].ModTime().Equal(directories[j].ModTime()) {
				return directories[i].Name() < directories[j].Name()
			}
			return directories[i].ModTime().After(directories[j].ModTime())
		})
		for _, child := range directories {
			walk(filepath.Join(dir, child.Name()), depth+1)
			if incomplete {
				return
			}
		}
	}
	if info.IsDir() {
		walk(root, 0)
	}
	incomplete = incomplete || ctx.Err() != nil
	if newest.IsZero() {
		return nil, incomplete
	}
	stamp := newest.UTC().Format(time.RFC3339)
	return &stamp, incomplete
}
