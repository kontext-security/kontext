package agentinventory

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Scan never opens activity files. Hook evaluators are injected by the daemon
// (also used by setup), keeping discovery independent of managedstream.
func Scan(ctx context.Context, home string, env func(string) string, now time.Time, wired map[string]func() Wired) Inventory {
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
			if info.IsDir() {
				config = candidate
				break
			}
		}
		if config == "" {
			continue
		}
		path := config
		if rel, err := filepath.Rel(home, config); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			path = "~"
			if rel != "." {
				path += "/" + filepath.ToSlash(rel)
			}
		}
		// Do not truncate a path into a different location or reject the whole
		// heartbeat at the API's 1024-character boundary.
		if len(path) > 1024 {
			continue
		}
		agent := Agent{ID: descriptor.ID, ConfigPath: path, Wired: WiredUnsupported}
		if descriptor.ID == "claude_code" || descriptor.ID == "claude_cowork" || descriptor.ID == "codex" {
			agent.Wired = WiredError
			if evaluate := wired[descriptor.ID]; evaluate != nil {
				agent.Wired = evaluate()
			}
		}
		if descriptor.ActivityRoot != "" {
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
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			incomplete = true
			return fs.SkipAll
		}
		if err != nil {
			if entry != nil && entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if rel != "." {
			visited++
			if visited > 2000 {
				incomplete = true
				return fs.SkipAll
			}
		}
		if !entry.IsDir() && entry.Type() != 0 {
			return nil
		}
		info, err := entry.Info()
		if err == nil && (info.IsDir() || info.Mode().IsRegular()) && info.ModTime().After(newest) {
			newest = info.ModTime()
		}
		if entry.IsDir() && rel != "." && strings.Count(rel, string(filepath.Separator))+1 >= 4 {
			return fs.SkipDir
		}
		return nil
	})
	incomplete = incomplete || ctx.Err() != nil
	if newest.IsZero() {
		return nil, incomplete
	}
	stamp := newest.UTC().Format(time.RFC3339)
	return &stamp, incomplete
}
