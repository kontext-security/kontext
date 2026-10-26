package agentinventory

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// versionSources lists where each agent's version is read, in order: an app
// bundle's Info.plist (no agent code runs), or a CLI whose --version is cheap
// and has no side effects. Agents without an entry report no version.
var versionSources = map[string][]string{
	"claude_code":   {"claude"},
	"claude_cowork": {"Claude.app"},
	"codex":         {"codex", "Codex.app"},
	"gemini_cli":    {"gemini"},
	"cursor":        {"Cursor.app", "cursor-agent"},
	"windsurf":      {"Windsurf.app"},
	"copilot_cli":   {"copilot"},
	"opencode":      {"opencode", "OpenCode.app"},
	"antigravity":   {"Antigravity.app"},
	"kiro":          {"Kiro.app"},
	"goose":         {"Goose.app"},
}

var versionPattern = regexp.MustCompile(`\d+(?:\.\d+){1,3}(?:-[0-9A-Za-z.]+)?`)

// ponytail: per-process cache keyed by binary identity, so the daemon runs a
// CLI's --version once per install, not on every 10-minute scan.
var cliVersions sync.Map

// AddVersions fills in the version of each discovered agent it can read.
// App versions are read inline. A CLI's --version can take seconds to start,
// so it runs in the background and its result appears from the next scan on.
func AddVersions(ctx context.Context, home string, inv *Inventory) {
	for i := range inv.Agents {
		if version := agentVersion(ctx, home, inv.Agents[i].ID); version != "" {
			inv.Agents[i].Version = &version
		}
	}
}

func agentVersion(ctx context.Context, home, id string) string {
	for _, source := range versionSources[id] {
		var version string
		if strings.HasSuffix(source, ".app") {
			version = appVersion(ctx, home, source)
		} else {
			version = cliVersion(ctx, home, source)
		}
		if version != "" {
			return version
		}
	}
	return ""
}

func appVersion(ctx context.Context, home, app string) string {
	if runtime.GOOS != "darwin" {
		return ""
	}
	for _, dir := range []string{"/Applications", filepath.Join(home, "Applications")} {
		plist := filepath.Join(dir, app, "Contents", "Info.plist")
		if _, err := os.Stat(plist); err != nil {
			continue
		}
		out, err := exec.CommandContext(ctx, "/usr/bin/plutil", "-extract", "CFBundleShortVersionString", "raw", "-o", "-", plist).Output()
		if err == nil {
			return parseVersion(string(out))
		}
	}
	return ""
}

func cliVersion(_ context.Context, home, name string) string {
	// Never run a user's binaries as root.
	if os.Geteuid() == 0 {
		return ""
	}
	path := findCLI(home, name)
	if path == "" {
		return ""
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return ""
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	key := fmt.Sprintf("%s|%d|%d", resolved, info.Size(), info.ModTime().UnixNano())
	if cached, loaded := cliVersions.LoadOrStore(key, pending{}); loaded {
		version, _ := cached.(string)
		return version
	}
	go func() {
		version, err := runVersion(home, resolved)
		if err != nil {
			cliVersions.Delete(key) // try again on the next scan
			return
		}
		cliVersions.Store(key, version)
	}()
	return ""
}

// runVersion runs "<binary> --version" with a bounded lifetime and output.
// The CLI runs in its own process group so a timeout also stops anything it
// started, and with the CLI's own directory and the usual install
// directories on PATH, since launchd's PATH cannot find node or bun.
func runVersion(home, binary string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--version")
	out := &cappedBuffer{limit: 4096}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.Env = append(os.Environ(), "PATH="+strings.Join(append([]string{filepath.Dir(binary)}, cliDirs(home)...), ":")+":"+os.Getenv("PATH"))
	ownProcessGroup(cmd)
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if err != nil {
		return "", nil // ran and failed: no version for this binary
	}
	return parseVersion(out.String()), nil
}

// cappedBuffer keeps the first limit bytes and discards the rest, so a CLI
// that floods its output cannot grow the daemon's memory.
type cappedBuffer struct {
	limit int
	buf   []byte
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if room := b.limit - len(b.buf); room > 0 {
		b.buf = append(b.buf, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

func (b *cappedBuffer) String() string { return string(b.buf) }

// pending marks a CLI whose --version is still running.
type pending struct{}

func findCLI(home, name string) string {
	if path, err := exec.LookPath(name); err == nil {
		return path
	}
	// The daemon runs under launchd with a minimal PATH.
	for _, dir := range cliDirs(home) {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return path
		}
	}
	return ""
}

func cliDirs(home string) []string {
	return []string{"/opt/homebrew/bin", "/usr/local/bin", filepath.Join(home, ".local", "bin"), filepath.Join(home, ".bun", "bin"), filepath.Join(home, ".npm-global", "bin")}
}

// parseVersion takes the first version-like token, at most 64 characters:
// "2.1.300 (Claude Code)" → 2.1.300, "codex-cli 0.162.1" → 0.162.1.
func parseVersion(output string) string {
	version := versionPattern.FindString(output)
	if len(version) > 64 {
		return ""
	}
	return version
}
