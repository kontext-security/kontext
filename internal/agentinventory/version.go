package agentinventory

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kontext-security/kontext/internal/privacyfolder"
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
	"antigravity":   {"Antigravity.app", "agy"},
	"kiro":          {"Kiro.app"},
	"goose":         {"Goose.app"},
}

// The machine-wide places apps and CLIs install to. Exported so a test in
// another package can keep the machine's own installs out of its fixture.
var (
	SystemAppDirs = []string{"/Applications"}
	SystemCLIDirs = []string{"/opt/homebrew/bin", "/usr/local/bin"}
)

var errPrivacyGuarded = fmt.Errorf("%w: privacy-guarded folder", os.ErrPermission)

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
	for _, dir := range appDirs(home) {
		plist := filepath.Join(dir, app, "Contents", "Info.plist")
		if privacyfolder.Guarded(home, plist) {
			continue
		}
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
	path, _ := findCLI(home, name, map[string]bool{})
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
	cmd.Env = append(os.Environ(), "PATH="+versionPath(home, binary))
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

// versionPath is the PATH a CLI's --version runs with: its own folder and the
// usual install folders, then the daemon's PATH. As in findCLI, a folder that
// is not absolute stays out: on Windows the unix system folders have no
// drive and would be taken on the current one.
func versionPath(home, binary string) string {
	dirs := []string{filepath.Dir(binary)}
	for _, dir := range cliDirs(home) {
		if filepath.IsAbs(dir) {
			dirs = append(dirs, dir)
		}
	}
	return strings.Join(append(dirs, os.Getenv("PATH")), string(os.PathListSeparator))
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

// findCLI also returns a lookup failure other than absence, so a caller can
// tell "not installed" from "could not check".
func findCLI(home, name string, clean map[string]bool) (string, error) {
	// On Windows LookPath answers for PATH first, as the shell resolves it. On
	// unix it reports an unreadable PATH folder as not found.
	if runtime.GOOS == "windows" {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	var failure error
	// The daemon runs with a minimal PATH (under launchd on macOS), hence the
	// fixed folders.
	for _, dir := range append(filepath.SplitList(os.Getenv("PATH")), cliDirs(home)...) {
		if !filepath.IsAbs(dir) {
			continue
		}
		for _, file := range programNames(name) {
			path := filepath.Join(dir, file)
			info, err := statCandidate(home, path, clean)
			if err == nil && isProgram(info) {
				return path, nil
			}
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				failure = err
			}
		}
	}
	if name == "claude" && runtime.GOOS == "darwin" {
		if path := desktopClaudeCode(home, clean); path != "" {
			return path, failure
		}
	}
	return "", failure
}

// desktopClaudeCode finds the Claude Code that Claude Desktop keeps for itself,
// with no claude command on any PATH: the program of the newest version folder
// that has one, under claude-code/<version>/<build>/claude.app.
func desktopClaudeCode(home string, clean map[string]bool) string {
	root := filepath.Join(home, "Library", "Application Support", "Claude", "claude-code")
	versions, _ := os.ReadDir(root)
	slices.SortFunc(versions, func(a, b os.DirEntry) int { return compareVersions(b.Name(), a.Name()) })
	for _, version := range versions {
		if !version.IsDir() || parseVersion(version.Name()) != version.Name() {
			continue
		}
		builds, _ := os.ReadDir(filepath.Join(root, version.Name()))
		for _, build := range builds {
			path := filepath.Join(root, version.Name(), build.Name(), "claude.app", "Contents", "MacOS", "claude")
			if info, err := statCandidate(home, path, clean); err == nil && isProgram(info) {
				return path
			}
		}
	}
	return ""
}

// compareVersions orders dotted versions by number: 2.1.10 after 2.1.9.
func compareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		x, _ := strconv.Atoi(as[i])
		y, _ := strconv.Atoi(bs[i])
		if x != y {
			return x - y
		}
	}
	return len(as) - len(bs)
}

// programNames lists the file names under which name is a program in a
// folder: the name itself on unix, and on Windows the name with each
// extension PATHEXT lists, since the extension makes a file a program there.
// Without PATHEXT it takes the extensions exec.LookPath falls back to.
func programNames(name string) []string {
	if runtime.GOOS != "windows" {
		return []string{name}
	}
	pathext := os.Getenv("PATHEXT")
	if pathext == "" {
		pathext = ".com;.exe;.bat;.cmd"
	}
	var names []string
	for _, ext := range strings.Split(pathext, ";") {
		if ext == "" {
			continue
		}
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		names = append(names, name+ext)
	}
	return names
}

// isProgram tells a program from another file: a regular file, on unix with
// an execute bit. Windows has no such bit; programNames picks by extension.
func isProgram(info os.FileInfo) bool {
	return info.Mode().IsRegular() && (runtime.GOOS == "windows" || info.Mode()&0o111 != 0)
}

// statCandidate never follows an install candidate into a privacy-guarded
// folder: the daemon would prompt in the background.
func statCandidate(home, path string, clean map[string]bool) (os.FileInfo, error) {
	if linkGuarded(home, path, clean) {
		return nil, errPrivacyGuarded
	}
	info, err := os.Stat(path)
	if errors.Is(err, syscall.ENOTDIR) {
		return nil, os.ErrNotExist
	}
	return info, err
}

func appDirs(home string) []string {
	return append(slices.Clone(SystemAppDirs), filepath.Join(home, "Applications"))
}

// agentInstalled locates an app bundle or CLI binary. An agent with no known
// location, or one Kontext could not check, is unknown rather than absent.
func agentInstalled(home, id string, clean map[string]bool) (Installed, error) {
	sources := versionSources[id]
	if len(sources) == 0 {
		return InstalledUnknown, nil
	}
	var failure error
	checkable := false
	for _, source := range sources {
		if !strings.HasSuffix(source, ".app") {
			checkable = true
			path, err := findCLI(home, source, clean)
			if path != "" {
				return InstalledYes, nil
			}
			if err != nil {
				failure = err
			}
			continue
		}
		if runtime.GOOS != "darwin" {
			continue
		}
		checkable = true
		for _, dir := range appDirs(home) {
			info, err := statCandidate(home, filepath.Join(dir, source), clean)
			if err == nil && info.IsDir() {
				return InstalledYes, nil
			}
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				failure = err
			}
		}
	}
	if failure != nil || !checkable {
		return InstalledUnknown, failure
	}
	return InstalledNo, nil
}

func cliDirs(home string) []string {
	return append(slices.Clone(SystemCLIDirs), filepath.Join(home, ".local", "bin"), filepath.Join(home, ".bun", "bin"), filepath.Join(home, ".npm-global", "bin"))
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
