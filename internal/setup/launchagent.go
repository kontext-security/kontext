package setup

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kontext-security/kontext-cli/internal/managedobserve"
)

// LaunchAgentLabel matches the enterprise LaunchAgent so the hook-side
// kickstart (managedobserve.Lifecycle) works identically for both install
// kinds. The refusal gate in Run keeps the two from coexisting on one Mac.
const LaunchAgentLabel = managedobserve.DefaultLaunchdLabel

const launchctlCommandTimeout = 15 * time.Second

func launchAgentPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", LaunchAgentLabel+".plist"), nil
}

func logFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Logs", "Kontext", "managed-observe.log"), nil
}

// renderLaunchAgentPlist produces the user LaunchAgent. KeepAlive + a 30s
// throttle keeps the pipeline always-on (matching the enterprise agent)
// without thrashing if the config is removed out from under the daemon;
// RunAtLoad covers login, and the hook-side kickstart covers everything else.
// localLLMAgentConfig is the resolved local-model opt-in. Nil means the agent
// runs without it.
//
// Every field is forwarded into the agent's environment, and that is the whole
// point: launchd does not inherit the shell, so any judge configuration an
// operator exported when running setup is invisible to the daemon. Resolving it
// once here and passing it through is what makes setup's pre-fetch and the
// daemon agree on which weights, which revision and which cache — rather than
// both reading an environment only one of them can see.
type localLLMAgentConfig struct {
	// ServerBinary is absolute, because launchd's minimal PATH excludes Homebrew.
	ServerBinary string
	HFRepo       string
	HFFile       string
	HFRevision   string
	CacheDir     string
}

// agentEnvironment renders the opt-in as plist environment entries, omitting
// anything unset so a default install stays byte-identical.
func (c *localLLMAgentConfig) agentEnvironment() string {
	if c == nil {
		return ""
	}
	entries := []struct{ key, value string }{
		{"KONTEXT_JUDGE_MANAGED", "1"},
		{"KONTEXT_JUDGE_SERVER_BIN", c.ServerBinary},
		{"KONTEXT_JUDGE_HF_REPO", c.HFRepo},
		{"KONTEXT_JUDGE_HF_FILE", c.HFFile},
		{"KONTEXT_JUDGE_HF_REVISION", c.HFRevision},
		{"KONTEXT_JUDGE_CACHE_DIR", c.CacheDir},
	}
	var rendered strings.Builder
	for _, entry := range entries {
		if strings.TrimSpace(entry.value) == "" {
			continue
		}
		rendered.WriteString("\n\t\t<key>" + entry.key + "</key>\n\t\t<string>" + xmlEscape(entry.value) + "</string>")
	}
	return rendered.String()
}

func renderLaunchAgentPlist(binary, logPath string, llm *localLLMAgentConfig) string {
	// The opt-in lives in the agent's environment rather than a config file:
	// launchd already owns the daemon's env, and the daemon reads exactly these
	// variables, so there is no second place for the two to disagree.
	localLLM := llm.agentEnvironment()
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + xmlEscape(LaunchAgentLabel) + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + xmlEscape(binary) + `</string>
		<string>managed-observe-daemon</string>
	</array>
	<key>EnvironmentVariables</key>
	<dict>
		<key>KONTEXT_EXPECTED_CONFIG_SCOPE</key>
		<string>user</string>` + localLLM + `
	</dict>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>30</integer>
	<key>ProcessType</key>
	<string>Background</string>
	<key>StandardOutPath</key>
	<string>` + xmlEscape(logPath) + `</string>
	<key>StandardErrorPath</key>
	<string>` + xmlEscape(logPath) + `</string>
</dict>
</plist>
`
}

func xmlEscape(value string) string {
	var builder strings.Builder
	_ = xml.EscapeText(&builder, []byte(value))
	return builder.String()
}

// installLaunchAgent writes the plist and (re)starts the agent in the user's
// GUI launchd domain — no sudo anywhere. Bootout failure is expected on first
// install; bootstrap failure usually means no GUI session (SSH).
func installLaunchAgent(ctx context.Context, binary string, llm *localLLMAgentConfig) (plistPath, logPath string, err error) {
	plistPath, err = launchAgentPath()
	if err != nil {
		return "", "", err
	}
	logPath, err = logFilePath()
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(filepath.Dir(plistPath), 0o755); err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(plistPath, []byte(renderLaunchAgentPlist(binary, logPath, llm)), 0o644); err != nil {
		return "", "", err
	}

	domainTarget := "gui/" + strconv.Itoa(os.Getuid())
	serviceTarget := domainTarget + "/" + LaunchAgentLabel

	// Not loaded on first install is fine. For re-runs, unload the exact
	// self-serve plist setup owns before bootstrapping the replacement. This
	// keeps a machine linked to an older workspace from keeping the old job
	// loaded while setup writes the new config.
	if out, err := runLaunchctl(ctx, "bootout", domainTarget, plistPath); err != nil {
		loaded, printErr := launchAgentLoaded(ctx, serviceTarget, true)
		if printErr != nil {
			return "", "", fmt.Errorf("launchctl bootout failed before reload and service state is unknown: %w (%s)", err, strings.TrimSpace(out))
		}
		if loaded {
			return "", "", fmt.Errorf("launchctl bootout failed before reload: %w (%s)", err, strings.TrimSpace(out))
		}
	}

	if out, err := runLaunchctl(ctx, "bootstrap", domainTarget, plistPath); err != nil {
		detail := strings.TrimSpace(out)
		if strings.Contains(detail, "Input/output error") {
			return "", "", fmt.Errorf("launchctl bootstrap failed (%s) — this usually means no GUI login session; run `kontext setup` from a logged-in desktop session, not SSH", detail)
		}
		return "", "", fmt.Errorf("launchctl bootstrap failed: %w (%s)", err, detail)
	}
	return plistPath, logPath, nil
}

// StopLaunchAgent unloads the self-serve agent but LEAVES the plist in place,
// so a later BootstrapLaunchAgent brings it back. Profile switching and
// migration need this pause: the daemon holds the ledger database open, and
// moving or re-pointing that database under a live writer is what a switch
// must never do. Already-unloaded and never-installed are both success.
func StopLaunchAgent(ctx context.Context) error {
	plistPath, err := launchAgentPath()
	if err != nil {
		return err
	}
	if _, err := os.Lstat(plistPath); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	domainTarget := "gui/" + strconv.Itoa(os.Getuid())
	serviceTarget := domainTarget + "/" + LaunchAgentLabel
	if out, err := runLaunchctl(ctx, "bootout", domainTarget, plistPath); err != nil {
		// Distinguish "was not loaded" (fine) from "refused to unload" (fatal):
		// continuing past a live daemon would move its database out from under it.
		loaded, printErr := launchAgentLoaded(ctx, serviceTarget, true)
		if printErr != nil {
			return fmt.Errorf("launchctl bootout failed and service state is unknown: %w (%s)", err, strings.TrimSpace(out))
		}
		if loaded {
			return fmt.Errorf("launchctl bootout failed and the background agent is still loaded: %w (%s)", err, strings.TrimSpace(out))
		}
	}
	return nil
}

// BootstrapLaunchAgent reloads the already-written plist. A missing plist is
// not an error: a machine mid-setup simply has no agent to start yet.
func BootstrapLaunchAgent(ctx context.Context) error {
	plistPath, err := launchAgentPath()
	if err != nil {
		return err
	}
	if _, err := os.Lstat(plistPath); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	domainTarget := "gui/" + strconv.Itoa(os.Getuid())
	if out, err := runLaunchctl(ctx, "bootstrap", domainTarget, plistPath); err != nil {
		detail := strings.TrimSpace(out)
		if strings.Contains(detail, "Input/output error") {
			return fmt.Errorf("launchctl bootstrap failed (%s) — this usually means no GUI login session; run this from a logged-in desktop session, not SSH", detail)
		}
		return fmt.Errorf("launchctl bootstrap failed: %w (%s)", err, detail)
	}
	return nil
}

func runLaunchctl(ctx context.Context, args ...string) (string, error) {
	launchCtx, cancel := context.WithTimeout(ctx, launchctlCommandTimeout)
	defer cancel()

	out, err := execCommand(launchCtx, "", "launchctl", args...)
	if launchCtx.Err() != nil {
		return out, launchCtx.Err()
	}
	return out, err
}

func launchAgentLoaded(ctx context.Context, serviceTarget string, bounded bool) (bool, error) {
	var (
		out string
		err error
	)
	if bounded {
		out, err = runLaunchctl(ctx, "print", serviceTarget)
	} else {
		out, err = execCommand(ctx, "", "launchctl", "print", serviceTarget)
	}
	if err == nil {
		return true, nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false, fmt.Errorf("launchctl print failed: %w (%s)", err, strings.TrimSpace(out))
	}
	if launchctlPrintMeansAbsent(out) {
		return false, nil
	}
	return false, fmt.Errorf("launchctl print failed: %w (%s)", err, strings.TrimSpace(out))
}

func launchctlPrintMeansAbsent(output string) bool {
	normalized := strings.ToLower(output)
	return strings.Contains(normalized, "could not find service") ||
		strings.Contains(normalized, "service is not loaded") ||
		strings.Contains(normalized, "no such service")
}

// removeLaunchAgent reverses installLaunchAgent; both steps tolerate
// already-removed state. Bootout targets OUR plist by path, not the shared
// label: if an MDM install's agent holds the same label, a label-target
// bootout could unload the wrong service (or "succeed" while our daemon
// keeps streaming with the token still in memory).
func removeLaunchAgent(ctx context.Context) (string, error) {
	plistPath, err := launchAgentPath()
	if err != nil {
		return "", err
	}
	domainTarget := "gui/" + strconv.Itoa(os.Getuid())
	serviceTarget := domainTarget + "/" + LaunchAgentLabel
	plistExists := true
	if _, err := os.Lstat(plistPath); errors.Is(err, os.ErrNotExist) {
		plistExists = false
	} else if err != nil {
		return "", err
	}
	if out, err := execCommand(ctx, "", "launchctl", "bootout", domainTarget, plistPath); err != nil {
		if plistExists {
			return "", fmt.Errorf("launchctl bootout failed: %w (%s)", err, strings.TrimSpace(out))
		}
		loaded, printErr := launchAgentLoaded(ctx, serviceTarget, false)
		if printErr != nil {
			return "", fmt.Errorf("launchctl bootout failed and %s state is unknown: %w", LaunchAgentLabel, printErr)
		}
		if loaded {
			return "", fmt.Errorf("launchctl bootout failed and %s is still loaded: %w (%s)", LaunchAgentLabel, err, strings.TrimSpace(out))
		}
	}
	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return "", err
	}
	return plistPath, nil
}
