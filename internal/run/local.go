package run

import (
	"context"
	"fmt"
	"os"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/runtimehost"
	"github.com/kontext-security/kontext-cli/internal/startupui"
)

// StartLocal launches an agent with a wrapper-owned local runtime.
func StartLocal(ctx context.Context, opts Options) error {
	diagnostics := diagnostic.New(os.Stderr, opts.Verbose || diagnostic.EnabledFromEnv())
	diagnostics.Printf("start local: agent=%s\n", opts.Agent)

	agentPath, err := preflightAgent(opts.Agent)
	if err != nil {
		return err
	}
	diagnostics.Printf("agent preflight: %s -> %s\n", opts.Agent, agentPath)

	mode, err := runtimehost.ResolveMode(os.Getenv("KONTEXT_MODE"))
	if err != nil {
		return err
	}
	cwd, _ := os.Getwd()
	ui := startupui.New(os.Stderr)
	ui.Header()
	host, err := runtimehost.Start(ctx, runtimehost.Options{
		AgentName:             opts.Agent,
		CWD:                   cwd,
		DBPath:                os.Getenv("KONTEXT_DB"),
		JudgeConfigFromEnv:    true,
		JudgeManagedDefault:   true,
		JudgeDownloadProgress: ui.HandleDownloadProgress,
		Mode:                  mode,
		Diagnostic:            diagnostics,
	})
	if err != nil {
		return err
	}
	defer func() {
		_ = host.Close(context.Background())
	}()

	kontextBin, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve kontext executable: %w", err)
	}
	settingsPath, err := GenerateLocalSettings(host.SessionDir, kontextBin, opts.Agent, host.SocketPath, string(host.Mode))
	if err != nil {
		return fmt.Errorf("generate settings: %w", err)
	}

	env := append(os.Environ(), "KONTEXT_RUN=1")
	env = append(env, "KONTEXT_SOCKET="+host.SocketPath)
	env = append(env, "KONTEXT_SESSION_ID="+host.SessionID)
	env = append(env, "KONTEXT_MODE="+string(host.Mode))

	ui.LocalJudgeReady(host.LocalJudgeEnabled, host.LocalJudgeUnavailable)
	ui.Mode(string(host.Mode))
	ui.LocalSessionReady()
	ui.Launching(opts.Agent)
	if err := ui.Err(); err != nil {
		return fmt.Errorf("write startup output: %w", err)
	}

	return launchAgentWithSettings(ctx, opts.Agent, agentPath, env, opts.Args, settingsPath)
}
