package setup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/guard/judge"
	"github.com/kontext-security/kontext-cli/internal/guard/judgeruntime"
	"github.com/kontext-security/kontext-cli/internal/runtimehost"
)

// llamaServerInstallHint is the only supported way to get the runtime today:
// the Homebrew formula depends on llama.cpp, and nothing in this CLI ships or
// downloads a native inference binary.
const llamaServerInstallHint = "brew install llama.cpp"

// errLlamaServerMissing is returned before anything is written, so asking for
// the local model without the runtime present costs nothing to recover from.
var errLlamaServerMissing = fmt.Errorf(
	"local risk model requested but %q is not on PATH; install it with `%s`, or re-run setup without --with-local-llm",
	judge.DefaultLlamaServerBinary, llamaServerInstallHint,
)

// preflightLocalLLM fails fast when the runtime is absent. It runs before any
// privileged write so an operator who wants the model, but has not installed
// llama.cpp, gets told immediately rather than after their Mac is half
// configured.
func preflightLocalLLM() error {
	if _, err := exec.LookPath(judge.DefaultLlamaServerBinary); err != nil {
		return errLlamaServerMissing
	}
	return nil
}

// prefetchLocalModel downloads the guardrail model into the judge cache so the
// cost lands here, with a progress bar, instead of inside a developer's first
// tool call. The download is ~680 MB and takes minutes on a cold cache; paid
// during setup it is expected, paid during a hook it looks like a hang.
//
// A failure here is reported and swallowed: the model is an optimization of
// something that already degrades cleanly, so a flaky network must not fail an
// otherwise complete setup. The daemon will fetch it on first use instead.
func prefetchLocalModel(ctx context.Context, stdout, stderr io.Writer, progress judge.DownloadProgressHandler) {
	cfg, err := judgeruntime.ConfigFromEnv(runtimehost.DefaultDBPath(), false)
	if err != nil {
		fmt.Fprintf(stderr, "warning: could not resolve the local model configuration (%v); the agent will fetch it on first use\n", err)
		return
	}
	repo, file := judge.DefaultLlamaServerHFRepo, judge.DefaultLlamaServerHFFile
	if strings.TrimSpace(cfg.HFRepo) != "" {
		repo = cfg.HFRepo
		file = cfg.HFFile
	}
	path, err := judge.ResolveLlamaServerModel(ctx, judge.LlamaServerOptions{
		HFRepo:           repo,
		HFFile:           file,
		HFRevision:       cfg.HFRevision,
		CacheDir:         cfg.CacheDir,
		DownloadProgress: progress,
	})
	if err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(stderr, "warning: model download cancelled; the agent will fetch it on first use")
			return
		}
		fmt.Fprintf(stderr, "warning: could not pre-fetch the local model (%v); the agent will fetch it on first use\n", err)
		return
	}
	fmt.Fprintf(stdout, "  ✓ Local risk model ready (%s)\n", path)
}
