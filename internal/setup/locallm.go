package setup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/kontext-security/kontext/internal/guard/judge"
	"github.com/kontext-security/kontext/internal/guard/judgeruntime"
	"github.com/kontext-security/kontext/internal/managedobserve"
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

// preflightLocalLLM fails fast when the runtime is absent and returns its
// absolute path. It runs before any privileged write so an operator who wants
// the model, but has not installed llama.cpp, gets told immediately rather than
// after their Mac is half configured.
//
// The absolute path is the point, not a convenience: this lookup happens in a
// login shell where Homebrew is on PATH, while launchd hands the daemon a
// minimal PATH that excludes /opt/homebrew/bin. Resolving here and passing the
// result through means the daemon does not repeat a lookup that would fail.
func preflightLocalLLM() (string, error) {
	path, err := exec.LookPath(judge.DefaultLlamaServerBinary)
	if err != nil {
		return "", errLlamaServerMissing
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", judge.DefaultLlamaServerBinary, err)
	}
	return absolute, nil
}

// prefetchLocalModel downloads the guardrail model into the daemon's cache and
// returns the configuration that was actually used, so the agent can be given
// the same one. The cost lands here, behind a progress bar, instead of inside a
// developer's first tool call: the download is ~680 MB and the first load takes
// minutes, which during a hook reads as a hang.
//
// A failure is reported and swallowed, and the returned configuration is still
// valid: the weights are an optimization of something that already degrades
// cleanly, so a flaky network must not fail an otherwise complete setup. The
// daemon fetches on first use instead — into the same cache, because it is
// handed the same configuration.
func prefetchLocalModel(ctx context.Context, serverBinary string, stdout, stderr io.Writer, progress judge.DownloadProgressHandler) *localLLMAgentConfig {
	// The daemon's database path, not Guard's: the model cache is derived from it,
	// and the two defaults are different directories. Deriving it from the wrong
	// one fills a cache nothing reads.
	cfg, err := judgeruntime.ConfigFromEnv(managedobserve.DefaultDBPath())
	if err != nil {
		fmt.Fprintf(stderr, "warning: could not resolve the local model configuration (%v); the agent will fetch it on first use\n", err)
		return &localLLMAgentConfig{ServerBinary: serverBinary}
	}
	repo, file := judge.DefaultLlamaServerHFRepo, judge.DefaultLlamaServerHFFile
	if strings.TrimSpace(cfg.HFRepo) != "" {
		repo = cfg.HFRepo
		file = cfg.HFFile
	}
	resolved := &localLLMAgentConfig{
		ServerBinary: serverBinary,
		HFRepo:       repo,
		HFFile:       file,
		HFRevision:   cfg.HFRevision,
		CacheDir:     cfg.CacheDir,
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
			return resolved
		}
		fmt.Fprintf(stderr, "warning: could not pre-fetch the local model (%v); the agent will fetch it on first use\n", err)
		return resolved
	}
	fmt.Fprintf(stdout, "  ✓ Local risk model ready (%s)\n", path)
	return resolved
}
