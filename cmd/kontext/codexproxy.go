package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/kontext-security/kontext/internal/codexmanaged"
	"github.com/kontext-security/kontext/internal/codexproxy"
	"github.com/kontext-security/kontext/internal/codexroute"
	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/localruntime"
	"github.com/kontext-security/kontext/internal/managedobserve"
	"github.com/kontext-security/kontext/internal/tooloutput"
)

// codexProxyCmd runs the Codex proxy. Its launchd job hands it the listening
// socket on standard input (inetdCompatibility with Wait), so release builds
// need no cgo; --port serves a loopback port instead.
func codexProxyCmd() *cobra.Command {
	var stdinSocket, passThrough bool
	var port int
	var home, tokenFile, stateDir, socketPath, upstream, apiUpstream string
	var idleExit time.Duration
	cmd := &cobra.Command{
		Use:    "codex-proxy",
		Short:  "Run the Codex proxy",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if stateDir == "" {
				return errors.New("--state-dir is required")
			}
			if tokenFile == "" {
				tokenFile = codexroute.TokenPath(stateDir)
				if !stdinSocket {
					// Run by hand: make the token the first time.
					if _, err := codexroute.EnsureToken(stateDir); err != nil {
						return err
					}
				}
			}
			data, err := os.ReadFile(tokenFile)
			if err != nil {
				return fmt.Errorf("read the proxy token: %w", err)
			}
			token := strings.TrimSpace(string(data))
			upstreamURL, err := url.Parse(upstream)
			if err != nil || upstreamURL.Host == "" {
				return fmt.Errorf("--upstream must be a URL")
			}
			apiUpstreamURL, err := url.Parse(apiUpstream)
			if err != nil || apiUpstreamURL.Host == "" {
				return fmt.Errorf("--api-upstream must be a URL")
			}
			store, err := codexproxy.OpenStore(codexroute.DecisionsDir(stateDir))
			if err != nil {
				return err
			}
			defer store.Close()
			logger := log.New(cmd.ErrOrStderr(), "codex-proxy ", log.LstdFlags)
			if socketPath == "" {
				socketPath = managedobserve.DefaultSocketPath()
			}
			var rewriter *codexproxy.Rewriter
			if !passThrough {
				decider := codexproxy.SocketDecider{Client: localruntime.NewClient(socketPath)}
				rewriter = codexproxy.NewRewriter(decider, store, codexproxy.DecideWait)
			}
			held, unreachable := jobRoute(home, stateDir, logger)
			server, err := codexproxy.New(codexproxy.Options{Upstream: upstreamURL, APIUpstream: apiUpstreamURL, Token: token, Rewriter: rewriter,
				Held: held, Unreachable: unreachable, Logf: logger.Printf})
			if err != nil {
				return err
			}
			var listener net.Listener
			if stdinSocket {
				listener, err = net.FileListener(os.Stdin)
			} else {
				listener, err = codexproxy.Listen(port)
			}
			if err != nil {
				return fmt.Errorf("listen: %w", err)
			}
			if !stdinSocket {
				// For a run by hand, to pass Codex as -c openai_base_url=...;
				// never in the job's log.
				fmt.Fprintf(cmd.OutOrStdout(), "openai_base_url = %q\n", codexproxy.BaseURL(listener.Addr(), token))
			}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			go pruneDecisions(ctx, store, logger)
			return codexproxy.Serve(ctx, listener, server, idleExit)
		},
	}
	cmd.Flags().BoolVar(&stdinSocket, "stdin-socket", false, "serve the listening socket launchd passes on standard input")
	cmd.Flags().BoolVar(&passThrough, "pass-through", false, "forward every request unchanged, asking the daemon nothing")
	cmd.Flags().StringVar(&home, "home", "", "home whose Codex route the proxy serves; once no daemon holds the route, or requests cannot reach the upstream, the proxy takes the route's line out of ~/.codex/config.toml")
	cmd.Flags().IntVar(&port, "port", 0, "loopback port to serve without launchd (0 picks one)")
	cmd.Flags().StringVar(&tokenFile, "token-file", "", "file holding the proxy's path token")
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "the proxy's state directory")
	cmd.Flags().StringVar(&socketPath, "socket", "", "managed observe socket path")
	cmd.Flags().StringVar(&upstream, "upstream", codexproxy.DefaultUpstream, "Codex backend base URL, for requests a ChatGPT login signs")
	cmd.Flags().StringVar(&apiUpstream, "api-upstream", codexproxy.DefaultAPIUpstream, "OpenAI API base URL, for requests an API key signs")
	cmd.Flags().DurationVar(&idleExit, "idle-exit", codexroute.IdleExit, "exit after this long without a connection (0 never)")
	cmd.AddCommand(codexProxyStatusCmd(), codexProxyDisableCmd())
	return cmd
}

// jobRoute asks, for the job, whether a daemon still holds the Codex route
// in home, which goes once none does (see codexroute.Router.Held), and takes
// the route away once the job's requests cannot reach the upstream (see
// codexroute.Router.Unreachable). A proxy run by hand serves no route, and
// asks nothing.
func jobRoute(home, stateDir string, logger *log.Logger) (func(context.Context) bool, func(context.Context)) {
	if home == "" {
		return nil, nil
	}
	router := codexroute.New(codexroute.Options{Home: home, StateDir: stateDir})
	return reportHeld(router.Held, logger.Printf), reportUnreachable(router.Unreachable, logger.Printf)
}

// reportUnreachable takes the route away with unreachable once requests
// could not reach the upstream, and logs what came of it.
func reportUnreachable(unreachable func(context.Context) (bool, error), logf func(string, ...any)) func(context.Context) {
	return func(ctx context.Context) {
		switch taken, err := unreachable(ctx); {
		case err != nil:
			logf("Codex route not taken away, though requests could not reach the upstream: %v", err)
		case !taken:
			logf("Codex route left to the daemon changing it, though requests could not reach the upstream")
		default:
			logf("Codex route taken away: requests could not reach the upstream; passing requests through")
		}
	}
}

// reportHeld asks held, and logs what it finds the first time, so each proxy
// run says where the route stands, and whenever that changes.
func reportHeld(ask func(context.Context) (bool, error), logf func(string, ...any)) func(context.Context) bool {
	var mu sync.Mutex
	last := ""
	return func(ctx context.Context) bool {
		held, err := ask(ctx)
		now := "held by a daemon"
		switch {
		case err != nil:
			now = "not held by a daemon, and not taken away: " + err.Error()
		case !held:
			now = "not held by a daemon: taken away; passing requests through"
		}
		mu.Lock()
		defer mu.Unlock()
		if now != last {
			logf("Codex route %s", now)
			last = now
		}
		return held
	}
}

func codexRouter() (*codexroute.Router, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return codexroute.New(codexroute.Options{Home: home, StateDir: codexroute.StateDir(managedobserve.DefaultDBPath()),
		Socket: managedobserve.DefaultSocketPath()}), nil
}

func codexProxyStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Report whether Codex is routed through the Codex proxy",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			router, err := codexRouter()
			if err != nil {
				return err
			}
			status := router.Status(cmd.Context())
			fmt.Fprintf(cmd.OutOrStdout(), "routed: %v\nanswering: %v\nheld by a daemon: %v\njob loaded: %v\nport: %d\n",
				status.Routed, status.Answering, status.Held, status.Loaded, status.Port)
			if status.Skipped != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "not routed because: %s\n", status.Skipped)
			}
			if status.Draining > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "kept for %d Codex process(es) started while Codex was routed\n", status.Draining)
			}
			return nil
		},
	}
}

func codexProxyDisableCmd() *cobra.Command {
	var now bool
	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Stop routing Codex through the Codex proxy",
		Long: "Removes the openai_base_url line Kontext wrote to ~/.codex/config.toml. The proxy job stays, passing requests " +
			"through, until no Codex process that started while Codex was routed is left; --now unloads it anyway. A daemon " +
			"whose switch is on routes Codex again.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			router, err := codexRouter()
			if err != nil {
				return err
			}
			if now {
				left, err := router.Remove(cmd.Context(), 0)
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), "Codex is no longer routed through the proxy, and the proxy is unloaded.")
				if left > 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "Restart Codex: %d Codex process(es) still had the proxy's address.\n", left)
				}
				return nil
			}
			if err := router.Disable(cmd.Context()); err != nil {
				return err
			}
			drained, err := router.Drain(cmd.Context())
			if err != nil {
				return err
			}
			if drained {
				fmt.Fprintln(cmd.OutOrStdout(), "Codex is no longer routed through the proxy, and the proxy is unloaded.")
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "Codex is no longer routed through the proxy. Quit Codex and the ChatGPT app, then run this again to unload it.")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&now, "now", false, "unload the proxy even while Codex processes may still call it")
	return cmd
}

// pruneDecisions drops decisions as old as the saved outputs they point to,
// once at start and hourly after.
func pruneDecisions(ctx context.Context, store *codexproxy.Store, logger *log.Logger) {
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		if err := store.Prune(tooloutput.Retention); err != nil {
			logger.Printf("prune decisions: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// codexUnroutedNotice tells the person, as a Codex session starts, that its
// hook took away a route nothing answered on.
const codexUnroutedNotice = "Kontext's Codex proxy is not answering, so Kontext took its openai_base_url line out of ~/.codex/config.toml. " +
	"Restart Codex and the ChatGPT app: sessions opened before now, this one included, still call the proxy and keep reconnecting."

// withCodexRouteCheck checks Codex's route to the Kontext proxy as each Codex
// session starts, before evaluate answers the hook, and hands the person what
// the check has to say. Codex runs the hook itself, so the check runs when
// neither the daemon nor the proxy job does.
func withCodexRouteCheck(evaluate func(hook.Event) (hook.Result, error), check func(context.Context) string) func(hook.Event) (hook.Result, error) {
	return func(e hook.Event) (hook.Result, error) {
		notice := ""
		if e.Agent == "codex" && e.HookName == hook.HookSessionStart {
			notice = check(context.Background())
		}
		result, err := evaluate(e)
		result.Notice = notice
		return result, err
	}
}

// codexRouteCheck builds the check every Codex hook path runs as a session
// starts (see withCodexRouteCheck); tests replace it.
var codexRouteCheck = unrouteUnansweredCodex

// unrouteUnansweredCodex takes Codex's route away on macOS when nothing
// answers on its port (see codexroute.Router.UnrouteUnanswered), and says so.
// A check that fails says nothing.
func unrouteUnansweredCodex(diag diagnostic.Logger) func(context.Context) string {
	return func(ctx context.Context) string {
		if runtime.GOOS != "darwin" {
			return ""
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		router := codexroute.New(codexroute.Options{Home: home, StateDir: codexroute.StateDir(managedobserve.DefaultDBPath())})
		unrouted, err := router.UnrouteUnanswered(ctx)
		if err != nil {
			diag.Printf("codex proxy route check: %v\n", err)
		}
		if !unrouted {
			return ""
		}
		return codexUnroutedNotice
	}
}

// checkCodexProxy reports the Codex route on macOS, and whether it is
// healthy: a route the proxy does not answer leaves Codex retrying forever.
func checkCodexProxy(ctx context.Context, out io.Writer) bool {
	if runtime.GOOS != "darwin" {
		return true
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return true
	}
	router := codexroute.New(codexroute.Options{Home: home, StateDir: codexroute.StateDir(managedobserve.DefaultDBPath())})
	status := router.Status(ctx)
	switch {
	case status.Routed && status.Answering:
		fmt.Fprintf(out, "  codex proxy: routing Codex through 127.0.0.1:%d\n", status.Port)
	case status.Routed:
		fmt.Fprintf(out, "  WARNING: ~/.codex/config.toml routes Codex through the Kontext proxy, which does not answer, so Codex requests wait forever; start the Kontext daemon, or delete the line marked %q\n", codexmanaged.RouteMarker)
		return false
	case status.Loaded && status.Draining > 0:
		fmt.Fprintf(out, "  codex proxy: not routed; kept for %d Codex process(es) started while it was\n", status.Draining)
	case status.Loaded:
		fmt.Fprintln(out, "  codex proxy: not routed")
	}
	return true
}
