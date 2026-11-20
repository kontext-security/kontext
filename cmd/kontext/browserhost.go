package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/kontext-security/kontext/internal/browserhost"
	"github.com/kontext-security/kontext/internal/localruntime"
	"github.com/kontext-security/kontext/internal/managedobserve"
)

// browserHostRelayTimeout bounds one message's round trip to the daemon. The
// extension waits for every answer, so a daemon that is gone must not hold it.
const browserHostRelayTimeout = 5 * time.Second

// startedByBrowser reports whether the browser started this binary as the
// native messaging host. The browser runs the manifest's path with the
// extension's origin as the first argument and nothing else we could name a
// subcommand with.
func startedByBrowser(args []string) bool {
	return len(args) > 1 && browserhost.CallerOrigin(args[1:2]) != ""
}

// runBrowserHost serves the extension on stdin and stdout until the browser
// closes the pipe. It writes nothing else to stdout, which carries frames.
func runBrowserHost(args []string, in io.Reader, out io.Writer) error {
	client := localruntime.Client{SocketPath: managedobserve.DefaultSocketPath(), Timeout: browserHostRelayTimeout}
	relay := func(ctx context.Context, message json.RawMessage) (json.RawMessage, error) {
		return client.Browser(ctx, message)
	}
	return browserhost.Serve(context.Background(), browserhost.CallerOrigin(args), in, out, relay)
}

func browserHostCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "browser-host <extension origin>",
		Short:  "Native messaging host of the Kontext browser extension",
		Hidden: true,
		Args:   cobra.MinimumNArgs(1),
		// stdout carries native messaging frames, so usage text must not reach it.
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBrowserHost(args, os.Stdin, os.Stdout)
		},
	}
	addBrowserHostDevCommands(cmd)
	return cmd
}
