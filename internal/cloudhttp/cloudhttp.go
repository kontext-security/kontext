// Package cloudhttp builds the HTTP clients the CLI uses to reach the Kontext
// cloud. They share one transport whose HTTP/2 connections are health-checked.
//
// Without health checks a dead HTTP/2 connection stays in the pool: Go keeps
// sending new requests on it, and each one only times out, until the reset
// streams fill the server's concurrent-stream limit (250 for many servers).
// A long-running daemon that hit this kept enforcing a stale policy while
// every refresh and ledger upload failed with "context deadline exceeded".
package cloudhttp

import (
	"net/http"
	"time"
)

const (
	// PingAfter is how long a connection may go without receiving any frame
	// before the transport pings it.
	PingAfter = 15 * time.Second
	// PingTimeout is how long the transport waits for the ping's reply before
	// it closes the connection and the next request dials a fresh one. The
	// wait includes writing the ping, which can queue behind a ledger upload
	// on a slow link, so it stays generous: a dead connection is still gone
	// within 30s, well inside the one-minute policy refresh interval.
	PingTimeout = 15 * time.Second
)

var sharedTransport = NewTransport(PingAfter, PingTimeout)

// NewTransport returns a copy of http.DefaultTransport (proxy settings, dial
// and TLS timeouts included) with HTTP/2 connection health checks enabled.
func NewTransport(pingAfter, pingTimeout time.Duration) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.HTTP2 = &http.HTTP2Config{
		SendPingTimeout: pingAfter,
		PingTimeout:     pingTimeout,
	}
	return transport
}

// NewClient returns a client on the shared health-checked transport.
func NewClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: sharedTransport}
}
