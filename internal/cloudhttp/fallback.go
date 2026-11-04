package cloudhttp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"time"
)

// proxyPatience is the longest a request to the cloud waits for a proxy macOS
// is set to use to connect it to the server before it goes directly. It waits
// no longer than half the time it has left, which leaves the other half for
// that.
const proxyPatience = 5 * time.Second

// directFallback sends requests to the cloud on transport, and sends one again
// directly when a proxy macOS is set to use failed it before it could reach
// the server: the proxy is down, refuses to tunnel it, wants a password, or
// does not connect it within patience. Once a tunnel through the proxy is up,
// or the request has gone out to the proxy, it may have reached the server, so
// it is not sent again: the server never gets it twice. When the request gets
// through directly, requests skip that proxy for directFor: on a network that
// lets traffic out directly, a proxy that is down or wants a password would
// otherwise make them fail. A proxy the environment names stays strict, as it
// does in Go.
type directFallback struct {
	transport *http.Transport
	proxies   *proxyPicker
	patience  time.Duration
}

// sharedFallback sends the cloud clients' requests on the shared transport.
var sharedFallback = &directFallback{transport: sharedTransport, proxies: cloudProxies, patience: proxyPatience}

func (f *directFallback) RoundTrip(req *http.Request) (*http.Response, error) {
	if f.proxies.system == nil {
		return f.transport.RoundTrip(req)
	}
	first := &attempt{patience: f.patience}
	resp, err := first.send(f.transport, req)
	proxy, reason := first.failedAtProxy(req, resp, err)
	if proxy == nil || req.Context().Err() != nil {
		return resp, err
	}
	again, ok := resend(req)
	if !ok {
		return resp, err
	}
	retry := &attempt{direct: true}
	directResp, directErr := retry.send(f.transport, again)
	connected, fresh := retry.connection()
	if !connected {
		// The request cannot get out directly either, so what the proxy
		// said tells more.
		return resp, err
	}
	if resp != nil {
		resp.Body.Close()
	}
	// The way out directly works when the server answered, or when a new
	// connection to it just came up: a request that failed on that failed
	// at the server. One that failed on a connection from before shows
	// nothing.
	if directErr == nil || fresh {
		f.proxies.goDirect(proxy, reason)
	}
	return directResp, directErr
}

// CloseIdleConnections closes the transport's idle connections.
func (f *directFallback) CloseIdleConnections() {
	f.transport.CloseIdleConnections()
}

// resend is req to send again, with its body read anew, or false when its
// body cannot be.
func resend(req *http.Request) (*http.Request, bool) {
	again := req.Clone(req.Context())
	if req.Body == nil || req.Body == http.NoBody {
		return again, true
	}
	if req.GetBody == nil {
		return nil, false
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, false
	}
	again.Body = body
	return again, true
}

// attempt follows a request to the cloud through the transport, to tell
// whether a proxy macOS is set to use failed it before it could reach the
// server.
type attempt struct {
	direct   bool          // the request is being sent again, directly
	patience time.Duration // how long it waits for its proxy to connect it

	mu     sync.Mutex
	cancel context.CancelCauseFunc
	proxy  *url.URL // the proxy of macOS's it goes through, if any
	timer  *time.Timer
	// up is set once the request may reach the server: a tunnel to the
	// server is up through its proxy, or the transport has a connection to
	// send it on, which is fresh when it was dialed for the request.
	up, fresh bool
	// gaveUp is set once the request stops waiting for its proxy.
	gaveUp bool
}

type attemptKey struct{}

// attemptOf is the attempt a request made with ctx is, or nil.
func attemptOf(ctx context.Context) *attempt {
	a, _ := ctx.Value(attemptKey{}).(*attempt)
	return a
}

// send sends req on transport as the attempt, which lasts until the
// response's body is closed.
func (a *attempt) send(transport http.RoundTripper, req *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithCancelCause(req.Context())
	a.mu.Lock()
	a.cancel = cancel
	a.mu.Unlock()
	ctx = httptrace.WithClientTrace(context.WithValue(ctx, attemptKey{}, a), &httptrace.ClientTrace{
		GotConn: a.gotConn,
	})
	resp, err := transport.RoundTrip(req.WithContext(ctx))
	a.mu.Lock()
	if a.timer != nil {
		a.timer.Stop()
	}
	a.mu.Unlock()
	if err != nil {
		cancel(err)
		return nil, err
	}
	resp.Body = attemptBody{resp.Body, cancel}
	return resp, nil
}

// through notes that the attempt goes through proxy, a proxy macOS is set to
// use, and has it stop waiting for the proxy unless the proxy connects it to
// the server within the attempt's patience, or half the time ctx leaves it.
func (a *attempt) through(ctx context.Context, proxy *url.URL) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.proxy = proxy
	if a.timer != nil || a.up {
		return
	}
	patience := a.patience
	if deadline, ok := ctx.Deadline(); ok {
		patience = min(patience, time.Until(deadline)/2)
	}
	if patience > 0 {
		a.timer = time.AfterFunc(patience, func() { a.giveUp(proxy, patience) })
	}
}

// giveUp stops the request waiting for proxy, which has not connected it to
// the server within patience.
func (a *attempt) giveUp(proxy *url.URL, patience time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.up {
		a.gaveUp = true
		a.cancel(fmt.Errorf("proxy %s did not connect within %v", proxy.Host, patience))
	}
}

// gotConn notes that the transport has a connection to send the request on,
// so it may reach the server from now on.
func (a *attempt) gotConn(info httptrace.GotConnInfo) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reach()
	a.fresh = a.fresh || !info.Reused
}

// tunnelUp notes that a tunnel to the server is up through the request's
// proxy, so it may reach the server from now on, unless it stopped waiting
// for the proxy: then the tunnel will carry another request.
func (a *attempt) tunnelUp() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.gaveUp {
		a.reach()
	}
}

// reach notes that the request may reach the server. a.mu must be held.
func (a *attempt) reach() {
	a.up = true
	if a.timer != nil {
		a.timer.Stop()
	}
}

// connection reports whether the transport had a connection to send the
// request on, and whether it dialed one for it.
func (a *attempt) connection() (connected, fresh bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.up, a.fresh
}

// failedAtProxy is the proxy macOS is set to use that failed the request
// before it could reach the server, given what the transport answered, and
// why, or nil when none did. A request through a proxy the environment
// names, or none, did not fail at one.
func (a *attempt) failedAtProxy(req *http.Request, resp *http.Response, err error) (*url.URL, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case a.proxy == nil:
	case err != nil:
		if !a.up {
			return a.proxy, err.Error()
		}
	case resp.StatusCode == http.StatusProxyAuthRequired && req.URL.Scheme == "http" && safeTwice(req.Method):
		// An http request goes to the proxy whole, with no tunnel. A proxy
		// that wants a password answers it without passing it on, but the
		// answer cannot prove that, so only a request the server may get
		// twice is sent again.
		return a.proxy, resp.Status
	}
	return nil, ""
}

// safeTwice reports whether a request with method may reach the server
// twice, as Go's transport sends one again: it is idempotent.
func safeTwice(method string) bool {
	switch method {
	case "", http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	return false
}

// noteTunnel is the transport's OnProxyConnectResponse: once a proxy answers
// a request's CONNECT with 200, its tunnel to the server is up. The transport
// dials with a context that keeps the request's values.
func noteTunnel(ctx context.Context, _ *url.URL, _ *http.Request, connectRes *http.Response) error {
	if a := attemptOf(ctx); a != nil && connectRes.StatusCode == http.StatusOK {
		a.tunnelUp()
	}
	return nil
}

// attemptBody is the body of a response to an attempt, which ends the attempt
// once closed.
type attemptBody struct {
	io.ReadCloser
	cancel context.CancelCauseFunc
}

func (b attemptBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel(nil)
	return err
}
