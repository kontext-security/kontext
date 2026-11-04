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
// through directly, requests go directly for directFor: on a network that lets
// traffic out directly, a proxy that is down or wants a password would
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
	reason, failed := first.failedAtProxy(req, resp, err)
	if !failed || req.Context().Err() != nil {
		return resp, err
	}
	again, ok := resend(req)
	if !ok {
		return resp, err
	}
	retry := &attempt{direct: true}
	directResp, directErr := retry.send(f.transport, again)
	if !retry.connected() {
		// The request cannot get out directly either, so what the proxy
		// said tells more.
		return resp, err
	}
	if resp != nil {
		resp.Body.Close()
	}
	f.proxies.goDirect(reason)
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
	// send it on.
	up bool
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
		GotConn: func(httptrace.GotConnInfo) { a.reach(true) },
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

// reach notes that the request may reach the server from now on: the
// transport has a connection to send it on (conn), or a tunnel through its
// proxy is up. A tunnel the request stopped waiting for will carry another
// one.
func (a *attempt) reach(conn bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if conn || !a.gaveUp {
		a.up = true
		if a.timer != nil {
			a.timer.Stop()
		}
	}
}

// connected reports whether the transport had a connection to send the
// request on.
func (a *attempt) connected() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.up
}

// failedAtProxy tells why a proxy macOS is set to use failed the request
// before it could reach the server, given what the transport answered, if
// one did. A request through a proxy the environment names, or none, did not.
func (a *attempt) failedAtProxy(req *http.Request, resp *http.Response, err error) (reason string, failed bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case a.proxy == nil:
		return "", false
	case err != nil:
		return err.Error(), !a.up
	case resp.StatusCode == http.StatusProxyAuthRequired && req.URL.Scheme == "http":
		// An http request goes to the proxy whole, with no tunnel, and a
		// proxy that wants a password answers it without passing it on.
		return resp.Status, true
	}
	return "", false
}

// noteTunnel is the transport's OnProxyConnectResponse: once a proxy answers
// a request's CONNECT with 200, its tunnel to the server is up. The transport
// dials with a context that keeps the request's values.
func noteTunnel(ctx context.Context, _ *url.URL, _ *http.Request, connectRes *http.Response) error {
	if a := attemptOf(ctx); a != nil && connectRes.StatusCode == http.StatusOK {
		a.reach(false)
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
