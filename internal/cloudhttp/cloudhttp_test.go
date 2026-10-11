package cloudhttp

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blackholeProxy forwards TCP to target. After freeze, connections that were
// already open stay open but silently drop every byte, like a peer that went
// away without a FIN or RST. Connections dialed after freeze work normally.
type blackholeProxy struct {
	listener net.Listener
	frozen   atomic.Bool
	dials    atomic.Int32
	mu       sync.Mutex
	conns    []net.Conn
}

func newBlackholeProxy(t *testing.T, target string) *blackholeProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := &blackholeProxy{listener: listener}
	t.Cleanup(proxy.close)
	go proxy.serve(target)
	return proxy
}

func (p *blackholeProxy) serve(target string) {
	for {
		client, err := p.listener.Accept()
		if err != nil {
			return
		}
		upstream, err := net.Dial("tcp", target)
		if err != nil {
			client.Close()
			continue
		}
		p.dials.Add(1)
		p.mu.Lock()
		p.conns = append(p.conns, client, upstream)
		p.mu.Unlock()
		openedFrozen := p.frozen.Load()
		pipe := func(dst, src net.Conn) {
			buf := make([]byte, 32<<10)
			for {
				n, err := src.Read(buf)
				if err != nil {
					return
				}
				if p.frozen.Load() && !openedFrozen {
					continue
				}
				if _, err := dst.Write(buf[:n]); err != nil {
					return
				}
			}
		}
		go pipe(upstream, client)
		go pipe(client, upstream)
	}
}

func (p *blackholeProxy) close() {
	p.listener.Close()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, conn := range p.conns {
		conn.Close()
	}
}

// consecutiveFailuresAfterFreeze makes one request, freezes the connection it
// used, then counts how many requests fail before one succeeds.
func consecutiveFailuresAfterFreeze(t *testing.T, transport *http.Transport, maxAttempts int) (int, int32) {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	server.EnableHTTP2 = true
	// The frozen connection ends in TLS errors on close; keep them out of the test log.
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	// A small stream limit keeps the unprotected case quick: without health
	// checks the client only leaves a dead connection once the reset streams
	// fill this limit.
	server.Config.HTTP2 = &http.HTTP2Config{MaxConcurrentStreams: 10}
	server.StartTLS()
	t.Cleanup(server.Close)
	proxy := newBlackholeProxy(t, server.Listener.Addr().String())

	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 200 * time.Millisecond}
	url := "https://" + proxy.listener.Addr().String() + "/"
	get := func() error {
		resp, err := client.Get(url)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.ProtoMajor != 2 {
			t.Fatalf("request used %s, want HTTP/2", resp.Proto)
		}
		return nil
	}

	if err := get(); err != nil {
		t.Fatalf("request before freeze: %v", err)
	}
	proxy.frozen.Store(true)
	failures := 0
	for failures < maxAttempts {
		if get() == nil {
			return failures, proxy.dials.Load()
		}
		failures++
	}
	t.Fatalf("no request succeeded in %d attempts after the connection went dead", maxAttempts)
	return 0, 0
}

func TestHealthCheckedTransportLeavesDeadConnection(t *testing.T) {
	failures, dials := consecutiveFailuresAfterFreeze(t, NewTransport(100*time.Millisecond, 100*time.Millisecond), 5)
	if failures > 2 {
		t.Fatalf("%d requests failed on the dead connection, want at most 2", failures)
	}
	if dials != 2 {
		t.Fatalf("dials = %d, want 2 (the dead connection and its replacement)", dials)
	}
}

// The failure this package exists to prevent: the stock transport keeps using
// a dead HTTP/2 connection until its stream limit fills.
func TestDefaultTransportStaysOnDeadConnection(t *testing.T) {
	failures, _ := consecutiveFailuresAfterFreeze(t, http.DefaultTransport.(*http.Transport).Clone(), 50)
	if failures < 10 {
		t.Fatalf("stock transport recovered after %d failures; the regression test no longer reproduces the dead-connection case", failures)
	}
}

func TestNewClientUsesHealthCheckedTransport(t *testing.T) {
	client := NewClient(7 * time.Second)
	if client.Timeout != 7*time.Second {
		t.Fatalf("timeout = %v", client.Timeout)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport != sharedTransport {
		t.Fatal("client does not use the shared transport")
	}
	if transport.HTTP2 == nil || transport.HTTP2.SendPingTimeout != PingAfter || transport.HTTP2.PingTimeout != PingTimeout {
		t.Fatalf("HTTP/2 health checks not configured: %+v", transport.HTTP2)
	}
	if transport.Proxy == nil {
		t.Fatal("proxy settings from the environment were dropped")
	}
}
