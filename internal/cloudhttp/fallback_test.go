package cloudhttp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// cloudFake is the cloud as the fallback tests reach it: cloud.example.com, a
// name the test servers' certificate holds, answered over https and http by
// servers on this machine. Each request it gets goes on got.
type cloudFake struct {
	https, http *httptest.Server
	got         chan string
	// direct counts the connections dialed to it directly rather than
	// through a proxy, and refuse has them refused.
	direct atomic.Int32
	refuse atomic.Bool
}

func newCloudFake(t *testing.T) *cloudFake {
	t.Helper()
	c := &cloudFake{got: make(chan string, 10)}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.got <- r.Method + " " + r.URL.Path + " " + string(body)
		switch r.URL.Path {
		case "/drop":
			panic(http.ErrAbortHandler)
		case "/slow":
			time.Sleep(500 * time.Millisecond)
		case "/stream":
			_, _ = io.WriteString(w, "from ")
			w.(http.Flusher).Flush()
			time.Sleep(100 * time.Millisecond)
			_, _ = io.WriteString(w, "the cloud")
			return
		}
		_, _ = io.WriteString(w, "from the cloud")
	})
	c.https, c.http = httptest.NewTLSServer(handler), httptest.NewServer(handler)
	t.Cleanup(c.https.Close)
	t.Cleanup(c.http.Close)
	return c
}

// gotNow is what the cloud has got so far.
func (c *cloudFake) gotNow() []string {
	var got []string
	for {
		select {
		case request := <-c.got:
			got = append(got, request)
		default:
			return got
		}
	}
}

// client is a client on a transport of its own, whose requests p picks the
// proxies of and which go directly after waiting patience for a proxy of
// macOS's.
func (c *cloudFake) client(t *testing.T, p *proxyPicker, patience time.Duration) *http.Client {
	t.Helper()
	transport := NewTransport(PingAfter, PingTimeout)
	transport.Proxy = p.proxyFor
	transport.TLSClientConfig = c.https.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	cloud := map[string]string{
		"cloud.example.com:443": c.https.Listener.Addr().String(),
		"cloud.example.com:80":  c.http.Listener.Addr().String(),
	}
	var dialer net.Dialer
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		to, ok := cloud[addr]
		if !ok {
			return dialer.DialContext(ctx, network, addr) // a proxy on this machine
		}
		c.direct.Add(1)
		if c.refuse.Load() {
			return nil, errors.New("this network lets nothing out directly")
		}
		return dialer.DialContext(ctx, network, to)
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: &directFallback{transport: transport, proxies: p, patience: patience}}
}

// post posts body to rawURL with client, and tells the status and body of the
// answer.
func post(t *testing.T, client *http.Client, rawURL, body string) (string, error) {
	t.Helper()
	resp, err := client.Post(rawURL, "text/plain", strings.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.Status + " " + string(answer), nil
}

// logLines collects what a picker logs.
type logLines struct {
	mu    sync.Mutex
	lines []string
}

func (l *logLines) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logLines) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.lines)
}

// cloudPicker picks the proxy at addr for every request to the cloud, as the
// web proxy and secure web proxy macOS is set to use, on a clock at *clock,
// and collects what it logs.
func cloudPicker(t *testing.T, addr string, clock *time.Time) (*proxyPicker, *logLines) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	p := testPicker(nil, &fakeScutil{output: "<dictionary> {\n  HTTPEnable : 1\n  HTTPPort : " + port + "\n  HTTPProxy : " + host +
		"\n  HTTPSEnable : 1\n  HTTPSPort : " + port + "\n  HTTPSProxy : " + host + "\n}\n"}, clock)
	logs := &logLines{}
	p.logf = logs.logf
	return p, logs
}

// proxyFake is a proxy on this machine at addr, which answers each request it
// gets, a CONNECT or a whole http request, with answer, and counts them.
type proxyFake struct {
	addr  string
	asked atomic.Int32
}

func newProxyFake(t *testing.T, answer func(conn net.Conn, req *http.Request)) *proxyFake {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &proxyFake{addr: listener.Addr().String()}
	var (
		mu     sync.Mutex
		conns  []net.Conn
		closed bool
	)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				conn.Close()
				return
			}
			conns = append(conns, conn)
			mu.Unlock()
			go func() {
				defer conn.Close()
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}
				p.asked.Add(1)
				answer(conn, req)
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		defer mu.Unlock()
		closed = true
		for _, conn := range conns {
			conn.Close()
		}
	})
	return p
}

// downProxy is the address of a proxy that is down: nothing listens there.
func downProxy(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().String()
}

// askForPassword answers with 407, as a proxy that wants a password does.
func askForPassword(conn net.Conn, req *http.Request) {
	_, _ = io.Copy(io.Discard, req.Body)
	_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n")
}

// tunnelTo answers CONNECT with a tunnel to addr, whatever it names.
func tunnelTo(addr string) func(net.Conn, *http.Request) {
	return func(conn net.Conn, _ *http.Request) {
		server, err := net.Dial("tcp", addr)
		if err != nil {
			_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			return
		}
		defer server.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
		go func() {
			_, _ = io.Copy(server, conn)
			server.Close()
		}()
		_, _ = io.Copy(conn, server)
	}
}

// hang never answers.
func hang(conn net.Conn, _ *http.Request) {
	_, _ = io.Copy(io.Discard, conn)
}

// tunnelThenClose answers CONNECT with 200, and closes the tunnel at once.
func tunnelThenClose(conn net.Conn, _ *http.Request) {
	_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
}

// readThenClose reads the request whole and leaves it unanswered, as a proxy
// that passed it on and lost the answer.
func readThenClose(_ net.Conn, req *http.Request) {
	_, _ = io.Copy(io.Discard, req.Body)
}

// A request goes directly, body and all, when the proxy macOS is set to use
// is down, and the switch is logged.
func TestDownMacOSProxyGoesDirect(t *testing.T) {
	cloud := newCloudFake(t)
	clock := time.Now()
	p, logs := cloudPicker(t, downProxy(t), &clock)

	answer, err := post(t, cloud.client(t, p, time.Minute), "https://cloud.example.com/v1/ingest", "batch")
	if err != nil || answer != "200 OK from the cloud" {
		t.Fatalf("answer %q, %v", answer, err)
	}
	if got := cloud.gotNow(); !slices.Equal(got, []string{"POST /v1/ingest batch"}) {
		t.Fatalf("the cloud got %q", got)
	}
	if lines := logs.all(); len(lines) != 1 || !strings.HasPrefix(lines[0], "cloud proxy failed (proxyconnect tcp: ") ||
		!strings.HasSuffix(lines[0], "); going direct\n") {
		t.Fatalf("logged %q", lines)
	}
}

// A request goes directly when the proxy macOS is set to use wants a
// password, which it asks for in its answer to CONNECT for an https request,
// and in its answer to the request itself for an http one.
func TestMacOSProxyWantingAPasswordGoesDirect(t *testing.T) {
	for _, test := range []struct{ scheme, reason string }{
		{"https", "Proxy Authentication Required"},
		{"http", "407 Proxy Authentication Required"},
	} {
		t.Run(test.scheme, func(t *testing.T) {
			cloud := newCloudFake(t)
			proxy := newProxyFake(t, askForPassword)
			clock := time.Now()
			p, logs := cloudPicker(t, proxy.addr, &clock)

			answer, err := post(t, cloud.client(t, p, time.Minute), test.scheme+"://cloud.example.com/v1/ingest", "batch")
			if err != nil || answer != "200 OK from the cloud" {
				t.Fatalf("answer %q, %v", answer, err)
			}
			if asked, direct := proxy.asked.Load(), cloud.direct.Load(); asked != 1 || direct != 1 {
				t.Fatalf("the proxy was asked %d times, and the cloud dialed directly %d times", asked, direct)
			}
			if got := cloud.gotNow(); !slices.Equal(got, []string{"POST /v1/ingest batch"}) {
				t.Fatalf("the cloud got %q", got)
			}
			if lines := logs.all(); !slices.Equal(lines, []string{"cloud proxy failed (" + test.reason + "); going direct\n"}) {
				t.Fatalf("logged %q", lines)
			}
		})
	}
}

// A request goes directly when the proxy macOS is set to use does not
// connect it within its patience, or within half the time it has left.
func TestSlowMacOSProxyGoesDirect(t *testing.T) {
	for _, test := range []struct {
		name              string
		patience, timeout time.Duration
	}{
		{"patience", 50 * time.Millisecond, 0},
		{"deadline", time.Minute, 2 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			cloud := newCloudFake(t)
			proxy := newProxyFake(t, hang)
			clock := time.Now()
			p, logs := cloudPicker(t, proxy.addr, &clock)
			client := cloud.client(t, p, test.patience)
			client.Timeout = test.timeout

			answer, err := post(t, client, "https://cloud.example.com/v1/ingest", "batch")
			if err != nil || answer != "200 OK from the cloud" {
				t.Fatalf("answer %q, %v", answer, err)
			}
			if lines := logs.all(); len(lines) != 1 || !strings.HasPrefix(lines[0], "cloud proxy failed (proxy "+proxy.addr+" did not connect within ") {
				t.Fatalf("logged %q", lines)
			}
		})
	}
}

// A proxy macOS is set to use that connects requests carries them, however
// long past its patience the server takes to answer, or to send the rest of
// its answer.
func TestWorkingMacOSProxyCarriesRequests(t *testing.T) {
	cloud := newCloudFake(t)
	proxy := newProxyFake(t, tunnelTo(cloud.https.Listener.Addr().String()))
	clock := time.Now()
	p, logs := cloudPicker(t, proxy.addr, &clock)
	client := cloud.client(t, p, 200*time.Millisecond)

	for _, path := range []string{"/slow", "/stream", "/v1/ingest"} {
		answer, err := post(t, client, "https://cloud.example.com"+path, "batch")
		if err != nil || answer != "200 OK from the cloud" {
			t.Fatalf("answer %q, %v", answer, err)
		}
	}
	if asked, direct := proxy.asked.Load(), cloud.direct.Load(); asked == 0 || direct != 0 {
		t.Fatalf("the proxy was asked %d times, and the cloud dialed directly %d times", asked, direct)
	}
	if got := cloud.gotNow(); len(got) != 3 {
		t.Fatalf("the cloud got %q", got)
	}
	if lines := logs.all(); len(lines) != 0 {
		t.Fatalf("logged %q", lines)
	}
}

// Once a request has gone directly, requests go directly for directFor by the
// wall clock, or until it goes back, and then try the proxy macOS is set to
// use again.
func TestRequestsGoDirectForAWhile(t *testing.T) {
	cloud := newCloudFake(t)
	proxy := newProxyFake(t, askForPassword)
	clock := time.Now()
	p, logs := cloudPicker(t, proxy.addr, &clock)
	client := cloud.client(t, p, time.Minute)
	send := func(asked int32, logged int) {
		t.Helper()
		if answer, err := post(t, client, "https://cloud.example.com/v1/ingest", "batch"); err != nil || answer != "200 OK from the cloud" {
			t.Fatalf("answer %q, %v", answer, err)
		}
		if got, lines := proxy.asked.Load(), logs.all(); got != asked || len(lines) != logged {
			t.Fatalf("the proxy was asked %d times, not %d, and %q logged", got, asked, lines)
		}
	}

	send(1, 1)
	// A request that went through the proxy before the switch fails after it.
	p.goDirect("Proxy Authentication Required")
	clock = clock.Add(directFor - time.Second)
	send(1, 1)
	clock = clock.Add(time.Second)
	send(2, 2)
	clock = clock.Add(-time.Hour)
	send(3, 3)
}

// A request that may have reached the server is not sent again: not once a
// tunnel through the proxy is up, nor once an http request has gone out to
// the proxy.
func TestRequestsPastTheProxyAreNotSentAgain(t *testing.T) {
	for _, test := range []struct {
		name, url string
		answer    func(*cloudFake) func(net.Conn, *http.Request)
		got       []string
	}{
		{"tunnel closed", "https://cloud.example.com/v1/ingest", func(*cloudFake) func(net.Conn, *http.Request) { return tunnelThenClose }, nil},
		{"answer lost", "https://cloud.example.com/drop", func(c *cloudFake) func(net.Conn, *http.Request) {
			return tunnelTo(c.https.Listener.Addr().String())
		}, []string{"POST /drop batch"}},
		{"http answer lost", "http://cloud.example.com/v1/ingest", func(*cloudFake) func(net.Conn, *http.Request) { return readThenClose }, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			cloud := newCloudFake(t)
			proxy := newProxyFake(t, test.answer(cloud))
			clock := time.Now()
			p, logs := cloudPicker(t, proxy.addr, &clock)

			if answer, err := post(t, cloud.client(t, p, time.Minute), test.url, "batch"); err == nil {
				t.Fatalf("answer %q", answer)
			}
			if direct, got, lines := cloud.direct.Load(), cloud.gotNow(), logs.all(); direct != 0 || !slices.Equal(got, test.got) || len(lines) != 0 {
				t.Fatalf("the cloud was dialed directly %d times and got %q, and %q logged", direct, got, lines)
			}
		})
	}
}

// A request a proxy macOS is set to use fails is not sent again directly when
// its body cannot be read again, and when it cannot get out directly either,
// what the proxy said comes back and requests keep trying the proxy.
func TestRequestsThatCannotGoDirect(t *testing.T) {
	cloud := newCloudFake(t)
	proxy := newProxyFake(t, askForPassword)
	clock := time.Now()
	p, logs := cloudPicker(t, proxy.addr, &clock)
	client := cloud.client(t, p, time.Minute)

	req, err := http.NewRequest(http.MethodPost, "https://cloud.example.com/v1/ingest", io.MultiReader(strings.NewReader("batch")))
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := client.Do(req); err == nil {
		resp.Body.Close()
		t.Fatal("a request whose body cannot be read again went through")
	}
	if direct := cloud.direct.Load(); direct != 0 {
		t.Fatalf("a request whose body cannot be read again was dialed directly %d times", direct)
	}

	cloud.refuse.Store(true)
	for range 2 {
		if _, err := post(t, client, "https://cloud.example.com/v1/ingest", "batch"); err == nil || !strings.Contains(err.Error(), "Proxy Authentication Required") {
			t.Fatalf("got %v, not what the proxy said", err)
		}
	}
	if asked, direct, lines := proxy.asked.Load(), cloud.direct.Load(), logs.all(); asked != 3 || direct != 2 || len(lines) != 0 {
		t.Fatalf("the proxy was asked %d times, the cloud dialed directly %d times, and %q logged", asked, direct, lines)
	}
}

// Proxies the environment names stay strict, as they do in Go: a request one
// fails is not sent again directly.
func TestEnvironmentProxiesStayStrict(t *testing.T) {
	cloud := newCloudFake(t)
	proxy := newProxyFake(t, askForPassword)
	clock := time.Now()
	p, logs := cloudPicker(t, downProxy(t), &clock)
	p.getenv = func(name string) string {
		if name == "HTTPS_PROXY" {
			return "http://" + proxy.addr
		}
		return ""
	}
	p.fromEnvironment = func(*http.Request) (*url.URL, error) { return &url.URL{Scheme: "http", Host: proxy.addr}, nil }

	if answer, err := post(t, cloud.client(t, p, time.Minute), "https://cloud.example.com/v1/ingest", "batch"); err == nil {
		t.Fatalf("answer %q", answer)
	}
	if asked, direct, lines := proxy.asked.Load(), cloud.direct.Load(), logs.all(); asked != 1 || direct != 0 || len(lines) != 0 {
		t.Fatalf("the proxy was asked %d times, the cloud dialed directly %d times, and %q logged", asked, direct, lines)
	}
}
