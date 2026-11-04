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
func post(client *http.Client, rawURL, body string) (string, error) {
	return answerOf(client.Post(rawURL, "text/plain", strings.NewReader(body)))
}

// get gets rawURL with client, and tells the status and body of the answer.
func get(client *http.Client, rawURL string) (string, error) {
	return answerOf(client.Get(rawURL))
}

func answerOf(resp *http.Response, err error) (string, error) {
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(resp.Body)
	return resp.Status + " " + string(answer), err
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

// proxiesAt is what scutil --proxy prints on a Mac set to use the proxy at
// web as its web proxy, and the one at secure as its secure web proxy.
func proxiesAt(t *testing.T, web, secure string) string {
	t.Helper()
	webHost, webPort, err := net.SplitHostPort(web)
	if err != nil {
		t.Fatal(err)
	}
	secureHost, securePort, err := net.SplitHostPort(secure)
	if err != nil {
		t.Fatal(err)
	}
	return "<dictionary> {\n  HTTPEnable : 1\n  HTTPPort : " + webPort + "\n  HTTPProxy : " + webHost +
		"\n  HTTPSEnable : 1\n  HTTPSPort : " + securePort + "\n  HTTPSProxy : " + secureHost + "\n}\n"
}

// cloudPicker picks the proxies scutil prints for every request to the cloud,
// on a clock at *clock, and collects what it logs.
func cloudPicker(scutil *fakeScutil, clock *time.Time) (*proxyPicker, *logLines) {
	p := testPicker(nil, scutil, clock)
	logs := &logLines{}
	p.logf = logs.logf
	return p, logs
}

// pickerOf picks the proxy at addr for every request to the cloud, as the web
// proxy and secure web proxy macOS is set to use, on a clock at *clock, and
// collects what it logs.
func pickerOf(t *testing.T, addr string, clock *time.Time) (*proxyPicker, *logLines) {
	t.Helper()
	return cloudPicker(&fakeScutil{output: proxiesAt(t, addr, addr)}, clock)
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

// onceBody is a request body that cannot be read once closed, as one read
// from a file or a pipe cannot.
type onceBody struct {
	io.Reader
	closed atomic.Bool
}

func (b *onceBody) Read(p []byte) (int, error) {
	if b.closed.Load() {
		return 0, errors.New("read after close")
	}
	return b.Reader.Read(p)
}

func (b *onceBody) Close() error {
	b.closed.Store(true)
	return nil
}

// A request goes directly, its body read anew, when the proxy macOS is set to
// use is down, and the switch is logged.
func TestDownMacOSProxyGoesDirect(t *testing.T) {
	cloud := newCloudFake(t)
	clock := time.Now()
	p, logs := pickerOf(t, downProxy(t), &clock)
	req, err := http.NewRequest(http.MethodPost, "https://cloud.example.com/v1/ingest", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Body, req.ContentLength = &onceBody{Reader: strings.NewReader("batch")}, int64(len("batch"))
	req.GetBody = func() (io.ReadCloser, error) { return &onceBody{Reader: strings.NewReader("batch")}, nil }

	answer, err := answerOf(cloud.client(t, p, time.Minute).Do(req))
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
// and in its answer to the request itself for an http one. That answer cannot
// prove the proxy kept an http request from the server, so an http POST gets
// it back instead.
func TestMacOSProxyWantingAPasswordGoesDirect(t *testing.T) {
	for _, test := range []struct {
		name, url, answer string
		post              bool
		got, logged       []string
	}{
		{"https POST", "https://cloud.example.com/v1/ingest", "200 OK from the cloud", true,
			[]string{"POST /v1/ingest batch"}, []string{"cloud proxy failed (Proxy Authentication Required); going direct\n"}},
		{"http GET", "http://cloud.example.com/v1/ingest", "200 OK from the cloud", false,
			[]string{"GET /v1/ingest "}, []string{"cloud proxy failed (407 Proxy Authentication Required); going direct\n"}},
		{"http POST", "http://cloud.example.com/v1/ingest", "407 Proxy Authentication Required ", true, nil, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			cloud := newCloudFake(t)
			proxy := newProxyFake(t, askForPassword)
			clock := time.Now()
			p, logs := pickerOf(t, proxy.addr, &clock)
			client := cloud.client(t, p, time.Minute)

			send := func() (string, error) { return get(client, test.url) }
			if test.post {
				send = func() (string, error) { return post(client, test.url, "batch") }
			}
			answer, err := send()
			if err != nil || answer != test.answer {
				t.Fatalf("answer %q, %v", answer, err)
			}
			if asked, direct := proxy.asked.Load(), cloud.direct.Load(); asked != 1 || int(direct) != len(test.got) {
				t.Fatalf("the proxy was asked %d times, and the cloud dialed directly %d times", asked, direct)
			}
			if got := cloud.gotNow(); !slices.Equal(got, test.got) {
				t.Fatalf("the cloud got %q", got)
			}
			if lines := logs.all(); !slices.Equal(lines, test.logged) {
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
			p, logs := pickerOf(t, proxy.addr, &clock)
			client := cloud.client(t, p, test.patience)
			client.Timeout = test.timeout

			answer, err := post(client, "https://cloud.example.com/v1/ingest", "batch")
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
	p, logs := pickerOf(t, proxy.addr, &clock)
	client := cloud.client(t, p, 200*time.Millisecond)

	for _, path := range []string{"/slow", "/stream", "/v1/ingest"} {
		answer, err := post(client, "https://cloud.example.com"+path, "batch")
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
	p, logs := pickerOf(t, proxy.addr, &clock)
	client := cloud.client(t, p, time.Minute)
	send := func(asked int32, logged int) {
		t.Helper()
		if answer, err := post(client, "https://cloud.example.com/v1/ingest", "batch"); err != nil || answer != "200 OK from the cloud" {
			t.Fatalf("answer %q, %v", answer, err)
		}
		if got, lines := proxy.asked.Load(), logs.all(); got != asked || len(lines) != logged {
			t.Fatalf("the proxy was asked %d times, not %d, and %q logged", got, asked, lines)
		}
	}

	send(1, 1)
	// A request that went through the proxy before the switch fails after it.
	p.goDirect(&url.URL{Scheme: "http", Host: proxy.addr}, "Proxy Authentication Required")
	clock = clock.Add(directFor - time.Second)
	send(1, 1)
	clock = clock.Add(time.Second)
	send(2, 2)
	clock = clock.Add(-time.Hour)
	send(3, 3)
}

// Requests skip only the proxy that failed: once macOS is set to use another,
// as on another network, they go through that one at once.
func TestRequestsGoThroughANewMacOSProxy(t *testing.T) {
	cloud := newCloudFake(t)
	broken := newProxyFake(t, askForPassword)
	working := newProxyFake(t, tunnelTo(cloud.https.Listener.Addr().String()))
	scutil := &fakeScutil{output: proxiesAt(t, broken.addr, broken.addr)}
	clock := time.Now()
	p, logs := cloudPicker(scutil, &clock)
	client := cloud.client(t, p, time.Minute)

	for _, proxy := range []*proxyFake{broken, working} {
		scutil.output = proxiesAt(t, proxy.addr, proxy.addr)
		clock = clock.Add(systemProxiesAge)
		if answer, err := post(client, "https://cloud.example.com/v1/ingest", "batch"); err != nil || answer != "200 OK from the cloud" {
			t.Fatalf("answer %q, %v", answer, err)
		}
	}
	if asked, direct, lines := working.asked.Load(), cloud.direct.Load(), logs.all(); asked != 1 || direct != 1 || len(lines) != 1 {
		t.Fatalf("the new proxy was asked %d times, the cloud dialed directly %d times, and %q logged", asked, direct, lines)
	}
}

// Requests skip each proxy that failed one: alternating between two that
// both did, as http and https requests do when macOS's web proxy and secure
// web proxy differ, asks each of them once.
func TestRequestsSkipEachProxyThatFailed(t *testing.T) {
	cloud := newCloudFake(t)
	web, secure := newProxyFake(t, askForPassword), newProxyFake(t, askForPassword)
	clock := time.Now()
	p, logs := cloudPicker(&fakeScutil{output: proxiesAt(t, web.addr, secure.addr)}, &clock)
	client := cloud.client(t, p, time.Minute)

	for range 2 {
		if answer, err := get(client, "http://cloud.example.com/v1/ingest"); err != nil || answer != "200 OK from the cloud" {
			t.Fatalf("answer %q, %v", answer, err)
		}
		if answer, err := post(client, "https://cloud.example.com/v1/ingest", "batch"); err != nil || answer != "200 OK from the cloud" {
			t.Fatalf("answer %q, %v", answer, err)
		}
	}
	if webAsked, secureAsked, lines := web.asked.Load(), secure.asked.Load(), logs.all(); webAsked != 1 || secureAsked != 1 || len(lines) != 2 {
		t.Fatalf("the web proxy was asked %d times, the secure web proxy %d times, and %q logged", webAsked, secureAsked, lines)
	}
}

// A direct request that fails at the server still shows that the way out
// directly works when it got a new connection to the server, so requests
// switch; one that failed on a connection from before shows nothing, so they
// do not.
func TestFailedDirectRequestsSwitchOnlyOnANewConnection(t *testing.T) {
	cloud := newCloudFake(t)
	proxy := newProxyFake(t, askForPassword)
	clock := time.Now()
	p, logs := pickerOf(t, proxy.addr, &clock)
	client := cloud.client(t, p, time.Minute)
	send := func(path string, asked int32, logged int) {
		t.Helper()
		answer, err := post(client, "https://cloud.example.com"+path, "batch")
		if (err == nil) != (path != "/drop") {
			t.Fatalf("answer %q, %v", answer, err)
		}
		if got, lines := proxy.asked.Load(), logs.all(); got != asked || len(lines) != logged {
			t.Fatalf("the proxy was asked %d times, not %d, and %q logged", got, asked, lines)
		}
	}

	// The server drops the request on a new direct connection.
	send("/drop", 1, 1)
	// Going directly, a request leaves its connection idle.
	send("/v1/ingest", 1, 1)
	clock = clock.Add(directFor)
	// The server drops the request on that connection.
	send("/drop", 2, 1)
	send("/v1/ingest", 3, 2)
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
			p, logs := pickerOf(t, proxy.addr, &clock)

			if answer, err := post(cloud.client(t, p, time.Minute), test.url, "batch"); err == nil {
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
	p, logs := pickerOf(t, proxy.addr, &clock)
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
		if _, err := post(client, "https://cloud.example.com/v1/ingest", "batch"); err == nil || !strings.Contains(err.Error(), "Proxy Authentication Required") {
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
	p, logs := pickerOf(t, downProxy(t), &clock)
	p.getenv = func(name string) string {
		if name == "HTTPS_PROXY" {
			return "http://" + proxy.addr
		}
		return ""
	}
	p.fromEnvironment = func(*http.Request) (*url.URL, error) { return &url.URL{Scheme: "http", Host: proxy.addr}, nil }

	if answer, err := post(cloud.client(t, p, time.Minute), "https://cloud.example.com/v1/ingest", "batch"); err == nil {
		t.Fatalf("answer %q", answer)
	}
	if asked, direct, lines := proxy.asked.Load(), cloud.direct.Load(), logs.all(); asked != 1 || direct != 0 || len(lines) != 0 {
		t.Fatalf("the proxy was asked %d times, the cloud dialed directly %d times, and %q logged", asked, direct, lines)
	}
}
