package cloudhttp

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// noProxies is what scutil --proxy prints on a Mac set to use no proxy,
// manualProxies on one set to use a web proxy and a secure web proxy, with
// macOS's own exceptions and one more, and pacProxies on one set to use a PAC
// file.
const (
	noProxies = `<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
    1 : 169.254/16
  }
  FTPPassive : 1
}
`
	manualProxies = `<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
    1 : 169.254/16
    2 : *.intranet.example
  }
  FTPPassive : 1
  HTTPEnable : 1
  HTTPPort : 8080
  HTTPProxy : proxy.example
  HTTPSEnable : 1
  HTTPSPort : 3128
  HTTPSProxy : proxy.example
}
`
	pacProxies = `<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
    1 : 169.254/16
  }
  FTPPassive : 1
  ProxyAutoConfigEnable : 1
  ProxyAutoConfigURLString : http://wpad.example/proxy.pac
}
`
)

// fakeScutil prints output, or fails with err, and counts its runs. While
// block is set, a run waits for it to close first.
type fakeScutil struct {
	output string
	err    error
	block  chan struct{}
	runs   atomic.Int32
}

func (s *fakeScutil) run(context.Context) (string, error) {
	s.runs.Add(1)
	if s.block != nil {
		<-s.block
	}
	return s.output, s.err
}

// fromEnvironment stands for the proxy the environment names.
var fromEnvironment = &url.URL{Scheme: "http", Host: "environment.example:3128"}

// testPicker picks proxies from env and the proxies scutil prints, on a clock
// at *clock. Its requests wait for any read under way, which a fake finishes
// at once unless it blocks.
func testPicker(env map[string]string, scutil *fakeScutil, clock *time.Time) *proxyPicker {
	return &proxyPicker{
		getenv:          func(name string) string { return env[name] },
		fromEnvironment: func(*http.Request) (*url.URL, error) { return fromEnvironment, nil },
		system:          scutil.run,
		now:             func() time.Time { return *clock },
		wait:            time.Minute,
	}
}

// settle waits for the read p has under way, if any.
func settle(p *proxyPicker) {
	p.mu.Lock()
	reading := p.reading
	p.mu.Unlock()
	if reading != nil {
		<-reading
	}
}

// proxyOf is the proxy p picks for a request to rawURL, or "" when it goes
// directly.
func proxyOf(t *testing.T, p *proxyPicker, rawURL string) string {
	t.Helper()
	return proxyWithin(t, context.Background(), p, rawURL)
}

// proxyWithin is the proxy p picks for a request to rawURL made with ctx.
func proxyWithin(t *testing.T, ctx context.Context, p *proxyPicker, rawURL string) string {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := p.proxyFor(req)
	if err != nil {
		t.Fatal(err)
	}
	if proxy == nil {
		return ""
	}
	return proxy.String()
}

func TestPickerUsesMacOSManualProxies(t *testing.T) {
	clock := time.Now()
	scutil := &fakeScutil{output: manualProxies}
	p := testPicker(nil, scutil, &clock)
	for rawURL, want := range map[string]string{
		"https://api.kontext.example/v1/endpoint-config": "http://proxy.example:3128",
		"http://api.kontext.example/":                    "http://proxy.example:8080",
		// The exceptions go directly.
		"https://kontext.intranet.example/": "", "https://kontext.local/": "", "https://169.254.1.1/": "",
	} {
		if got := proxyOf(t, p, rawURL); got != want {
			t.Errorf("%s goes through %q, want %q", rawURL, got, want)
		}
	}
	if scutil.runs.Load() != 1 {
		t.Fatalf("scutil ran %d times for requests at the same moment", scutil.runs.Load())
	}
}

// Requests that stay on this machine never go through a proxy, so they do not
// run scutil.
func TestLocalRequestsDoNotReadMacOSProxies(t *testing.T) {
	clock := time.Now()
	scutil := &fakeScutil{output: manualProxies}
	p := testPicker(nil, scutil, &clock)
	for _, rawURL := range []string{"http://localhost:8080/", "https://127.0.0.1:8443/", "https://[::1]/"} {
		if got := proxyOf(t, p, rawURL); got != "" {
			t.Errorf("%s goes through %q", rawURL, got)
		}
	}
	if scutil.runs.Load() != 0 {
		t.Fatalf("scutil ran %d times", scutil.runs.Load())
	}
}

func TestPickerGoesDirectlyWithoutManualProxies(t *testing.T) {
	for name, output := range map[string]string{"no proxy": noProxies, "a PAC file": pacProxies} {
		clock := time.Now()
		if got := proxyOf(t, testPicker(nil, &fakeScutil{output: output}, &clock), "https://api.kontext.example/"); got != "" {
			t.Errorf("%s: requests go through %q", name, got)
		}
	}
}

// Any proxy variable leaves the proxy to the environment, and macOS's are
// not read; one set to "" is not set.
func TestEnvironmentProxiesWin(t *testing.T) {
	for _, name := range proxyVariables {
		clock := time.Now()
		scutil := &fakeScutil{output: manualProxies}
		p := testPicker(map[string]string{name: "http://environment.example:3128"}, scutil, &clock)
		if got := proxyOf(t, p, "https://api.kontext.example/"); got != fromEnvironment.String() || scutil.runs.Load() != 0 {
			t.Errorf("with %s set, requests go through %q after %d scutil runs", name, got, scutil.runs.Load())
		}
	}
	clock := time.Now()
	p := testPicker(map[string]string{"HTTPS_PROXY": "", "no_proxy": ""}, &fakeScutil{output: manualProxies}, &clock)
	if got := proxyOf(t, p, "https://api.kontext.example/"); got != "http://proxy.example:3128" {
		t.Fatalf("with empty variables, requests go through %q", got)
	}
}

func TestPickerReadsMacOSProxiesAgainAsTheyAge(t *testing.T) {
	clock := time.Now()
	scutil := &fakeScutil{output: noProxies}
	p := testPicker(nil, scutil, &clock)
	proxyOf(t, p, "https://api.kontext.example/")
	// The Mac joins a network that needs a proxy.
	scutil.output = manualProxies
	clock = clock.Add(systemProxiesAge - time.Second)
	if got := proxyOf(t, p, "https://api.kontext.example/"); got != "" || scutil.runs.Load() != 1 {
		t.Fatalf("before they age, requests go through %q after %d scutil runs", got, scutil.runs.Load())
	}
	clock = clock.Add(time.Second)
	if got := proxyOf(t, p, "https://api.kontext.example/"); got != "http://proxy.example:3128" || scutil.runs.Load() != 2 {
		t.Fatalf("once they aged, requests go through %q after %d scutil runs", got, scutil.runs.Load())
	}
	// A clock set back reads them again too.
	scutil.output = noProxies
	clock = clock.Add(-time.Second)
	if got := proxyOf(t, p, "https://api.kontext.example/"); got != "" || scutil.runs.Load() != 3 {
		t.Fatalf("after the clock went back, requests go through %q after %d scutil runs", got, scutil.runs.Load())
	}
}

// Requests go on through the proxies read last when scutil fails or prints
// something else, and directly before any were read.
func TestPickerKeepsTheProxiesItCouldRead(t *testing.T) {
	clock := time.Now()
	scutil := &fakeScutil{err: errors.New("exit status 1")}
	p := testPicker(nil, scutil, &clock)
	if got := proxyOf(t, p, "https://api.kontext.example/"); got != "" {
		t.Fatalf("with no proxies read, requests go through %q", got)
	}
	scutil.output, scutil.err = manualProxies, nil
	clock = clock.Add(systemProxiesAge)
	if got := proxyOf(t, p, "https://api.kontext.example/"); got != "http://proxy.example:3128" {
		t.Fatalf("requests go through %q", got)
	}
	for _, answer := range []struct {
		output string
		err    error
	}{{err: context.DeadlineExceeded}, {output: "No proxy configuration available\n"}} {
		scutil.output, scutil.err = answer.output, answer.err
		clock = clock.Add(systemProxiesAge)
		if got := proxyOf(t, p, "https://api.kontext.example/"); got != "http://proxy.example:3128" {
			t.Errorf("after scutil printed %q (%v), requests go through %q", answer.output, answer.err, got)
		}
	}
	if scutil.runs.Load() != 4 {
		t.Fatalf("scutil ran %d times, want 4", scutil.runs.Load())
	}
}

// A read that hangs holds a request up no longer than the request's deadline
// or the picker's wait, starts no second read, and leaves requests on the
// proxies read before.
func TestHangingReadsHoldRequestsUpBriefly(t *testing.T) {
	clock := time.Now()
	scutil := &fakeScutil{output: manualProxies, block: make(chan struct{})}
	p := testPicker(nil, scutil, &clock)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if got := proxyWithin(t, ctx, p, "https://api.kontext.example/"); got != "" {
		t.Fatalf("before any proxies were read, a request went through %q", got)
	}
	p.wait = 20 * time.Millisecond
	clock = clock.Add(systemProxiesAge)
	if got := proxyOf(t, p, "https://api.kontext.example/"); got != "" || scutil.runs.Load() != 1 {
		t.Fatalf("while the first read hangs, a request goes through %q after %d scutil runs", got, scutil.runs.Load())
	}
	close(scutil.block)
	settle(p)
	if got := proxyOf(t, p, "https://api.kontext.example/"); got != "http://proxy.example:3128" || scutil.runs.Load() != 2 {
		t.Fatalf("once the read ended, requests go through %q after %d scutil runs", got, scutil.runs.Load())
	}
	release := make(chan struct{})
	scutil.output, scutil.block = noProxies, release
	clock = clock.Add(systemProxiesAge)
	if got := proxyOf(t, p, "https://api.kontext.example/"); got != "http://proxy.example:3128" {
		t.Fatalf("while a read hangs, requests go through %q", got)
	}
	close(release)
	settle(p)
	if got := proxyOf(t, p, "https://api.kontext.example/"); got != "" || scutil.runs.Load() != 3 {
		t.Fatalf("after the hanging read, requests go through %q after %d scutil runs", got, scutil.runs.Load())
	}
}

func TestPickerReadsMacOSProxiesOnlyOnAMac(t *testing.T) {
	if reads := newProxyPicker().system != nil; reads != (runtime.GOOS == "darwin") {
		t.Fatalf("on %s the picker reads macOS's proxies: %v", runtime.GOOS, reads)
	}
	clock := time.Now()
	p := testPicker(nil, nil, &clock)
	p.system = nil
	if got := proxyOf(t, p, "https://api.kontext.example/"); got != "" {
		t.Fatalf("off a Mac, requests go through %q", got)
	}
}

// useMacOSProxies has the shared transport's requests pick their proxies from
// what scutil prints as output, whatever this process's environment holds,
// for the rest of the test.
func useMacOSProxies(t *testing.T, output string) {
	t.Helper()
	settle(cloudProxies)
	cloudProxies.mu.Lock()
	defer cloudProxies.mu.Unlock()
	getenv, system := cloudProxies.getenv, cloudProxies.system
	cloudProxies.getenv = func(string) string { return "" }
	cloudProxies.system = func(context.Context) (string, error) { return output, nil }
	cloudProxies.readAt, cloudProxies.proxy = time.Time{}, nil
	t.Cleanup(func() {
		sharedTransport.CloseIdleConnections()
		settle(cloudProxies)
		cloudProxies.mu.Lock()
		defer cloudProxies.mu.Unlock()
		cloudProxies.getenv, cloudProxies.system = getenv, system
		cloudProxies.readAt, cloudProxies.proxy = time.Time{}, nil
	})
}

// fakeProxy is a proxy that answers plain HTTP requests itself and refuses to
// tunnel, telling asked about each request.
func fakeProxy(t *testing.T, asked chan<- string) (host, port string) {
	t.Helper()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			asked <- "CONNECT " + r.Host
			http.Error(w, "no tunnels here", http.StatusForbidden)
			return
		}
		asked <- r.Method + " " + r.URL.String()
		_, _ = io.WriteString(w, "from the proxy")
	}))
	t.Cleanup(proxy.Close)
	host, port, err := net.SplitHostPort(proxy.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

// askedOf is the request a fake proxy was asked, or "" when none came.
func askedOf(asked <-chan string) string {
	select {
	case request := <-asked:
		return request
	case <-time.After(5 * time.Second):
		return ""
	}
}

// The clients' requests go through macOS's secure web proxy and web proxy.
// Both fakes answer themselves, so nothing leaves this machine.
func TestCloudClientsGoThroughMacOSProxies(t *testing.T) {
	secureAsked, webAsked := make(chan string, 1), make(chan string, 1)
	secureHost, securePort := fakeProxy(t, secureAsked)
	webHost, webPort := fakeProxy(t, webAsked)
	useMacOSProxies(t, "<dictionary> {\n  HTTPEnable : 1\n  HTTPPort : "+webPort+"\n  HTTPProxy : "+webHost+
		"\n  HTTPSEnable : 1\n  HTTPSPort : "+securePort+"\n  HTTPSProxy : "+secureHost+"\n}\n")
	client := NewClient(5 * time.Second)

	if resp, err := client.Get("https://api.kontext.example/v1/endpoint-config"); err == nil {
		resp.Body.Close()
		t.Fatal("the request went through although the secure web proxy refused to tunnel it")
	}
	if asked := askedOf(secureAsked); asked != "CONNECT api.kontext.example:443" {
		t.Fatalf("the secure web proxy was asked %q", asked)
	}

	resp, err := client.Get("http://api.kontext.example/v1/endpoint-config")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "from the proxy" {
		t.Fatalf("body %q, %v", body, err)
	}
	if asked := askedOf(webAsked); asked != "GET http://api.kontext.example/v1/endpoint-config" {
		t.Fatalf("the web proxy was asked %q", asked)
	}
}
