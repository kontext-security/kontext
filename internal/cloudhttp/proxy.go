package cloudhttp

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/systemproxy"
)

// proxyVariables are the variables http.ProxyFromEnvironment reads.
var proxyVariables = []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"}

// systemProxiesAge is how long requests go on through the proxies macOS was
// set to use when they were read, before the next request reads them again:
// they change as the Mac moves from network to network, and each read runs
// scutil.
const systemProxiesAge = 30 * time.Second

// systemProxiesWait is the longest a request waits for a read of macOS's
// proxies that is under way, as when scutil hangs, before it goes on without
// it: a request to the cloud may have a budget of less than scutil's timeout.
const systemProxiesWait = time.Second

// directFor is how long requests to the cloud skip a proxy macOS is set to use
// and go directly once one got through directly after the proxy failed it,
// before they try the proxy again: a proxy that is down or wants a password
// would otherwise hold up each of them (see directFallback).
const directFor = 5 * time.Minute

// proxyPicker picks the proxy of each request to the cloud: the one the
// environment names when it sets any proxy variable, read as
// http.ProxyFromEnvironment reads it, and otherwise the manual proxies macOS
// is set to use. A standard install starts the daemon without proxy
// variables, and Go never reads macOS's proxies, so on a network that lets
// traffic out only through one the daemon could not reach the cloud. Go reads
// the variables once per process, so macOS's proxies are not handed over as
// variables but read again as they age.
type proxyPicker struct {
	getenv          func(string) string
	fromEnvironment func(*http.Request) (*url.URL, error)
	// system prints the proxies macOS is set to use, as scutil --proxy does.
	// It is nil on other systems, where requests the environment names no
	// proxy for go directly.
	system func(context.Context) (string, error)
	now    func() time.Time
	// wait is how long a request waits for a read under way: systemProxiesWait.
	wait time.Duration
	// logf writes to the process log.
	logf func(format string, args ...any)

	mu     sync.Mutex
	readAt time.Time
	// reading is closed when the read under way ends, and nil while none is.
	reading chan struct{}
	// proxy gives the proxies read last, and is nil until a read succeeds.
	proxy func(*url.URL) *url.URL
	// direct is when requests last started skipping each proxy that failed
	// one, and going directly for directFor.
	direct map[string]time.Time
}

// cloudProxies picks the proxies of the shared transport's requests.
var cloudProxies = newProxyPicker()

func newProxyPicker() *proxyPicker {
	p := &proxyPicker{getenv: os.Getenv, fromEnvironment: http.ProxyFromEnvironment, now: time.Now, wait: systemProxiesWait, logf: logAlways}
	if runtime.GOOS == "darwin" {
		p.system = systemproxy.Scutil
	}
	return p
}

// proxyFor is the proxy req goes through, or nil when it goes directly.
func (p *proxyPicker) proxyFor(req *http.Request) (*url.URL, error) {
	for _, name := range proxyVariables {
		if p.getenv(name) != "" {
			return p.fromEnvironment(req)
		}
	}
	// A request that stays on this machine never goes through a proxy, so it
	// need not run scutil.
	if p.system == nil || systemproxy.Local(req.URL) {
		return nil, nil
	}
	// Nor does one sent again directly after a proxy of macOS's failed it.
	a := attemptOf(req.Context())
	if a != nil && a.direct {
		return nil, nil
	}
	// Requests skip a proxy for a while after it failed one, but macOS's
	// settings are still read, so that a Mac that moves to a network with
	// another proxy uses it at once.
	proxy := p.systemProxy(req.Context())(req.URL)
	if proxy == nil || p.goingDirect(proxy) {
		return nil, nil
	}
	if a != nil {
		a.through(req.Context(), proxy)
	}
	return proxy, nil
}

// goingDirect reports whether requests skip proxy and go directly for now:
// less than directFor ago by the wall clock, one got through directly after
// proxy failed it.
func (p *proxyPicker) goingDirect(proxy *url.URL) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	age := p.now().Round(0).Sub(p.direct[proxy.String()])
	return age >= 0 && age < directFor
}

// goDirect has requests skip proxy and go directly for directFor, as one just
// got through directly after proxy failed it with reason, and logs the
// switch. Requests that went through the proxy before the switch may fail
// after it, and switch nothing again. Each proxy that failed is skipped for
// its own directFor, as when macOS's web proxy and secure web proxy differ.
func (p *proxyPicker) goDirect(proxy *url.URL, reason string) {
	p.mu.Lock()
	now := p.now().Round(0)
	for key, at := range p.direct {
		if age := now.Sub(at); age < 0 || age >= directFor {
			delete(p.direct, key)
		}
	}
	_, skipped := p.direct[proxy.String()]
	if !skipped {
		if p.direct == nil {
			p.direct = make(map[string]time.Time)
		}
		p.direct[proxy.String()] = now
	}
	p.mu.Unlock()
	if !skipped {
		p.logf("cloud proxy failed (%s); going direct\n", reason)
	}
}

// systemProxy gives the proxy macOS's manual proxies send a URL through. Once
// they are systemProxiesAge old by the wall clock, the next request starts
// reading them again: Go's monotonic clock may stop while a Mac sleeps, and a
// Mac that wakes up has often moved to another network. A request waits for a
// read under way for no longer than p.wait, or than ctx allows, and then goes
// on through the proxies read before, or directly when none were, as it does
// when a read fails.
func (p *proxyPicker) systemProxy(ctx context.Context) func(*url.URL) *url.URL {
	p.mu.Lock()
	now := p.now().Round(0)
	if age := now.Sub(p.readAt); p.reading == nil && (age < 0 || age >= systemProxiesAge) {
		p.readAt, p.reading = now, make(chan struct{})
		go p.read(p.system, p.reading)
	}
	reading := p.reading
	p.mu.Unlock()
	if reading != nil {
		timer := time.NewTimer(p.wait)
		select {
		case <-reading:
		case <-timer.C:
		case <-ctx.Done():
		}
		timer.Stop()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.proxy == nil {
		return direct
	}
	return p.proxy
}

// read reads macOS's proxies with system, and closes done once it is over. It
// does not take a request's context: a request given up on would leave the ones
// after it on the proxies read before until the next read.
func (p *proxyPicker) read(system func(context.Context) (string, error), done chan struct{}) {
	var proxy func(*url.URL) *url.URL
	if output, err := system(context.Background()); err == nil {
		if read, ok := systemproxy.Parse(output); ok {
			proxy = read.ProxyFunc()
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if proxy != nil {
		p.proxy = proxy
	}
	p.reading = nil
	close(done)
}

func direct(*url.URL) *url.URL { return nil }

// logAlways writes to the process log, whether or not diagnostics are on.
func logAlways(format string, args ...any) {
	diagnostic.LogAlways(diagnostic.Logger{}, format, args...)
}
