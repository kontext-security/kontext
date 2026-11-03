package cloudhttp

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/kontext-security/kontext/internal/systemproxy"
)

// proxyVariables are the variables http.ProxyFromEnvironment reads.
var proxyVariables = []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"}

// systemProxiesAge is how long requests go on through the proxies macOS was
// set to use when they were read, before the next request reads them again:
// they change as the Mac moves from network to network, and each read runs
// scutil.
const systemProxiesAge = 30 * time.Second

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

	mu     sync.Mutex
	readAt time.Time
	proxy  func(*url.URL) *url.URL
}

// cloudProxies picks the proxies of the shared transport's requests.
var cloudProxies = newProxyPicker()

func newProxyPicker() *proxyPicker {
	p := &proxyPicker{getenv: os.Getenv, fromEnvironment: http.ProxyFromEnvironment, now: time.Now}
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
	return p.systemProxy()(req.URL), nil
}

// systemProxy gives the proxy macOS's manual proxies send a URL through. It
// reads them again once they are systemProxiesAge old by the wall clock: Go's
// monotonic clock may stop while a Mac sleeps, and a Mac that wakes up has
// often moved to another network. When they cannot be read, requests go on
// through the ones read before, or directly when none were.
func (p *proxyPicker) systemProxy() func(*url.URL) *url.URL {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now().Round(0)
	if age := now.Sub(p.readAt); age < 0 || age >= systemProxiesAge {
		p.readAt = now
		// Not the request's context: a request given up on would leave the
		// ones after it on the proxies read before until the next read.
		if output, err := p.system(context.Background()); err == nil {
			if read, ok := systemproxy.Parse(output); ok {
				p.proxy = read.ProxyFunc()
			}
		}
	}
	if p.proxy == nil {
		return direct
	}
	return p.proxy
}

func direct(*url.URL) *url.URL { return nil }
