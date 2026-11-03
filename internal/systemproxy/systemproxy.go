// Package systemproxy reads the manual proxies macOS is set to use, which Go
// never reads, from what scutil --proxy prints, so no cgo is needed. It gives
// them as the proxy variables Go reads, for a process started with those, and
// as the proxy those variables would give a URL, for this one.
package systemproxy

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Scutil is what scutil --proxy prints: the proxies macOS is set to use.
func Scutil(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/usr/sbin/scutil", "--proxy").Output()
	return string(output), err
}

// Proxies are the manual proxies macOS is set to use, as the values of the
// variables Go reads: HTTPS_PROXY for the secure web proxy and HTTP_PROXY for
// the web proxy, both of which macOS speaks HTTP to, and NO_PROXY for the
// hosts and domains it sends around them (see noProxy). A value is "" when
// its variable is not set. A PAC file or proxy auto-discovery cannot be
// expressed as variables, and the password of a proxy that needs one stays in
// the keychain.
type Proxies struct {
	HTTPS, HTTP, NoProxy string
}

// Parse reads the manual proxies in what scutil --proxy printed. It reports
// false when output is not what scutil --proxy prints.
func Parse(output string) (Proxies, bool) {
	settings, exceptions, ok := parseProxies(output)
	if !ok {
		return Proxies{}, false
	}
	var proxies Proxies
	if settings["HTTPSEnable"] == "1" {
		proxies.HTTPS = proxyURL(settings["HTTPSProxy"], settings["HTTPSPort"])
	}
	if settings["HTTPEnable"] == "1" {
		proxies.HTTP = proxyURL(settings["HTTPProxy"], settings["HTTPPort"])
	}
	// Without a proxy the exceptions mean nothing, and would only change the
	// environment Env gives when they change.
	if proxies.HTTPS != "" || proxies.HTTP != "" {
		proxies.NoProxy = noProxy(exceptions)
	}
	return proxies, true
}

// Env is p as a process's environment: the variables that are set, in the
// order HTTPS_PROXY, HTTP_PROXY, NO_PROXY.
func (p Proxies) Env() [][2]string {
	var env [][2]string
	for _, variable := range [][2]string{{"HTTPS_PROXY", p.HTTPS}, {"HTTP_PROXY", p.HTTP}, {"NO_PROXY", p.NoProxy}} {
		if variable[1] != "" {
			env = append(env, variable)
		}
	}
	return env
}

// parseProxies reads the settings at the top of what scutil --proxy prints,
// and the entries of their ExceptionsList; the settings it prints for each
// network interface (__SCOPED__) are left out. It reports false for output
// of another shape.
func parseProxies(output string) (map[string]string, []string, bool) {
	settings := map[string]string{}
	var exceptions []string
	// depth counts the dictionaries and arrays open, the outer dictionary
	// among them.
	depth, inExceptions, closed := 0, false, false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
			continue
		case closed:
			return nil, nil, false
		case depth == 0:
			if line != "<dictionary> {" {
				return nil, nil, false
			}
			depth = 1
			continue
		case line == "}":
			depth--
			inExceptions = inExceptions && depth > 1
			closed = depth == 0
			continue
		}
		// Other lines are a key, which holds no space, a colon and a value,
		// which may be empty or hold colons of its own.
		key, value, _ := strings.Cut(line, " ")
		value, ok := strings.CutPrefix(value, ":")
		if !ok {
			return nil, nil, false
		}
		value = strings.TrimSpace(value)
		if value == "<dictionary> {" || value == "<array> {" {
			inExceptions = inExceptions || depth == 1 && key == "ExceptionsList"
			depth++
			continue
		}
		switch {
		case depth == 1:
			settings[key] = value
		case depth == 2 && inExceptions:
			exceptions = append(exceptions, value)
		}
	}
	return settings, exceptions, closed
}

// proxyURL is the URL of the proxy at host and port, or "" when they do not
// name one: host is a name or an IP address.
func proxyURL(host, port string) string {
	if number, err := strconv.Atoi(port); err != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port {
		return ""
	}
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return ""
	}
	address := "http://" + net.JoinHostPort(host, port)
	if parsed, err := url.Parse(address); host == "" || err != nil || parsed.Hostname() != host || parsed.Port() != port {
		return ""
	}
	return address
}

// noProxy is macOS's proxy exceptions as Go's NO_PROXY reads them, or "". Go
// reads hosts, domains (example.com, .example.com and *.example.com), IP
// addresses and CIDR blocks as macOS writes them, except blocks whose address
// leaves octets out (169.254/16), which get them back. Entries with other
// wildcards (10.*), or that would not stay one entry, are left out, as are
// the simple hostnames macOS can exclude on a switch of its own: their
// requests go through the proxy.
func noProxy(exceptions []string) string {
	var entries []string
	for _, exception := range exceptions {
		if entry, ok := noProxyEntry(exception); ok {
			entries = append(entries, entry)
		}
	}
	return strings.Join(entries, ",")
}

func noProxyEntry(exception string) (string, bool) {
	if exception == "" || strings.ContainsAny(exception, ", \t") {
		return "", false
	}
	if address, bits, ok := strings.Cut(exception, "/"); ok {
		if !strings.Contains(address, ":") {
			for strings.Count(address, ".") < 3 {
				address += ".0"
			}
		}
		_, block, err := net.ParseCIDR(address + "/" + bits)
		if err != nil {
			return "", false
		}
		return block.String(), true
	}
	if exception != "*" && strings.Contains(strings.TrimPrefix(exception, "*."), "*") {
		return "", false
	}
	return exception, true
}

// ProxyFunc gives the proxy a request to a URL goes through, or nil when it
// goes directly, as http.ProxyFromEnvironment does in a process whose
// environment is p.Env(): the secure web proxy for https URLs and the web
// proxy for http ones, except for localhost, loopback addresses and the hosts
// NoProxy names. Go compares a host name in Unicode by its ASCII form; here
// names are compared as written.
func (p Proxies) ProxyFunc() func(*url.URL) *url.URL {
	https, http := parseProxyURL(p.HTTPS), parseProxyURL(p.HTTP)
	exceptions := readNoProxy(p.NoProxy)
	return func(u *url.URL) *url.URL {
		var proxy *url.URL
		switch u.Scheme {
		case "https":
			proxy = https
		case "http":
			proxy = http
		}
		if proxy == nil || exceptions.direct(u) {
			return nil
		}
		return proxy
	}
}

func parseProxyURL(address string) *url.URL {
	if address == "" {
		return nil
	}
	proxy, err := url.Parse(address)
	if err != nil {
		return nil
	}
	return proxy
}

// exceptions are the entries of a NO_PROXY value, as Go reads them.
type exceptions struct {
	all     bool
	blocks  []*net.IPNet
	ips     []ipException
	domains []domainException
}

// ipException is an IP address, on port unless that is "".
type ipException struct {
	ip   net.IP
	port string
}

// domainException is the hosts whose names end in suffix, which starts with a
// dot, and when host is set the one that suffix names without it, on port
// unless that is "".
type domainException struct {
	suffix, port string
	host         bool
}

func readNoProxy(value string) exceptions {
	var e exceptions
	for _, entry := range strings.Split(value, ",") {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry == "*" {
			return exceptions{all: true}
		}
		if _, block, err := net.ParseCIDR(entry); err == nil {
			e.blocks = append(e.blocks, block)
			continue
		}
		host, port, err := net.SplitHostPort(entry)
		if err != nil {
			host, port = entry, ""
		}
		if ip := net.ParseIP(host); ip != nil {
			e.ips = append(e.ips, ipException{ip: ip, port: port})
			continue
		}
		if host == "" {
			continue
		}
		// example.com is that host and those under it, .example.com and
		// *.example.com only those under it.
		if strings.HasPrefix(host, "*.") {
			host = host[1:]
		}
		exception := domainException{suffix: host, port: port, host: host[0] != '.'}
		if exception.host {
			exception.suffix = "." + host
		}
		e.domains = append(e.domains, exception)
	}
	return e
}

// defaultPorts are the ports of URLs that name none.
var defaultPorts = map[string]string{"http": "80", "https": "443"}

// Local reports whether a request to u stays on this machine: its host is
// localhost or a loopback address, which Go never sends through a proxy.
func Local(u *url.URL) bool {
	return u.Hostname() == "localhost" || hostIP(u.Hostname()).IsLoopback()
}

// hostIP is host's IP address, or nil when it is a name.
func hostIP(host string) net.IP {
	address, err := netip.ParseAddr(host)
	if err != nil {
		return nil
	}
	return net.IP(address.AsSlice())
}

// direct reports whether a request to u goes around the proxy.
func (e exceptions) direct(u *url.URL) bool {
	if e.all || Local(u) {
		return true
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = defaultPorts[u.Scheme]
	}
	if ip := hostIP(host); ip != nil {
		for _, block := range e.blocks {
			if block.Contains(ip) {
				return true
			}
		}
		for _, exception := range e.ips {
			if exception.ip.Equal(ip) && (exception.port == "" || exception.port == port) {
				return true
			}
		}
		return false
	}
	host = strings.ToLower(host)
	for _, exception := range e.domains {
		if (strings.HasSuffix(host, exception.suffix) || exception.host && host == exception.suffix[1:]) &&
			(exception.port == "" || exception.port == port) {
			return true
		}
	}
	return false
}
