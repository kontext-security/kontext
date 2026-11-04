package systemproxy

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// noProxies is what scutil --proxy prints on a Mac set to use no proxy.
const noProxies = `<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
    1 : 169.254/16
  }
  FTPPassive : 1
}
`

// manualProxies is what it prints on one set to use a web proxy and a secure
// web proxy, with macOS's own exceptions and two more, while a VPN's
// interface has a proxy of its own.
const manualProxies = `<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
    1 : 169.254/16
    2 : 10/8
    3 : *.intranet.example
  }
  ExcludeSimpleHostnames : 1
  FTPPassive : 1
  HTTPEnable : 1
  HTTPPort : 8080
  HTTPProxy : proxy.example
  HTTPSEnable : 1
  HTTPSPort : 3128
  HTTPSProxy : proxy.example
  ProxyAutoConfigEnable : 0
  SOCKSEnable : 0
  __SCOPED__ : <dictionary> {
    en0 : <dictionary> {
      ExceptionsList : <array> {
        0 : *.local
        1 : 169.254/16
        2 : 10/8
        3 : *.intranet.example
      }
      ExcludeSimpleHostnames : 1
      FTPPassive : 1
      HTTPEnable : 1
      HTTPPort : 8080
      HTTPProxy : proxy.example
      HTTPSEnable : 1
      HTTPSPort : 3128
      HTTPSProxy : proxy.example
      ProxyAutoConfigEnable : 0
      SOCKSEnable : 0
    }
    utun4 : <dictionary> {
      HTTPSEnable : 1
      HTTPSPort : 8443
      HTTPSProxy : vpn-proxy.example
    }
  }
}
`

// manualEnv is its proxies as an environment.
var manualEnv = [][2]string{{"HTTPS_PROXY", "http://proxy.example:3128"}, {"HTTP_PROXY", "http://proxy.example:8080"},
	{"NO_PROXY", "*.local,169.254.0.0/16,10.0.0.0/8,*.intranet.example"}}

// pacProxies is what it prints on one set to use a PAC file, and
// discoveryProxies on one set to discover its proxies.
const (
	pacProxies = `<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
    1 : 169.254/16
  }
  FTPPassive : 1
  HTTPEnable : 0
  HTTPSEnable : 0
  ProxyAutoConfigEnable : 1
  ProxyAutoConfigURLString : http://wpad.example/proxy.pac
  ProxyAutoDiscoveryEnable : 0
}
`
	discoveryProxies = `<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
    1 : 169.254/16
  }
  FTPPassive : 1
  ProxyAutoDiscoveryEnable : 1
}
`
)

func TestParse(t *testing.T) {
	proxies := func(settings string) string { return "<dictionary> {\n" + settings + "}\n" }
	for _, test := range []struct {
		name, output string
		want         [][2]string
	}{
		{"manual proxies", manualProxies, manualEnv},
		{"no proxy", noProxies, nil},
		{"a PAC file", pacProxies, nil},
		{"proxy auto-discovery", discoveryProxies, nil},
		{"a secure web proxy alone, at an IPv6 address, with no exceptions",
			proxies("  HTTPSEnable : 1\n  HTTPSPort : 3128\n  HTTPSProxy : fd00::3\n"), [][2]string{{"HTTPS_PROXY", "http://[fd00::3]:3128"}}},
		{"a proxy switched off", proxies("  HTTPSEnable : 0\n  HTTPSPort : 3128\n  HTTPSProxy : proxy.example\n"), nil},
		{"a proxy without a port", proxies("  HTTPSEnable : 1\n  HTTPSProxy : proxy.example\n"), nil},
		{"a proxy on a port out of range", proxies("  HTTPSEnable : 1\n  HTTPSPort : 65536\n  HTTPSProxy : proxy.example\n"), nil},
		{"a proxy without a host", proxies("  HTTPSEnable : 1\n  HTTPSPort : 3128\n  HTTPSProxy : \n"), nil},
		{"a proxy at a URL", proxies("  HTTPSEnable : 1\n  HTTPSPort : 3128\n  HTTPSProxy : http://proxy.example\n"), nil},
		{"a proxy at a host with a colon", proxies("  HTTPSEnable : 1\n  HTTPSPort : 3128\n  HTTPSProxy : proxy:example\n"), nil},
		{"a proxy at a host with a user", proxies("  HTTPSEnable : 1\n  HTTPSPort : 3128\n  HTTPSProxy : kim@proxy.example\n"), nil},
	} {
		if proxies, ok := Parse(test.output); !ok || !slices.Equal(proxies.Env(), test.want) {
			t.Errorf("%s: Parse = %q, %v; want %q", test.name, proxies.Env(), ok, test.want)
		}
	}
}

func TestParseRefusesOtherOutput(t *testing.T) {
	for _, output := range []string{"", "No proxy configuration available\n", "<array> {\n}\n",
		"<dictionary> {\n  HTTPSEnable : 1\n", noProxies + noProxies, "<dictionary> {\n  HTTPSEnable\n}\n"} {
		if proxies, ok := Parse(output); ok {
			t.Errorf("Parse(%q) = %q, true", output, proxies.Env())
		}
	}
}

func TestNoProxyKeepsWhatGoReads(t *testing.T) {
	for exception, want := range map[string]string{
		// Go reads these as they are.
		"*.local": "*.local", ".example.com": ".example.com", "example.com": "example.com", "example.com:8443": "example.com:8443",
		"localhost": "localhost", "127.0.0.1": "127.0.0.1", "fd00::1": "fd00::1", "*": "*",
		"172.16.0.0/12": "172.16.0.0/12", "fe80::/10": "fe80::/10",
		// CIDR blocks get back the octets macOS lets them leave out.
		"169.254/16": "169.254.0.0/16", "10/8": "10.0.0.0/8", "192.168.1/24": "192.168.1.0/24", "10.1.2.3/8": "10.0.0.0/8",
		// The rest goes.
		"10.*": "", "192.168.*.*": "", "*.example.*": "", "*example.com": "", "intranet,example": "", "intranet example": "",
		"": "", "300.1/16": "", "169.254/33": "", "1.2.3.4.5/8": "", "/16": "",
	} {
		if got := noProxy([]string{exception}); got != want {
			t.Errorf("noProxy(%q) = %q, want %q", exception, got, want)
		}
	}
	if got := noProxy([]string{"*.local", "10.*", "169.254/16"}); got != "*.local,169.254.0.0/16" {
		t.Errorf("noProxy of a list = %q", got)
	}
}

// proxyOf is the proxy that proxy gives rawURL, or "" when it goes directly.
func proxyOf(t *testing.T, proxy func(*url.URL) *url.URL, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	if p := proxy(u); p != nil {
		return p.String()
	}
	return ""
}

func TestProxyFunc(t *testing.T) {
	manual, _ := Parse(manualProxies)
	for rawURL, want := range map[string]string{
		"https://api.kontext.example/v1/config": "http://proxy.example:3128",
		"http://api.kontext.example/":           "http://proxy.example:8080",
		// macOS's own exceptions and the ones added to them.
		"https://printer.local/": "", "https://169.254.10.1/": "", "https://10.1.2.3:8443/": "", "https://wiki.intranet.example/": "",
		// *.intranet.example leaves out intranet.example itself.
		"https://intranet.example/": "http://proxy.example:3128",
		// Go never sends these through a proxy.
		"https://localhost:8443/": "", "https://127.0.0.1/": "", "http://[::1]:8080/": "", "ftp://files.example/": "",
	} {
		if got := proxyOf(t, manual.ProxyFunc(), rawURL); got != want {
			t.Errorf("manual proxies send %s through %q, want %q", rawURL, got, want)
		}
	}
	secure, _ := Parse("<dictionary> {\n  HTTPSEnable : 1\n  HTTPSPort : 3128\n  HTTPSProxy : proxy.example\n}\n")
	if got := proxyOf(t, secure.ProxyFunc(), "http://api.kontext.example/"); got != "" {
		t.Errorf("a secure web proxy alone sends an http URL through %q", got)
	}
	for name, output := range map[string]string{"no proxy": noProxies, "a PAC file": pacProxies, "proxy auto-discovery": discoveryProxies} {
		proxies, _ := Parse(output)
		if got := proxyOf(t, proxies.ProxyFunc(), "https://api.kontext.example/"); got != "" {
			t.Errorf("%s sends requests through %q", name, got)
		}
	}
}

func TestPunycode(t *testing.T) {
	for label, want := range map[string]string{
		"büro": "bro-hoa", "bücher": "bcher-kva", "münchen": "mnchen-3ya", "straße": "strae-oqa", "例え": "r8jz45g", "テスト": "zckzah",
	} {
		if got, ok := punycode(label); !ok || got != want {
			t.Errorf("punycode(%q) = %q, %v; want %q", label, got, ok, want)
		}
	}
}

// parityChild is set in the process that TestProxyFuncReadsTheEnvAsGoDoes
// starts, which prints the proxies http.ProxyFromEnvironment gives
// parityURLs.
const parityChild = "KONTEXT_SYSTEMPROXY_PARITY_CHILD"

// parityURLs are the URLs it asks about: one for each kind of entry, on the
// entry's port and another, and the hosts Go never sends through a proxy.
var parityURLs = []string{
	"https://api.kontext.example/", "http://api.kontext.example/", "ftp://api.kontext.example/",
	"https://printer.local/", "https://local/", "https://169.254.10.1/", "https://[fe80::1%25en0]/", "https://[fe80::1]:8443/",
	"https://wiki.intranet.example/", "https://intranet.example/", "https://a.corp.example/", "https://corp.example/",
	"https://exact.example/", "https://sub.exact.example/", "http://exact.example:8080/",
	"https://ported.example:8443/", "https://ported.example/", "http://ported.example:8443/",
	"https://192.0.2.7/", "https://192.0.2.7:8443/", "https://[::ffff:192.0.2.7]/", "http://198.51.100.9:8080/", "http://198.51.100.9/", "https://203.0.113.7/",
	"https://[fd00::1]/", "https://[fd00::2]:8443/", "https://[fd00::2]/", "https://[fd00::3]/",
	"https://mixed.example/", "https://MIXED.EXAMPLE/", "http://other.example:8080/",
	"https://localhost/", "https://LOCALHOST/", "https://127.0.0.2:8443/", "https://[::1]/", "https://[::ffff:127.0.0.1]/", "https://[::1%25lo0]/",
	// Names in Unicode, against entries in Unicode and in ASCII.
	"https://büro.example/", "https://BÜRO.example/", "https://xn--bro-hoa.example/", "https://bu\u0308ro.example/",
	"https://a.bücher.example/", "https://a.xn--bcher-kva.example/", "https://bücher.example/",
	"https://例え.テスト/", "https://例え。テスト/", "https://xn--r8jz45g.xn--zckzah/", "https://straße.example/", "https://xn--strae-oqa.example/",
	"https://full.example/", "https://ｆｕｌｌ.example/", "https://ｌｏｃａｌｈｏｓｔ/", "https://other.テスト/",
}

// Whatever ProxyFunc gives a URL is what http.ProxyFromEnvironment gives it
// in a process started with Env, as the Codex proxy job is. Go reads the
// environment once per process, so a child process reads it.
func TestProxyFuncReadsTheEnvAsGoDoes(t *testing.T) {
	if os.Getenv(parityChild) == "1" {
		answers := map[string]string{}
		for _, rawURL := range parityURLs {
			u, err := url.Parse(rawURL)
			if err != nil {
				t.Fatal(err)
			}
			proxy, err := http.ProxyFromEnvironment(&http.Request{URL: u})
			if err != nil {
				t.Fatal(err)
			}
			if proxy != nil {
				answers[rawURL] = proxy.String()
			}
		}
		out, err := json.Marshal(answers)
		if err != nil {
			t.Fatal(err)
		}
		os.Stdout.WriteString("\nPROXIES " + string(out) + "\n")
		return
	}
	for _, noProxy := range []string{
		"*.local,169.254.0.0/16,fe80::/10,*.intranet.example,.corp.example,exact.example,ported.example:8443," +
			"192.0.2.7,198.51.100.9:8080,113.7,fd00::1,[fd00::2]:8443,[fd00::3], MiXeD.Example ,:8080,," +
			"xn--bro-hoa.example,.bücher.example,例え.テスト,straße.example,ＦＵＬＬ.example",
		"*",
		"",
	} {
		proxies := Proxies{HTTPS: "http://proxy.example:3128", HTTP: "http://proxy.example:8080", NoProxy: noProxy}
		want := goProxies(t, proxies.Env())
		for _, rawURL := range parityURLs {
			if got := proxyOf(t, proxies.ProxyFunc(), rawURL); got != want[rawURL] {
				t.Errorf("NO_PROXY=%q: ProxyFunc sends %s through %q, Go through %q", noProxy, rawURL, got, want[rawURL])
			}
		}
	}
}

// goProxies is what http.ProxyFromEnvironment gives parityURLs in a process
// whose environment is env.
func goProxies(t *testing.T, env [][2]string) map[string]string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestProxyFuncReadsTheEnvAsGoDoes$")
	cmd.Env = []string{parityChild + "=1"}
	for _, variable := range env {
		cmd.Env = append(cmd.Env, variable[0]+"="+variable[1])
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "PROXIES "); ok {
			answers := map[string]string{}
			if err := json.Unmarshal([]byte(rest), &answers); err != nil {
				t.Fatal(err)
			}
			return answers
		}
	}
	t.Fatalf("child printed no proxies:\n%s", out)
	return nil
}
