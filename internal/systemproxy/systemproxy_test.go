package systemproxy

import (
	"slices"
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
