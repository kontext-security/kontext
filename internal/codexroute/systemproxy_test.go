package codexroute

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

// manualEnv is the job's environment on that Mac.
var manualEnv = [][2]string{{"HTTPS_PROXY", "http://proxy.example:3128"}, {"HTTP_PROXY", "http://proxy.example:8080"},
	{"NO_PROXY", "*.local,169.254.0.0/16,10.0.0.0/8,*.intranet.example"}}

// pacProxies is what it prints on one set to use a PAC file.
const pacProxies = `<dictionary> {
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

// jobEnv reads back what renderPlist writes, and nothing from a plist without
// it.
func TestJobEnvReadsTheEnvBack(t *testing.T) {
	j := job{label: Label, binary: "/kontext", port: testPort, home: "/Users/kim", stateDir: "/state", socket: "/kontext.sock",
		logPath: "/codex-proxy.log", env: [][2]string{{"HTTPS_PROXY", "http://kim:s3cr&t<@proxy.example:3128"}, {"NO_PROXY", "*.local"}}}
	if env := jobEnv(renderPlist(j)); !slices.Equal(env, j.env) {
		t.Fatalf("jobEnv = %q", env)
	}
	j.env = nil
	for _, plist := range []string{renderPlist(j), "<plist/>\n", ""} {
		if env := jobEnv(plist); env != nil {
			t.Fatalf("jobEnv(%q) = %q", plist, env)
		}
	}
}
