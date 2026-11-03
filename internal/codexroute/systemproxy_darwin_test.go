package codexroute

import (
	"context"
	"testing"
)

// What scutil prints on this Mac, whatever proxies it is set to use, is what
// systemProxyEnv reads: otherwise the job would never get them.
func TestScutilPrintsWhatSystemProxyEnvReads(t *testing.T) {
	output, err := scutilProxies(context.Background())
	if err != nil {
		// A sandbox may keep scutil from configd.
		t.Skipf("scutil --proxy: %v", err)
	}
	env, ok := systemProxyEnv(output)
	if !ok {
		t.Fatalf("systemProxyEnv does not read what scutil --proxy prints:\n%s", output)
	}
	t.Logf("this Mac's proxies give the job %q", env)
}
