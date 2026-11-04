package systemproxy

import (
	"context"
	"testing"
)

// What scutil prints on this Mac, whatever proxies it is set to use, is what
// Parse reads: otherwise nothing would ever get them.
func TestScutilPrintsWhatParseReads(t *testing.T) {
	output, err := Scutil(context.Background())
	if err != nil {
		// A sandbox may keep scutil from configd.
		t.Skipf("scutil --proxy: %v", err)
	}
	proxies, ok := Parse(output)
	if !ok {
		t.Fatalf("Parse does not read what scutil --proxy prints:\n%s", output)
	}
	t.Logf("this Mac's proxies are %q", proxies.Env())
}
