package managedobserve

import (
	"strings"
	"testing"
)

func TestRaiseProcessType(t *testing.T) {
	plist := "<dict>\n\t<key>ThrottleInterval</key>\n\t<integer>30</integer>\n\t<key>ProcessType</key>\n\t<string>Background</string>\n\t<key>StandardOutPath</key>\n</dict>"
	next, changed := raiseProcessType(plist)
	if !changed || !strings.Contains(next, "<string>Standard</string>") || strings.Contains(next, "Background") {
		t.Fatalf("Background plist not raised: %q", next)
	}
	if _, changed := raiseProcessType(next); changed {
		t.Fatal("a Standard plist must be left alone")
	}
	if _, changed := raiseProcessType("<dict></dict>"); changed {
		t.Fatal("a plist without ProcessType must be left alone")
	}
}
