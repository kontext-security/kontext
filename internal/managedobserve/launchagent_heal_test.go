package managedobserve

import (
	"strings"
	"testing"
)

func TestHealPlist(t *testing.T) {
	plist := "<dict>\n\t<key>ThrottleInterval</key>\n\t<integer>30</integer>\n\t<key>ProcessType</key>\n\t<string>Background</string>\n\t<key>StandardOutPath</key>\n</dict>"
	next, changed := healPlist(plist)
	if !changed || !strings.Contains(next, "<string>Standard</string>") || !strings.Contains(next, "<integer>10</integer>") || strings.Contains(next, "Background") {
		t.Fatalf("old plist not healed: %q", next)
	}
	if _, changed := healPlist(next); changed {
		t.Fatal("a healed plist must be left alone")
	}
	if _, changed := healPlist("<dict></dict>"); changed {
		t.Fatal("a plist without the old settings must be left alone")
	}
}
