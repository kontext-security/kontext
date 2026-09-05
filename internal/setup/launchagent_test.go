package setup

import (
	"strings"
	"testing"
)

func TestRenderLaunchAgentPlistGolden(t *testing.T) {
	got := renderLaunchAgentPlist("/opt/homebrew/bin/kontext", "/Users/x/Library/Logs/Kontext/managed-observe.log", nil)
	want := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>security.kontext.managed-observe</string>
	<key>ProgramArguments</key>
	<array>
		<string>/opt/homebrew/bin/kontext</string>
		<string>managed-observe-daemon</string>
	</array>
	<key>EnvironmentVariables</key>
	<dict>
		<key>KONTEXT_EXPECTED_CONFIG_SCOPE</key>
		<string>user</string>
	</dict>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>10</integer>
	<key>ProcessType</key>
	<string>Standard</string>
	<key>StandardOutPath</key>
	<string>/Users/x/Library/Logs/Kontext/managed-observe.log</string>
	<key>StandardErrorPath</key>
	<string>/Users/x/Library/Logs/Kontext/managed-observe.log</string>
</dict>
</plist>
`
	if got != want {
		t.Fatalf("plist mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestRenderLaunchAgentPlistEscapesXML(t *testing.T) {
	got := renderLaunchAgentPlist(`/Users/a&b/bin/kontext <v2>`, "/tmp/log", nil)
	if !strings.Contains(got, "/Users/a&amp;b/bin/kontext &lt;v2&gt;") {
		t.Fatalf("binary path not XML-escaped:\n%s", got)
	}
	if strings.Contains(got, "a&b") {
		t.Fatal("raw ampersand leaked into plist")
	}
}
