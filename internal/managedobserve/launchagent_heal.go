package managedobserve

import "strings"

// plistFixes are the settings older setups wrote that make the hook see a
// dead daemon. Background is macOS's throttled QoS: the daemon starves
// whenever the user does anything, the hook times out and the call goes
// through without a policy check. ThrottleInterval 30 makes launchd hold a relaunch for up to 30 s
// when the daemon restarts twice in a row (doctor --fix after an upgrade),
// longer than the hook waits; 10 is launchd's floor.
var plistFixes = [][2]string{
	{"<key>ProcessType</key>\n\t<string>Background</string>", "<key>ProcessType</key>\n\t<string>Standard</string>"},
	{"<key>ThrottleInterval</key>\n\t<integer>30</integer>", "<key>ThrottleInterval</key>\n\t<integer>10</integer>"},
}

// healPlist applies plistFixes. Returns false when nothing needed changing.
func healPlist(plist string) (string, bool) {
	changed := false
	for _, fix := range plistFixes {
		if strings.Contains(plist, fix[0]) {
			plist = strings.Replace(plist, fix[0], fix[1], 1)
			changed = true
		}
	}
	return plist, changed
}
