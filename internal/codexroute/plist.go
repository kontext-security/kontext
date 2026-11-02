package codexroute

import (
	"bytes"
	"encoding/xml"
	"strconv"
	"strings"
)

// job is the proxy's launchd job: binary is the job's own copy of kontext,
// home the home whose Codex route it serves, and upstream and apiUpstream,
// when set, where it forwards instead of the Codex backend and the OpenAI
// API.
type job struct {
	label       string
	binary      string
	port        int
	home        string
	stateDir    string
	socket      string
	upstream    string
	apiUpstream string
	logPath     string
}

// renderPlist is the proxy job: launchd holds 127.0.0.1:port and starts the
// proxy on the first connection, handing it the listening socket on standard
// input (inetdCompatibility with Wait), which needs no cgo. When the proxy
// exits or dies, launchd keeps the port and starts it again for the next
// connection, a second later at most.
func renderPlist(j job) string {
	args := []string{j.binary, "codex-proxy", "--stdin-socket", "--home", j.home, "--token-file", TokenPath(j.stateDir),
		"--state-dir", j.stateDir, "--socket", j.socket, "--idle-exit", IdleExit.String()}
	if j.upstream != "" {
		args = append(args, "--upstream", j.upstream)
	}
	if j.apiUpstream != "" {
		args = append(args, "--api-upstream", j.apiUpstream)
	}
	var program strings.Builder
	for _, arg := range args {
		program.WriteString("\t\t<string>" + xmlEscape(arg) + "</string>\n")
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + xmlEscape(j.label) + `</string>
	<key>ProgramArguments</key>
	<array>
` + program.String() + `	</array>
	<key>Sockets</key>
	<dict>
		<key>Listener</key>
		<dict>
			<key>SockNodeName</key>
			<string>127.0.0.1</string>
			<key>SockServiceName</key>
			<string>` + strconv.Itoa(j.port) + `</string>
			<key>SockType</key>
			<string>stream</string>
			<key>SockFamily</key>
			<string>IPv4</string>
		</dict>
	</dict>
	<key>inetdCompatibility</key>
	<dict>
		<key>Wait</key>
		<true/>
	</dict>
	<key>ThrottleInterval</key>
	<integer>1</integer>
	<key>ProcessType</key>
	<string>Standard</string>
	<key>StandardOutPath</key>
	<string>` + xmlEscape(j.logPath) + `</string>
	<key>StandardErrorPath</key>
	<string>` + xmlEscape(j.logPath) + `</string>
</dict>
</plist>
`
}

func xmlEscape(value string) string {
	var escaped bytes.Buffer
	_ = xml.EscapeText(&escaped, []byte(value))
	return escaped.String()
}
