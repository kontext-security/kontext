package shellprojection

import (
	"encoding/json"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/kontext-security/kontext/internal/cedareval"
)

// Reuse curl's route/body classification after reading each client's argv.
// Unsupported options stay unrecognized rather than vouching for a request.
func classifyHTTPClient(program string, args []string, complete, opaqueValues, stdin bool) cedareval.ShellProjectionV2 {
	var converted []string
	offline := false
	switch {
	case webCmdlet(program):
		converted = webCmdletArgs(args, stdin)
	case program == "wget":
		converted = wgetArgs(args)
	default:
		converted, offline = httpieArgs(program, args, stdin)
	}
	if offline && (complete || opaqueValues) {
		return projection(program, nil, []string{"offline-preview"}, true)
	}
	result := classifyCurl(converted, complete, opaqueValues, false)
	result.Program = program
	if !result.ParseComplete {
		facts, _ := httpClientTargetFacts(converted)
		result.Facts = sortedUnique(append(result.Facts, facts...))
	}
	return result
}

// webCmdlet reports PowerShell's web cmdlets, by name or alias.
func webCmdlet(program string) bool {
	switch program {
	case "invoke-restmethod", "invoke-webrequest", "irm", "iwr":
		return true
	}
	return false
}

// windowsPowerShellWebArgs binds arguments as Windows PowerShell 5.1 does for
// its curl and wget aliases of Invoke-WebRequest, and returns them with each
// parameter under its full name. ok is false when 5.1 refuses the call and
// runs nothing: no named parameter (the call is then read as the program),
// a parameter Invoke-WebRequest does not have there or an ambiguous prefix,
// a missing value, or not exactly one URI.
func windowsPowerShellWebArgs(args []string) (_ []string, ok bool) {
	var out []string
	named, uris := false, 0
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if len(arg) < 2 || arg[0] != '-' || arg[1] == '-' {
			out = append(out, arg)
			uris++
			continue
		}
		name, value, hasValue := strings.Cut(arg[1:], ":")
		p, found := lookupWebCmdletParameter(strings.ToLower(name), true)
		if !found {
			return nil, false
		}
		named = true
		if p.role == "uri" {
			uris++
		}
		switch {
		case hasValue:
			out = append(out, "-"+p.name+":"+value)
		case p.value && i+1 < len(args) && !parameterToken(args[i+1]):
			out = append(out, "-"+p.name, args[i+1])
			i++
		case p.value:
			return nil, false
		default:
			out = append(out, "-"+p.name)
		}
	}
	return out, named && uris == 1
}

// webCmdletParameter is a parameter of Invoke-WebRequest and Invoke-RestMethod
// (Windows PowerShell 5.1 and PowerShell 7) or a common parameter: whether a
// value follows, and what the request does with it. An empty role only
// shapes output, credentials, timeouts or error handling.
type webCmdletParameter struct {
	name    string
	value   bool
	role    string
	aliases []string
	common  bool
}

var webCmdletParameters = []webCmdletParameter{
	{name: "uri", value: true, role: "uri"},
	{name: "method", value: true, role: "method"},
	{name: "custommethod", value: true, role: "method"},
	{name: "body", value: true, role: "body"},
	{name: "infile", value: true, role: "infile"},
	{name: "form", value: true, role: "body"},
	{name: "headers", value: true, role: "headers"},
	// A web session can carry headers; a Unix socket sends the request to a
	// local listener instead of the URL's host.
	{name: "websession", value: true, role: "opaque"},
	{name: "unixsocket", value: true, role: "opaque"},
	{name: "contenttype", value: true}, {name: "outfile", value: true}, {name: "credential", value: true},
	{name: "authentication", value: true}, {name: "token", value: true}, {name: "useragent", value: true},
	{name: "timeoutsec", value: true}, {name: "maximumredirection", value: true}, {name: "maximumretrycount", value: true},
	{name: "retryintervalsec", value: true}, {name: "proxy", value: true}, {name: "proxycredential", value: true},
	{name: "sessionvariable", value: true, aliases: []string{"sv"}}, {name: "httpversion", value: true},
	{name: "sslprotocol", value: true}, {name: "transferencoding", value: true}, {name: "maximumfollowrellink", value: true, aliases: []string{"ml"}},
	{name: "responseheadersvariable", value: true, aliases: []string{"rhv"}}, {name: "statuscodevariable", value: true},
	{name: "connectiontimeoutseconds", value: true}, {name: "operationtimeoutseconds", value: true},
	{name: "certificatethumbprint", value: true}, {name: "certificate", value: true},
	{name: "usebasicparsing"}, {name: "passthru"}, {name: "skipcertificatecheck"}, {name: "skipheadervalidation"},
	{name: "noproxy"}, {name: "resume"}, {name: "allowunencryptedauthentication"}, {name: "preserveauthorizationonredirect"},
	{name: "followrellink", aliases: []string{"fl"}}, {name: "skiphttperrorcheck"}, {name: "disablekeepalive"},
	{name: "preservehttpmethodonredirect"}, {name: "usedefaultcredentials"}, {name: "proxyusedefaultcredentials"},
	{name: "allowinsecureredirect"},
	// Common parameters.
	{name: "verbose", aliases: []string{"vb"}, common: true}, {name: "debug", aliases: []string{"db"}, common: true},
	{name: "erroraction", value: true, aliases: []string{"ea"}, common: true}, {name: "warningaction", value: true, aliases: []string{"wa"}, common: true},
	{name: "informationaction", value: true, aliases: []string{"infa"}, common: true}, {name: "progressaction", value: true, aliases: []string{"proga"}, common: true},
	{name: "errorvariable", value: true, aliases: []string{"ev"}, common: true}, {name: "warningvariable", value: true, aliases: []string{"wv"}, common: true},
	{name: "informationvariable", value: true, aliases: []string{"iv"}, common: true}, {name: "outvariable", value: true, aliases: []string{"ov"}, common: true},
	{name: "outbuffer", value: true, aliases: []string{"ob"}, common: true}, {name: "pipelinevariable", value: true, aliases: []string{"pv"}, common: true},
}

// windowsPowerShellWebParameters are the parameters Invoke-WebRequest has in
// Windows PowerShell 5.1, with the common parameters.
var windowsPowerShellWebParameters = []string{
	"usebasicparsing", "uri", "websession", "sessionvariable", "credential", "usedefaultcredentials",
	"certificatethumbprint", "certificate", "useragent", "disablekeepalive", "timeoutsec", "headers",
	"maximumredirection", "method", "proxy", "proxycredential", "proxyusedefaultcredentials", "body",
	"contenttype", "transferencoding", "infile", "outfile", "passthru",
	"verbose", "debug", "erroraction", "warningaction", "informationaction", "progressaction", "errorvariable",
	"warningvariable", "informationvariable", "outvariable", "outbuffer", "pipelinevariable",
}

// lookupWebCmdletParameter resolves a parameter as PowerShell binds it: the
// full name or an alias, else a prefix of exactly one parameter, where a
// cmdlet parameter wins over common ones (-d is -DisableKeepAlive, not
// -Debug). With windowsPowerShell set, only Windows PowerShell 5.1's
// parameters count.
func lookupWebCmdletParameter(name string, windowsPowerShell bool) (webCmdletParameter, bool) {
	var match []webCmdletParameter
	for _, p := range webCmdletParameters {
		if windowsPowerShell && !slices.Contains(windowsPowerShellWebParameters, p.name) {
			continue
		}
		if p.name == name || slices.Contains(p.aliases, name) {
			return p, true
		}
		if strings.HasPrefix(p.name, name) {
			match = append(match, p)
		}
	}
	if len(match) > 1 {
		match = slices.DeleteFunc(match, func(p webCmdletParameter) bool { return p.common })
	}
	if len(match) == 1 {
		return match[0], true
	}
	return webCmdletParameter{}, false
}

// parameterToken reports a word PowerShell reads as a parameter name rather
// than as the value of the parameter before it.
func parameterToken(word string) bool {
	return len(word) > 1 && word[0] == '-' && (word[1] >= 'a' && word[1] <= 'z' || word[1] >= 'A' && word[1] <= 'Z')
}

// webCmdletArgs translates Invoke-WebRequest and Invoke-RestMethod arguments
// to curl's: a positional value is -Uri; -Body, -Form and -InFile are the
// body, as is input from the pipeline; -Headers are headers, so a computed
// table is an opaque header value, as for curl. Without -Method the request
// is a GET even with a body, and -Method Default is GET. A parameter that
// cannot be bound, a second URI (by position or name) or a session make the
// request unreadable, as an unknown wget option does; every positional value
// stays a URL, since it may be the value of a parameter that was not read.
func webCmdletArgs(args []string, stdin bool) []string {
	var out, body []string
	uris, method := 0, false
	uri := func() {
		if uris++; uris == 2 {
			out = append(out, "-K", "unreadable-web-cmdlet-argument")
		}
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if len(arg) < 2 || arg[0] != '-' {
			out = append(out, "--url", arg)
			uri()
			continue
		}
		name, attached, hasValue := strings.Cut(arg[1:], ":")
		p, ok := lookupWebCmdletParameter(strings.ToLower(name), false)
		if !ok {
			out = append(out, "-K", "unreadable-web-cmdlet-parameter")
			continue
		}
		value := ""
		if p.value {
			switch {
			case hasValue:
				value = attached
			case i+1 < len(args) && !parameterToken(args[i+1]):
				i++
				value = args[i]
			default:
				// PowerShell refuses a parameter with its value missing.
				out = append(out, "-K", "unreadable-web-cmdlet-parameter")
				continue
			}
		}
		switch p.role {
		case "uri":
			out = append(out, "--url", value)
			uri()
		case "method":
			method = true
			if p.name == "method" && strings.EqualFold(value, "default") {
				value = "GET"
			}
			out = append(out, "-X", value)
		case "body":
			body = []string{"--data-raw", value}
		case "infile":
			body = []string{"--data-binary", "@" + value}
		case "headers":
			out = append(out, "-H", value)
		case "opaque":
			out = append(out, "-K", "unreadable-web-cmdlet-"+p.name)
		}
	}
	if body == nil && stdin {
		body = []string{"--data-binary", "@-"}
	}
	if body != nil && !method {
		// curl would send a body as a POST; the cmdlets send a GET (or, in
		// Windows PowerShell 5.1, refuse a body that is not a table).
		out = append(out, "-X", "GET")
	}
	return append(out, body...)
}

// The translators mark request operands with --url. Inspect only their
// authority: URLs in bodies, headers, output paths or request paths are data.
func httpClientTargetFacts(converted []string) ([]string, bool) {
	var facts []string
	resolved, sawTarget := true, false
	addTarget := func(target string) {
		hints, known := httpTargetFacts(target)
		facts = append(facts, hints...)
		resolved, sawTarget = resolved && known, true
	}
	for i := 0; i < len(converted); i++ {
		switch converted[i] {
		case "-K":
			resolved = false // Unknown options may move target operands.
			i++
			continue
		case "-X", "-H", "--data-raw", "--data-binary":
			i++
			continue
		}
		if converted[i] == "--url" && i+1 < len(converted) {
			i++
			addTarget(converted[i])
		} else if converted[i] == "--" {
			for _, remaining := range converted[i+1:] {
				addTarget(remaining)
			}
			break
		}
	}
	return facts, resolved && sawTarget
}

func httpTargetFacts(target string) ([]string, bool) {
	target = strings.Trim(target, "\"'")
	original := target
	resolved := true
	// Expansion in a scheme or authority can inject URL delimiters. A
	// computed path cannot replace an already literal external authority.
	if scheme, authority, ok := strings.Cut(target, "://"); ok {
		resolved = !strings.ContainsAny(scheme, "$`")
		target = authority
	}
	if end := strings.IndexAny(target, "/?#"); end >= 0 {
		target = target[:end]
	}
	resolved = resolved && target != "" && !strings.ContainsAny(target, "$`")
	if parsed, err := url.Parse(original); err == nil && parsed.Hostname() != "" {
		return providerHostFacts(parsed.Hostname()), resolved
	}
	if at := strings.LastIndexByte(target, '@'); at >= 0 {
		target = target[at+1:]
	}
	return providerHostFacts(target), resolved
}

func wgetArgs(args []string) []string {
	var out, body []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		name, attached, hasValue := strings.Cut(arg, "=")
		value := func() string {
			if hasValue {
				return attached
			}
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch name {
		case "--":
			return append(append(out, body...), append([]string{"--"}, args[i+1:]...)...)
		case "--method":
			out = append(out, "-X", value())
		case "--header":
			out = append(out, "-H", value())
		case "--post-data":
			out = append(out, "-X", "POST")
			body = []string{"--data-raw", value()}
		case "--body-data":
			body = []string{"--data-raw", value()}
		case "--post-file":
			out = append(out, "-X", "POST")
			body = []string{"--data-binary", "@" + value()}
		case "--body-file":
			body = []string{"--data-binary", "@" + value()}
		case "-O", "--output-document", "-o", "--output-file", "--timeout", "-T", "--tries", "-t", "--user", "--password", "--http-user", "--http-password", "--ca-certificate", "--referer", "--user-agent", "-U":
			value()
		case "-qO":
			value()
		case "-q", "--quiet", "-v", "--verbose", "-nv", "--no-verbose", "--no-check-certificate", "--no-config", "--content-disposition", "-c", "--continue":
		default:
			switch {
			case strings.HasPrefix(arg, "-qO") || strings.HasPrefix(arg, "-O") && len(arg) > 2:
				// -qO- and -Ofile affect only the output file.
			case strings.HasPrefix(arg, "-"):
				// Config, execute, input files, recursion and unknown options
				// can add requests or replace their method and headers.
				out = append(out, "-K", "unreadable-wget-option")
			default:
				out = append(out, "--url", arg)
			}
		}
	}
	return append(out, body...)
}

func httpieArgs(program string, args []string, stdin bool) ([]string, bool) {
	var out, rawBody []string
	method, target := "", ""
	fields := map[string]any{}
	ignoreStdin, uncertainTarget := false, false
	offline, offlineReset, offlineCertain := false, false, true
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "" {
			offlineCertain = false // An unresolved standalone word can reset options.
		}
		name, attached, hasValue := strings.Cut(arg, "=")
		value := func() string {
			if hasValue {
				return attached
			}
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		if strings.HasPrefix(arg, "-") {
			switch name {
			case "--offline":
				offline = true
			case "--no-offline":
				offlineReset = true
			case "--ignore-stdin", "-I":
				ignoreStdin = true
			case "--raw":
				rawBody = []string{"--data-raw", value()}
			case "--session", "--session-read-only", "--boundary", "--default-scheme":
				value()
				out = append(out, "-K", "unreadable-httpie-session")
			case "-a", "--auth", "--auth-type", "-A", "--timeout", "--verify", "--cert", "--cert-key", "--cert-key-pass", "-o", "--output", "--print", "-p", "--pretty", "--style", "-s", "--response-charset", "--response-mime", "--format-options", "--history-print", "-P", "--proxy", "--max-redirects", "--max-headers", "--ssl", "--ciphers":
				value()
			case "-j", "--json", "-f", "--form", "--multipart", "-v", "--verbose", "-h", "--headers", "-b", "--body", "--check-status", "--follow", "-F", "-d", "--download", "--meta", "-m", "--all", "--stream", "-S", "--continue", "-c", "--quiet", "-q", "--ignore-netrc", "--chunked", "--sorted", "--unsorted", "--no-sorted", "--no-unsorted", "--compress", "-x", "--traceback", "--debug":
			default:
				offlineCertain = false
				out = append(out, "-K", "unreadable-httpie-option")
				uncertainTarget = uncertainTarget || target == ""
			}
			continue
		}
		if target == "" {
			if arg == "" || strings.ContainsAny(arg, "$`") && !strings.Contains(arg, "://") {
				offlineCertain = false
				uncertainTarget = true
				out = append(out, "-K", "unreadable-httpie-method-or-target")
				continue
			}
			if method == "" && isHTTPMethod(arg) {
				method = strings.ToUpper(arg)
				continue
			}
			target = arg
			if program == "https" && !strings.Contains(target, "://") {
				target = "https://" + target
			}
			out = append(out, "--url", target)
			continue
		}
		// Unknown options can consume a value (including argparse long
		// abbreviations), so an earlier token may have displaced the URL.
		if uncertainTarget {
			candidate := arg
			if !strings.Contains(candidate, "://") {
				candidate = "http://" + candidate
			}
			parsed, err := url.Parse(candidate)
			if err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && len(providerHostFacts(parsed.Hostname())) > 0 {
				out = append(out, "--url", candidate)
				continue
			}
		}
		item := httpieItem.FindStringSubmatch(arg)
		if item == nil {
			out = append(out, "-K", "unreadable-httpie-item")
			continue
		}
		key, separator, val := item[1], item[2], httpieUnescape(item[3])
		switch separator {
		case ":=":
			var parsed any
			if json.Unmarshal([]byte(val), &parsed) != nil || strings.ContainsAny(key, "[\\") {
				out = append(out, "--data-binary", "@unreadable-httpie-field")
			} else {
				fields[key] = parsed
			}
		case "==":
			// Query parameters cannot turn a read into a write.
		case "=":
			if strings.ContainsAny(key, "[\\") {
				out = append(out, "--data-binary", "@unreadable-httpie-field")
			} else {
				fields[key] = val
			}
		case ":":
			out = append(out, "-H", arg)
		case "@", "=@", ":=@":
			out = append(out, "--data-binary", "@unreadable-httpie-field")
		case ":@", "==@":
			out = append(out, "-K", "unreadable-httpie-field")
		default:
			out = append(out, "-K", "unreadable-httpie-item")
		}
	}
	// These clients replace repeated body options rather than joining them.
	out = append(out, rawBody...)
	if len(fields) > 0 {
		body, _ := json.Marshal(fields)
		out = append(out, "--data-raw", string(body))
	}
	// Functions and wrappers may supply stdin outside the visible AST.
	// A write cannot vouch for an absent body without --ignore-stdin.
	if !ignoreStdin && (stdin || method == "" || isWriteMethod(method)) {
		out = append(out, "--data-binary", "@stdin")
	}
	// Agent subprocesses can inherit non-TTY stdin, which HTTPie treats as
	// a request body even when empty. Require an explicit read method or
	// --ignore-stdin before proving a default GET.
	if method == "" && !ignoreStdin {
		method = "POST"
	}
	if method != "" {
		out = append(out, "-X", method)
	}
	// HTTPie applies --no-* resets after parsing every ordinary option.
	return out, offline && !offlineReset && offlineCertain
}

// HTTPie splits at the first separator and prefers the longest there.
var httpieItem httpieItemParser

type httpieItemParser struct{}

func (httpieItemParser) FindStringSubmatch(value string) []string {
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' {
			i++
			continue
		}
		for _, separator := range []string{":=@", "==@", ":@", "=@", ":=", "==", ":", "=", "@"} {
			if strings.HasPrefix(value[i:], separator) {
				return []string{value, value[:i], separator, value[i+len(separator):]}
			}
		}
	}
	return nil
}

func httpieUnescape(value string) string {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+1 < len(value) {
			// HTTPie consumes an escaped pair together, preserving the slash
			// unless the next byte is a request-item separator character.
			if !strings.ContainsRune(":=@;", rune(value[i+1])) {
				out.WriteByte(value[i])
			}
			i++
		}
		out.WriteByte(value[i])
	}
	return out.String()
}

func isHTTPMethod(value string) bool {
	if value == "" {
		return false
	}
	for _, letter := range value {
		if (letter < 'a' || letter > 'z') && (letter < 'A' || letter > 'Z') {
			return false
		}
	}
	return true
}

var hostInCommand = regexp.MustCompile(`(?i)[a-z0-9-]+(?:\.[a-z0-9-]+)+`)

func providerHostFacts(text string) []string {
	var facts []string
	for _, host := range hostInCommand.FindAllString(strings.ToLower(text), -1) {
		if host == "github.com" || host == hostGitHubAPI || host == hostGitHubUploads {
			facts = append(facts, FactRouteUnrecognized)
		}
		if databricksHost(host) {
			facts = append(facts, FactDatabricksRouteUnrecognized)
		}
	}
	return facts
}

func opaqueProgram(program string) bool {
	base := strings.ToLower(filepath.Base(program))
	switch filepath.Ext(base) {
	case ".sh", ".py", ".js", ".rb", ".pl", ".php":
		return true
	}
	return strings.HasPrefix(base, "python") || strings.HasPrefix(base, "ruby") || strings.HasPrefix(base, "perl") ||
		base == "node" || base == "nodejs" || base == "deno" || base == "bun" || base == "php" ||
		base == "bash" || base == "sh" || base == "zsh" || base == "dash" || base == "ksh" ||
		base == "eval" || base == "source" || base == "." || strings.ContainsRune(program, '/')
}

// Explicit custom paths remain opaque, even when named after a known utility.
// Bare PATH commands and standard system/package-manager locations use known CLI semantics.
func standardUtilityPath(program string) bool {
	if !strings.ContainsRune(program, '/') {
		return true
	}
	// Shell text is POSIX on every host: path, not filepath, which on
	// Windows would read /bin/cat as \bin.
	switch path.Dir(program) {
	case "/bin", "/usr/bin", "/usr/local/bin", "/opt/homebrew/bin":
		return true
	}
	return false
}

// These utilities operate on local files or text; a host-like path is not a provider call.
func localUtility(program string) bool {
	if !standardUtilityPath(program) {
		return false
	}
	switch strings.TrimSuffix(strings.ToLower(filepath.Base(program)), ".exe") {
	case "mkdir", "touch", "echo", "printf", "grep", "rg", "jq", "cat", "head", "tail", "wc", "cut", "tr", "ls", "stat", "basename", "dirname", "readlink", "pwd", "uname", "id", "whoami":
		return true
	}
	return false
}
