package shellprojection

import (
	"encoding/json"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/kontext-security/kontext/internal/cedareval"
)

// Reuse curl's route/body classification after reading each client's argv.
// Unsupported options stay unrecognized rather than vouching for a request.
// source lines up with args, with the source text of each computed word, or
// is nil: a request that cannot be read keeps the literal host of a URL with
// a computed part.
func classifyHTTPClient(program string, args, source []string, complete, opaqueValues, stdin bool) cedareval.ShellProjectionV2 {
	converted, offline := httpClientArgs(program, args, stdin)
	if offline && (complete || opaqueValues) {
		return projection(program, nil, []string{"offline-preview"}, true)
	}
	result := classifyCurl(converted, nil, complete, opaqueValues, false)
	result.Program = program
	if !result.ParseComplete {
		facts, _ := httpClientTargetFacts(converted)
		// The source text only adds targets: a filled word can also read
		// as an option and take a literal target as its value.
		if filled, ok := withComputedSource(args, source); ok {
			refilled, _ := httpClientArgs(program, filled, stdin)
			facts = append(facts, readableTargetFacts(refilled)...)
		}
		result.Facts = sortedUnique(append(result.Facts, facts...))
	}
	return result
}

// httpClientArgs converts a wget, HTTPie or web cmdlet call to curl's
// arguments, and reports an HTTPie call that only prints its request.
func httpClientArgs(program string, args []string, stdin bool) ([]string, bool) {
	switch {
	case webCmdlet(program):
		return webCmdletArgs(args, stdin), false
	case program == "wget":
		return wgetArgs(args), false
	default:
		return httpieArgs(program, args, stdin)
	}
}

// withComputedSource returns args with each computed word ("") written as
// its source text, for reading the targets a request names.
func withComputedSource(args, source []string) ([]string, bool) {
	if len(source) != len(args) {
		return nil, false
	}
	filled, changed := slices.Clone(args), false
	for i, arg := range args {
		if arg == "" && source[i] != "" {
			filled[i], changed = source[i], true
		}
	}
	return filled, changed
}

// computedTargetHints returns the provider facts that a computed URL
// operand's source text still names: its literal host, read as
// httpTargetFacts reads one. A computed scheme or host names none, a host in
// a path or query is not the target, and a word that is an option with its
// value attached (--referer=…, -d…) is no URL, except --url=.
func computedTargetHints(source string) []string {
	if strings.HasPrefix(strings.TrimLeft(source, `"'`), "-") && !strings.HasPrefix(source, "--url=") {
		return nil
	}
	facts, resolved := httpTargetFacts(strings.TrimPrefix(source, "--url="))
	if !resolved {
		return nil
	}
	return facts
}

// webCmdlet reports PowerShell's web cmdlets, by name or alias.
func webCmdlet(program string) bool {
	switch program {
	case "invoke-restmethod", "invoke-webrequest", "irm", "iwr":
		return true
	}
	return false
}

// webCmdletCall reports a call of a web cmdlet as PowerShell resolves it: the
// bare name or alias in any case, or the name qualified with its module. A
// path or an extension names a file, which runs instead of the cmdlet.
func webCmdletCall(word string) bool {
	return webCmdlet(strings.TrimPrefix(strings.ToLower(word), `microsoft.powershell.utility\`))
}

// computedValue stands in for the computed part of a word whose parameter
// name is literal, as in -TimeoutSec:$t, so that the value stays with its
// parameter; projectStatements writes it, the binders read it as unknown.
const computedValue = "\x00"

// cmdletDefaults is an argument projectStatements adds to a web cmdlet call
// in a script that touches $PSDefaultParameterValues, which can supply any
// parameter the call leaves out.
const cmdletDefaults = "\x00defaults"

// powerShellDash returns a word with its leading en dash, em dash or
// horizontal bar written as '-': PowerShell reads all four as a parameter's
// dash, for cmdlets, but passes them to a native program unchanged.
func powerShellDash(word string) string {
	for _, dash := range []string{"\u2013", "\u2014", "\u2015"} {
		if rest, ok := strings.CutPrefix(word, dash); ok {
			return "-" + rest
		}
	}
	return word
}

// quotedValue marks a word written in quotes, which PowerShell always binds
// as a value, even when it starts with a dash ('-s').
const quotedValue = "\x01"

// aliasUnreadable is added to the arguments of a curl or wget alias call that
// Windows PowerShell 5.1 binds in part but that windowsPowerShellWebArgs
// cannot follow to the end: such a call may still run.
const aliasUnreadable = "\x00alias"

// ignorableInName are characters PowerShell's culture-aware comparison skips
// in a parameter name, such as the soft hyphen in -M\u00adethod; removing
// them can only make more names match.
var ignorableInName = strings.NewReplacer("\u00ad", "", "\u200b", "", "\u200c", "", "\u200d", "", "\u2060", "", "\ufeff", "")

// endOfParameters reports --, written with any two of PowerShell's dashes.
func endOfParameters(word string) bool {
	word = powerShellDash(word)
	return len(word) > 1 && word[0] == '-' && powerShellDash(word[1:]) == "-"
}

// webValue returns a word as the value PowerShell binds.
func webValue(word string) string {
	return strings.TrimPrefix(word, quotedValue)
}

// commaValue extends a value PowerShell reads as an array (-Method Get, Delete)
// to the list form 'Get,Delete'; next is the index of the word after it, and
// the index after the array comes back.
func commaValue(args []string, value string, next int) (string, int) {
	for next < len(args) && (strings.HasSuffix(value, ",") || strings.HasPrefix(webValue(args[next]), ",")) {
		value += webValue(args[next])
		next++
	}
	return value, next
}

// windowsPowerShellWebArgs binds arguments as Windows PowerShell 5.1 does for
// its curl and wget aliases of Invoke-WebRequest. read is false when no word
// binds as one of its parameters there: 5.1 then sends the same GET as the
// program, or refuses the call. When 5.1 binds the call, each parameter comes
// back under its full name. When a word binds but the rest cannot be followed
// (an unknown or ambiguous parameter, a missing value, not exactly one URI),
// the words come back as written with aliasUnreadable: a call this reading
// cannot follow may still run, so it is read as unreadable, never dropped;
// without any URI, 5.1 refuses for certain. After --, every word is
// positional.
func windowsPowerShellWebArgs(args []string) (_ []string, read bool) {
	var out []string
	named, refused, uris, positional := false, false, 0, false
	for i := 0; i < len(args); i++ {
		arg := powerShellDash(args[i])
		if !positional && endOfParameters(arg) {
			positional = true
			out = append(out, "--")
			continue
		}
		if positional || !parameterToken(arg) {
			out = append(out, args[i])
			uris++
			continue
		}
		name, value, hasValue := strings.Cut(arg[1:], ":")
		p, found := lookupWebCmdletParameter(strings.ToLower(name), true)
		if !found {
			refused = true
			continue
		}
		named = true
		if p.role == "uri" {
			uris++
		}
		switch {
		case hasValue && value != "":
			v, next := commaValue(args, value, i+1)
			out = append(out, "-"+p.name+":"+v)
			i = next - 1
		case (hasValue || p.value) && i+1 < len(args) && !parameterToken(powerShellDash(args[i+1])):
			// -Name value binds the next word, and so does -Name: value.
			v, next := commaValue(args, args[i+1], i+2)
			out = append(out, "-"+p.name, v)
			i = next - 1
		case hasValue:
			// -Name: before a parameter: the scanner drops an empty quoted
			// value ('' in -UserAgent:''), so read it as empty.
			out = append(out, "-"+p.name, "")
		case p.value:
			refused = true
		default:
			out = append(out, "-"+p.name)
		}
	}
	switch {
	case !named || uris == 0:
		// Without a URI, 5.1 refuses the call (curl -s <url> binds the URL
		// as -SessionVariable).
		return nil, false
	case refused || uris != 1:
		return append(slices.Clone(args), aliasUnreadable), true
	}
	return out, true
}

// webCmdletParameter is a parameter of Invoke-WebRequest and Invoke-RestMethod
// (Windows PowerShell 5.1 and PowerShell 7) or a common parameter: whether a
// value follows, and what the request does with it. An empty role only
// shapes output, credentials, timeouts or error handling. v51 marks the
// parameters Invoke-WebRequest has in Windows PowerShell 5.1, which its curl
// and wget aliases bind.
type webCmdletParameter struct {
	name    string
	value   bool
	role    string
	aliases []string
	common  bool
	v51     bool
}

var webCmdletParameters = []webCmdletParameter{
	{name: "uri", value: true, role: "uri", v51: true},
	{name: "method", value: true, role: "method", v51: true},
	{name: "custommethod", value: true, role: "method", aliases: []string{"cm"}},
	{name: "body", value: true, role: "body", v51: true},
	{name: "infile", value: true, role: "infile", v51: true},
	{name: "form", value: true, role: "body"},
	{name: "headers", value: true, role: "headers", v51: true},
	// A web session can carry headers; a Unix socket sends the request to a
	// local listener instead of the URL's host.
	{name: "websession", value: true, role: "opaque", v51: true},
	{name: "unixsocket", value: true, role: "opaque"},
	{name: "contenttype", value: true, v51: true}, {name: "outfile", value: true, v51: true}, {name: "credential", value: true, v51: true},
	{name: "authentication", value: true}, {name: "token", value: true}, {name: "useragent", value: true, v51: true},
	{name: "timeoutsec", value: true, v51: true}, {name: "maximumredirection", value: true, v51: true}, {name: "maximumretrycount", value: true},
	{name: "retryintervalsec", value: true}, {name: "proxy", value: true, v51: true}, {name: "proxycredential", value: true, v51: true},
	{name: "sessionvariable", value: true, aliases: []string{"sv"}, v51: true}, {name: "httpversion", value: true},
	{name: "sslprotocol", value: true}, {name: "transferencoding", value: true, v51: true}, {name: "maximumfollowrellink", value: true, aliases: []string{"ml"}},
	{name: "responseheadersvariable", value: true, aliases: []string{"rhv"}}, {name: "statuscodevariable", value: true},
	{name: "connectiontimeoutseconds", value: true}, {name: "operationtimeoutseconds", value: true},
	{name: "certificatethumbprint", value: true, v51: true}, {name: "certificate", value: true, v51: true},
	{name: "usebasicparsing", v51: true}, {name: "passthru", v51: true}, {name: "skipcertificatecheck"}, {name: "skipheadervalidation"},
	{name: "noproxy"}, {name: "resume"}, {name: "allowunencryptedauthentication"}, {name: "preserveauthorizationonredirect"},
	{name: "followrellink", aliases: []string{"fl"}}, {name: "skiphttperrorcheck"}, {name: "disablekeepalive", v51: true},
	{name: "preservehttpmethodonredirect"}, {name: "usedefaultcredentials", v51: true}, {name: "proxyusedefaultcredentials", v51: true},
	{name: "allowinsecureredirect"},
	// Common parameters; -ProgressAction came in PowerShell 7.4.
	{name: "verbose", aliases: []string{"vb"}, common: true, v51: true}, {name: "debug", aliases: []string{"db"}, common: true, v51: true},
	{name: "erroraction", value: true, aliases: []string{"ea"}, common: true, v51: true}, {name: "warningaction", value: true, aliases: []string{"wa"}, common: true, v51: true},
	{name: "informationaction", value: true, aliases: []string{"infa"}, common: true, v51: true}, {name: "progressaction", value: true, aliases: []string{"proga"}, common: true},
	{name: "errorvariable", value: true, aliases: []string{"ev"}, common: true, v51: true}, {name: "warningvariable", value: true, aliases: []string{"wv"}, common: true, v51: true},
	{name: "informationvariable", value: true, aliases: []string{"iv"}, common: true, v51: true}, {name: "outvariable", value: true, aliases: []string{"ov"}, common: true, v51: true},
	{name: "outbuffer", value: true, aliases: []string{"ob"}, common: true, v51: true}, {name: "pipelinevariable", value: true, aliases: []string{"pv"}, common: true, v51: true},
}

// lookupWebCmdletParameter resolves a parameter as PowerShell binds it: the
// full name or an alias, else a prefix of exactly one parameter, where a
// cmdlet parameter wins over common ones (-d is -DisableKeepAlive, not
// -Debug). With windowsPowerShell set, only Windows PowerShell 5.1's
// parameters count.
func lookupWebCmdletParameter(name string, windowsPowerShell bool) (webCmdletParameter, bool) {
	var match []webCmdletParameter
	name = ignorableInName.Replace(name)
	for _, p := range webCmdletParameters {
		if windowsPowerShell && !p.v51 {
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

// webRequestMethods are the values of PowerShell's WebRequestMethod enum, 0 to
// 9 in Windows PowerShell 5.1 and PowerShell 7, as the methods they send:
// Default sends GET.
var webRequestMethods = []struct{ name, method string }{
	{"default", "GET"}, {"get", "GET"}, {"head", "HEAD"}, {"post", "POST"}, {"put", "PUT"},
	{"delete", "DELETE"}, {"trace", "TRACE"}, {"options", "OPTIONS"}, {"merge", "MERGE"}, {"patch", "PATCH"},
}

// webRequestMethod converts a -Method value as PowerShell converts it to the
// enum: each comma-separated part a name in any case or a number (decimal or
// hex), blanks around it ignored, the parts combined bitwise ('Get,Head' is
// POST). ok is false for a value PowerShell refuses.
func webRequestMethod(value string) (string, bool) {
	combined := 0
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		n := slices.IndexFunc(webRequestMethods, func(m struct{ name, method string }) bool { return strings.EqualFold(m.name, part) })
		if n < 0 {
			v, ok := powerShellNumber(part)
			if !ok || v >= len(webRequestMethods) {
				return "", false
			}
			n = v
		}
		combined |= n
	}
	if combined >= len(webRequestMethods) {
		return "", false
	}
	return webRequestMethods[combined].method, true
}

// powerShellNumber reads a number as PowerShell does when it converts a string
// to an enum: decimal, leading zeros included (09 is 9), or hex after 0x, with
// a type suffix such as l. Reading more forms than PowerShell accepts only
// reads a request where PowerShell would refuse the call.
func powerShellNumber(s string) (int, bool) {
	s = strings.TrimPrefix(strings.ToLower(s), "+")
	for _, suffix := range []string{"ul", "lu", "uy", "us", "u", "l", "y", "s", "n"} {
		if rest, ok := strings.CutSuffix(s, suffix); ok && rest != "" {
			s = rest
			break
		}
	}
	base := 10
	if rest, ok := strings.CutPrefix(s, "0x"); ok {
		s, base = rest, 16
	}
	v, err := strconv.ParseUint(s, base, 31)
	if err != nil {
		return 0, false
	}
	return int(v), true
}

// webCmdletArgs translates Invoke-WebRequest and Invoke-RestMethod arguments
// to curl's: a positional value is -Uri; -Body, -Form and -InFile are the
// body, as is input from the pipeline; -Headers are headers, so a computed
// table is an opaque header value, as for curl. -Method is read as the enum
// PowerShell converts it to; without it the request is a GET even with a
// body. A computed value is unknown to curl too. A parameter that cannot be
// bound, a value PowerShell refuses, a second URI (by position or name), a
// session, or defaults the script may set make the request unreadable, as an
// unknown wget option does; every positional value stays a URL, since it may
// be the value of a parameter that was not read. After --, every word is
// positional.
func webCmdletArgs(args []string, stdin bool) []string {
	var out, body []string
	uris, method, positional := 0, false, false
	uri := func() {
		if uris++; uris == 2 {
			out = append(out, "-K", "unreadable-web-cmdlet-argument")
		}
	}
	for i := 0; i < len(args); i++ {
		arg := powerShellDash(args[i])
		switch {
		case arg == cmdletDefaults:
			out = append(out, "-K", "unreadable-web-cmdlet-defaults")
			continue
		case arg == aliasUnreadable:
			out = append(out, "-K", "unreadable-web-cmdlet-alias")
			continue
		case !positional && endOfParameters(arg):
			positional = true
			continue
		case positional || len(arg) < 2 || arg[0] != '-' || !parameterToken(arg) && arg[1] != '-':
			out = append(out, "--url", webValue(strings.TrimSuffix(args[i], computedValue)))
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
		if p.value || hasValue {
			next := i + 1
			switch {
			case hasValue && attached != "":
				value = attached
			case next < len(args) && !parameterToken(powerShellDash(args[next])):
				// -Name value binds the next word, and so does -Name: value.
				value = args[next]
				next++
			case hasValue:
				// -Name: before a parameter or at the end: the scanner drops
				// an empty quoted value ('' in -UserAgent:''), so read it as
				// empty rather than missing.
			default:
				// PowerShell refuses a parameter with its value missing.
				out = append(out, "-K", "unreadable-web-cmdlet-parameter")
				continue
			}
			value, next = commaValue(args, webValue(value), next)
			i = next - 1
		}
		computed := value == "" || value == computedValue
		if computed {
			value = ""
		}
		switch p.role {
		case "uri":
			out = append(out, "--url", value)
			uri()
		case "method":
			method = true
			if p.name == "method" && !computed {
				resolved, ok := webRequestMethod(value)
				if !ok {
					out = append(out, "-K", "unreadable-web-cmdlet-method")
					continue
				}
				value = resolved
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
	return clientTargetFacts(converted, false)
}

// readableTargetFacts returns the provider facts of the targets whose scheme
// and host are literal: a computed one (api.github.com$SUFFIX) names none.
func readableTargetFacts(converted []string) []string {
	facts, _ := clientTargetFacts(converted, true)
	return facts
}

func clientTargetFacts(converted []string, readableOnly bool) ([]string, bool) {
	var facts []string
	resolved, sawTarget := true, false
	addTarget := func(target string) {
		hints, known := httpTargetFacts(target)
		if known || !readableOnly {
			facts = append(facts, hints...)
		}
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
