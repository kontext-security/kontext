package shellprojection

import (
	"encoding/json"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kontext-security/kontext/internal/cedareval"
)

// Reuse curl's route/body classification after reading each client's argv.
// Unsupported options stay unrecognized rather than vouching for a request.
func classifyHTTPClient(program string, args []string, complete, opaqueValues, stdin bool) cedareval.ShellProjectionV2 {
	var converted []string
	offline := false
	if program == "wget" {
		converted = wgetArgs(args)
	} else {
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
