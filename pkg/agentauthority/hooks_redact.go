package agentauthority

import (
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/kontext-security/kontext/internal/payloadcapture"
)

// A hook's readable fields go to the workspace's dashboard, so they keep only
// what is known to be safe and drop the rest: a credential can sit in any
// argument (curl -u user:pass), not only behind a flag the scanner knows.

var (
	// A script's file name tells an administrator what runs. It is kept only
	// as an interpreter's first argument, before any flag (`bash check.sh`):
	// anywhere else a word with a script's suffix can be a password
	// (`redis-cli AUTH x.sh`), and a flag can take the script's place
	// (`python -m mod x.py`, `python -c code x.py` pass x.py as data).
	scriptName  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.(sh|bash|zsh|fish|py|js|mjs|cjs|ts|rb|pl|php|ps1|cmd|bat)$`)
	interpreter = regexp.MustCompile(`^(sh|bash|zsh|dash|ksh|fish|python[0-9.]*|node|nodejs|bun|deno|tsx|ts-node|ruby|perl|php|pwsh|powershell|cmd|osascript)(\.exe)?$`)
	// A long flag's name, or a single-letter short one: `-pSECRET` carries
	// its value attached, so a longer short flag is never kept.
	summaryFlag = regexp.MustCompile(`^(--[A-Za-z0-9][A-Za-z0-9_-]{0,63}|-[A-Za-z0-9])$`)
	programName = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)
)

const redacted = "<redacted>"

// hookToken is the cloud's long-token class for hook fields: `_` and `-` sit
// inside a token, so an npm_ or a dashed key is one word.
var hookToken = regexp.MustCompile(`[A-Za-z0-9_+/=-]{32,}`)

// pluginVersion is the shape a plugin version is kept in: a release number
// or a commit hash. Anything else can be a substituted secret. Keep
// identical to PLUGIN_VERSION in kontext-cloud's hook-inventory.ts.
var pluginVersion = regexp.MustCompile(`^(v?[0-9]{1,6}(\.[0-9]{1,6}){0,3}(-[0-9A-Za-z.]{1,24})?(\+[0-9A-Za-z.]{1,24})?|[0-9a-f]{7,40})$`)

// hookSecret is secret, the shared redaction ruleset's token shapes (vendor
// tokens short enough to pass the long-token check, such as a GitLab PAT),
// and the cloud's hook check for long mixed tokens (hookTextUnsafe in
// kontext-cloud's hook-inventory.ts). Keep them identical.
func hookSecret(value string) bool {
	if secret(value, "args") || payloadcapture.HasSecretToken(value) {
		return true
	}
	for _, token := range hookToken.FindAllString(value, -1) {
		if strings.ContainsAny(token, "0123456789") && strings.IndexFunc(token, func(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }) >= 0 {
			return true
		}
	}
	return false
}

// hookSummary is the program's file name, flag names and script file names.
// A flag's value, a path, a URL's user, path and query, and every other
// argument are replaced.
func hookSummary(program string, args []string) string {
	name := program[strings.LastIndexAny(program, `/\`)+1:]
	if !programName.MatchString(name) || hookSecret(name) {
		name = redacted
	}
	words := []string{name}
	// hidden: a word was hidden. It may have been an option that takes the
	// next word (`zip -9P '--pw'`) or a command whose argument is a secret
	// (`redis-cli AUTH '--pw'`), so no later word is kept as a flag.
	hidden := name == redacted
	add := func(word string) {
		if word == redacted {
			hidden = true
			if words[len(words)-1] == redacted {
				return
			}
		}
		words = append(words, word)
	}
	afterFlag := false
	// Only the interpreter's first positional argument can be its script.
	scriptSlot := interpreter.MatchString(strings.ToLower(name))
	for _, raw := range args {
		arg := strings.Trim(raw, `"'`)
		switch {
		case strings.Contains(arg, "://"):
			// A URL keeps only its scheme and host, also as a flag's value.
			add(summaryURL(arg))
			afterFlag, scriptSlot = false, false
		case afterFlag:
			// The value of a flag: a user, a password, a key file. It can
			// look like a flag itself (`sshpass -p '--winter-2026'`), so a
			// flag right after a flag is hidden too, and the summary never
			// shows two flags in a row. A hidden word shaped like a flag may
			// itself take the next word (`sshpass -v -p '--pw'`), so that word
			// is hidden as well.
			add(redacted)
			afterFlag, scriptSlot = takesValue(arg), false
		case strings.HasPrefix(arg, "-"):
			flag, _, hasValue := strings.Cut(arg, "=")
			if hidden || !summaryFlag.MatchString(flag) || hookSecret(flag) {
				// A hidden flag can still take the next word as its value,
				// and a short cluster (`-ab`) can end in a flag that does.
				add(redacted)
				afterFlag, scriptSlot = !hasValue, false
				continue
			}
			add(flag)
			if hasValue {
				add(redacted)
			}
			afterFlag = !hasValue
			scriptSlot = false
		case scriptSlot && scriptName.MatchString(arg) && !hookSecret(arg):
			add(arg)
			scriptSlot = false
		default:
			add(redacted)
			scriptSlot = false
		}
	}
	return safe(strings.Join(words, " "), 256)
}

// takesValue reports a flag-shaped word that may take the next word as its
// value: not `--name=value`, and not a short flag with its value attached
// (`-pSECRET`).
func takesValue(arg string) bool {
	if !strings.HasPrefix(arg, "-") || strings.Contains(arg, "=") {
		return false
	}
	return strings.HasPrefix(arg, "--") || len(arg) == 2
}

// summaryURL keeps a URL's scheme and host, and only when it carries no user.
// A host label that reads as an id is hidden: a webhook's host can be the
// whole credential (`eo1a2b3c4d5e6f7.m.pipedream.net`).
func summaryURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Scheme == "" || u.Hostname() == "" {
		return redacted
	}
	labels := strings.Split(u.Host, ".")
	for i, label := range labels {
		if hostLabelSecret(label) {
			labels[i] = redacted
		}
	}
	return safe(u.Scheme+"://"+strings.Join(labels, "."), 64)
}

// hostLabelSecret: a DNS label of ten or more characters that mixes letters
// and digits, or any label of 24 or more, or one that reads as a secret.
// Keep identical to hostLabelUnsafe in kontext-cloud's hook-inventory.ts.
func hostLabelSecret(label string) bool {
	label, _, _ = strings.Cut(label, ":")
	digits := strings.ContainsAny(label, "0123456789")
	letters := strings.IndexFunc(label, func(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }) >= 0
	return len(label) >= 24 || len(label) >= 10 && digits && letters || hookSecret(label)
}

// hookField is safe for a readable name the user didn't write as a summary
// (a plugin's name or version, an MCP server): a secret-shaped value is
// hidden whole.
func hookField(value string, limit int) string {
	if hookSecret(value) || urlCredential(value) {
		return redacted
	}
	return safe(value, limit)
}

// urlCredential reports a URL that can carry a credential: a user or
// password (`https://build:pass@repo.example`), or a query or fragment
// (`?sig=…`). A generated manifest can hold one; a plain URL stays.
func urlCredential(value string) bool {
	_, rest, ok := strings.Cut(value, "://")
	if !ok {
		return false
	}
	host, _, _ := strings.Cut(rest, "/")
	return strings.Contains(host, "@") || strings.ContainsAny(rest, "?#")
}

// hookVersion keeps a plugin version only in a version's shape; empty and
// Claude's "unknown" stay as they are.
func hookVersion(value string) string {
	if value == "" || value == "unknown" {
		return value
	}
	// A version's shape is checked instead of the long-token rule, which
	// would hide every full commit hash; a vendor token or other secret
	// shape is still hidden.
	if !pluginVersion.MatchString(value) || secretPattern.MatchString(value) || payloadcapture.HasSecretToken(value) {
		return redacted
	}
	return safe(value, 64)
}

// fileEvents match on a file's name, which can be private (a watched
// `acquisition-targets.csv`): only a bare extension or `*` stays readable.
var (
	fileEvents      = []string{"FileChanged"}
	fileMatcherPart = regexp.MustCompile(`^(\*|\*\.[A-Za-z0-9]{1,16})$`)
)

// safeEventMatcher is safeMatcher, with file events' names hidden too.
func safeEventMatcher(event, matcher string) string {
	if !slices.Contains(fileEvents, event) || matcher == "" {
		return safeMatcher(matcher)
	}
	parts := strings.Split(matcher, "|")
	for i, part := range parts {
		if !fileMatcherPart.MatchString(strings.TrimSpace(part)) {
			parts[i] = redacted
		}
	}
	return safeMatcher(strings.Join(parts, "|"))
}

// safeMatcher keeps a matcher's tool names and patterns, which tell an
// administrator what a hook watches, and replaces any alternative that holds
// a path or reads as a secret.
func safeMatcher(matcher string) string {
	parts := strings.Split(matcher, "|")
	for i, part := range parts {
		control := strings.ContainsFunc(part, func(r rune) bool { return r < 0x20 || r == 0x7f })
		if control || strings.ContainsAny(part, `/\`) || windowsPath.MatchString(part) || hookSecret(part) {
			parts[i] = redacted
		}
	}
	return safe(strings.Join(parts, "|"), 256)
}
