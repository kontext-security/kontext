package agentauthority

import (
	"net/url"
	"regexp"
	"strings"
)

// A hook's readable fields go to the workspace's dashboard, so they keep only
// what is known to be safe and drop the rest: a credential can sit in any
// argument (curl -u user:pass), not only behind a flag the scanner knows.

var (
	summaryWord = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,63}$`)
	summaryFlag = regexp.MustCompile(`^--?[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	programName = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)
)

const redacted = "<redacted>"

// hookSummary is the program's file name and the arguments that read as
// plain words or flag names. A flag's value, a path, a URL's user, path and
// query, and anything else are replaced.
func hookSummary(program string, args []string) string {
	name := program[strings.LastIndexAny(program, `/\`)+1:]
	if !programName.MatchString(name) || secret(name, "args") {
		name = redacted
	}
	words := []string{name}
	add := func(word string) {
		if word == redacted && words[len(words)-1] == redacted {
			return
		}
		words = append(words, word)
	}
	afterFlag := false
	for _, raw := range args {
		arg := strings.Trim(raw, `"'`)
		switch {
		case strings.HasPrefix(arg, "-"):
			flag, _, hasValue := strings.Cut(arg, "=")
			if !summaryFlag.MatchString(flag) {
				add(redacted)
				afterFlag = false
				continue
			}
			add(flag)
			if hasValue {
				add(redacted)
			}
			afterFlag = !hasValue
		case strings.Contains(arg, "://"):
			add(summaryURL(arg))
			afterFlag = false
		case afterFlag:
			// The value of a flag: a user, a password, a key file.
			add(redacted)
			afterFlag = false
		case summaryWord.MatchString(arg) && !secret(arg, "args"):
			add(arg)
		default:
			add(redacted)
		}
	}
	return safe(strings.Join(words, " "), 256)
}

// summaryURL keeps a URL's scheme and host, and only when it carries no user.
func summaryURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Scheme == "" || u.Hostname() == "" {
		return redacted
	}
	return safe(u.Scheme+"://"+u.Host, 64)
}

// safeMatcher keeps a matcher's tool names and patterns, which tell an
// administrator what a hook watches, and replaces any alternative that holds
// a path or reads as a secret.
func safeMatcher(matcher string) string {
	parts := strings.Split(matcher, "|")
	for i, part := range parts {
		if strings.ContainsAny(part, `/\`) || windowsPath.MatchString(part) || secret(part, "matcher") {
			parts[i] = redacted
		}
	}
	return safe(strings.Join(parts, "|"), 256)
}
