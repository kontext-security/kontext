package agentauthority

import (
	"encoding/json"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Keep identical to AUTHORITY_SECRET_PATTERN in the cloud contract.
var secretPattern = regexp.MustCompile(`(?i)ghp_|gho_|ghu_|github_pat_|\bsk-[A-Za-z0-9]|xox[abp]-|\bAKIA[0-9A-Z]{16}|AIza|Bearer |-----BEGIN|(password|passwd|secret|token|api[-_]?key)=`)

var secretArgName = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[-_]?key)`)

var longTokenPattern = regexp.MustCompile(`^[A-Za-z0-9+/=]{32,}$`)

func secret(value, key string) bool {
	if secretPattern.MatchString(value) {
		return true
	}
	if key == "source" || key == "name" || key == "path" {
		return false
	}
	for _, token := range strings.FieldsFunc(value, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_+/=", r))
	}) {
		if !longTokenPattern.MatchString(token) {
			continue
		}
		letters, digits := false, false
		for _, r := range token {
			letters = letters || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
			digits = digits || r >= '0' && r <= '9'
		}
		if letters && digits {
			return true
		}
	}
	return false
}

func safe(value string, limit int) string {
	if secretPattern.MatchString(value) {
		return ""
	}
	runes := []rune(value)
	if len(runes) > limit {
		return string(runes[:limit])
	}
	return value
}
func pointer(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
func safeArgs(args []string) []string {
	cleaned := []string{}
	for i := 0; i < len(args); i++ {
		arg := strings.Trim(args[i], "\"'")
		if secretFlag(arg) {
			if i+1 < len(args) && !strings.HasPrefix(strings.Trim(args[i+1], "\"'"), "-") {
				i++
			}
			continue
		}
		if value := safeArg(arg); value != "" {
			cleaned = append(cleaned, value)
		}
	}
	return cleaned
}

func secretFlag(arg string) bool {
	if !strings.HasPrefix(arg, "-") || strings.Contains(arg, "=") {
		return false
	}
	name := strings.ToLower(strings.TrimLeft(arg, "-"))
	if strings.HasPrefix(name, "no-") || strings.HasPrefix(name, "no_") {
		return false
	}
	parts := strings.Split(strings.ReplaceAll(name, "_", "-"), "-")
	switch parts[len(parts)-1] {
	case "password", "passwd", "secret", "token", "apikey":
		return true
	case "key":
		return len(parts) > 1 && parts[len(parts)-2] == "api"
	}
	return false
}

func safeArg(arg string) string {
	if name, _, hasValue := strings.Cut(arg, "="); hasValue && secretArgName.MatchString(name) {
		return ""
	}
	if secret(arg, "args") {
		return ""
	}
	if strings.Contains(arg, "://") {
		u, err := url.Parse(arg)
		if err != nil || u.User != nil || u.Scheme == "" || u.Hostname() == "" {
			return "<redacted>"
		}
		return safe(u.Scheme+"://"+u.Host, 64)
	}
	for _, part := range strings.FieldsFunc(arg, func(r rune) bool { return r == '=' || r == ':' }) {
		if filepath.IsAbs(part) {
			return "<redacted>"
		}
	}
	return safe(arg, 64)
}
func (r *Report) finish() {
	// Last defense for strings from every reader, before any payload can escape.
	data, _ := json.Marshal(r)
	var value map[string]any
	_ = json.Unmarshal(data, &value)
	var clean func(any, string) (any, bool)
	clean = func(v any, key string) (any, bool) {
		switch x := v.(type) {
		case string:
			return x, !secret(x, key)
		case []any:
			result := []any{}
			for _, entry := range x {
				if c, ok := clean(entry, key); ok {
					result = append(result, c)
				}
			}
			return result, true
		case map[string]any:
			result := map[string]any{}
			for key, entry := range x {
				c, ok := clean(entry, key)
				if !ok {
					return nil, false
				}
				result[key] = c
			}
			return result, true
		default:
			return v, true
		}
	}
	// Only the hash itself is a deliberately long hex string.
	delete(value, "hash")
	value["hash"] = ""
	cleaned, ok := clean(value, "")
	if !ok {
		*r = Report{}
		return
	}
	data, _ = json.Marshal(cleaned)
	_ = json.Unmarshal(data, r)
	for i := range r.Agents {
		a := &r.Agents[i]
		trimSlice(&a.MCPServers, 64, &r.Coverage.SkippedFiles)
		trimSlice(&a.Plugins, 64, &r.Coverage.SkippedFiles)
		trimSlice(&a.Permissions.Allow, 64, &r.Coverage.SkippedFiles)
	}
	trimSlice(&r.Agents, 25, &r.Coverage.SkippedFiles)
	trimSlice(&r.Credentials, 32, &r.Coverage.SkippedFiles)
	trimSlice(&r.Coverage.Errors, 200, &r.Coverage.SkippedFiles)
	trimSlice(&r.Coverage.Limits, 25, &r.Coverage.SkippedFiles)
	trimSlice(&r.Coverage.UnknownFormat, 25, &r.Coverage.SkippedFiles)
	r.Hash = strings.Repeat("0", 64)
	for {
		data, _ = json.Marshal(r)
		if len(data) <= maxReportBytes {
			break
		}
		r.Truncated = true
		dropped := false
		for kind := 0; kind < 3 && !dropped; kind++ {
			for i := len(r.Agents) - 1; i >= 0 && !dropped; i-- {
				a := &r.Agents[i]
				switch kind {
				case 0:
					dropped = dropLast(&a.Plugins)
				case 1:
					dropped = dropLast(&a.MCPServers)
				case 2:
					dropped = dropLast(&a.Permissions.Allow)
				}
			}
		}
		if !dropped {
			if !dropLast(&r.Coverage.Errors) && !dropLast(&r.Credentials) && !dropLast(&r.Agents) {
				break
			}
		}
	}
	r.Hash, _ = r.ContentHash()
}
func trimSlice[T any](values *[]T, max int, skipped *int) {
	if len(*values) > max {
		*skipped += len(*values) - max
		*values = (*values)[:max]
	}
}
func dropLast[T any](values *[]T) bool {
	if len(*values) == 0 {
		return false
	}
	*values = (*values)[:len(*values)-1]
	return true
}
func validText(value string) bool { return utf8.ValidString(value) && value != "" }
