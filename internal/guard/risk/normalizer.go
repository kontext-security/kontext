package risk

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/kontext-security/kontext-cli/internal/payloadcapture"
)

// credentialReference is a classification signal, not a redactor: it matches
// the shapes redaction removes, so it must only ever run on raw command text.
var credentialReference = regexp.MustCompile(`(?i)(authorization\s*:|bearer\s+[a-z0-9._~+/=-]+|api[_-]?key\s*[=:]|secret\s*[=:]|token\s*[=:]|\$[A-Z0-9_]*(TOKEN|SECRET|API_KEY|ACCESS_KEY)[A-Z0-9_]*)`)
var destructiveWord = regexp.MustCompile(`(?i)\b(delete|destroy|drop|truncate|wipe)\b`)
var resourceWord = regexp.MustCompile(`(?i)\b(database|volume|backup|bucket|project|repo|repository|branch|deployment|namespace|secret)\b`)

const (
	maxCommandSummaryBytes        = 240
	maxSummaryRedactionInputBytes = 64 << 10
	oversizedCommandSummary       = "[command omitted: exceeds summary limit]"
)

var directProviderHosts = map[string]string{
	"api.railway.app":      "railway",
	"railway.app":          "railway",
	"api.vercel.com":       "vercel",
	"api.digitalocean.com": "digitalocean",
	"api.cloudflare.com":   "cloudflare",
	"googleapis.com":       "google_cloud",
	"amazonaws.com":        "aws",
	"api.github.com":       "github",
}

func NormalizeHookEvent(event HookEvent) RiskEvent {
	toolName := strings.TrimSpace(event.ToolName)
	command := commandFromInput(event.ToolInput)
	path := pathFromInput(event.ToolInput)
	inputText := ""
	if command == "" {
		inputText = strings.ToLower(MarshalInput(event.ToolInput))
	}
	commandSignalText := commandRiskText(command)
	environmentText := inputText + " " + strings.ToLower(path)
	if command != "" {
		environmentText = strings.ToLower(commandSignalText + " " + path)
	}
	commandSummary := summarizeCommand(command)
	requestSummary := summarizeRequest(toolName, path)
	if command != "" {
		requestSummary = commandSummary
	}
	riskEvent := RiskEvent{
		Type:             EventNormalToolCall,
		ProviderCategory: "unknown",
		OperationClass:   "unknown",
		ResourceClass:    "unknown",
		Environment:      environmentFromText(environmentText),
		CommandSummary:   commandSummary,
		RequestSummary:   requestSummary,
		Confidence:       0.75,
	}

	lowerTool := strings.ToLower(toolName)
	lowerCommand := strings.ToLower(command)
	combinedInput := inputText
	if command != "" {
		combinedInput = ""
	}
	combined := strings.ToLower(fmt.Sprintf("%s %s %s", toolName, commandSignalText, combinedInput))

	signalSet := make(map[string]struct{}, 8)
	if strings.HasPrefix(lowerTool, "mcp__") {
		riskEvent.Type = EventManagedToolCall
		addSignal(&riskEvent, signalSet, "managed_tool")
	}
	if lowerTool == "bash" || strings.Contains(lowerTool, "bash") || strings.Contains(lowerTool, "shell") {
		classifySourceControl(&riskEvent, signalSet, lowerCommand)
	}
	if isReadTool(lowerTool) && isCredentialPath(path) {
		riskEvent.Type = EventCredentialAccess
		riskEvent.CredentialObserved = true
		riskEvent.CredentialSource = "tool_input"
		riskEvent.PathClass = pathClass(path)
		addSignal(&riskEvent, signalSet, "credential_path")
	}
	if lowerTool == "bash" || strings.Contains(lowerTool, "bash") || strings.Contains(lowerTool, "shell") {
		classifyBash(&riskEvent, signalSet, lowerCommand, commandSignalText)
	}
	if strings.Contains(lowerCommand, "curl") {
		classifyProvider(&riskEvent, signalSet, lowerCommand)
	}
	if observesCredential(lowerCommand, riskEvent.Type) {
		riskEvent.CredentialObserved = true
		if riskEvent.CredentialSource == "" {
			riskEvent.CredentialSource = "tool_input"
		}
		addSignal(&riskEvent, signalSet, "credential_observed")
	}
	if op := destructiveOperation(combined); op != "" {
		riskEvent.Operation = op
		riskEvent.OperationClass = "delete"
		addSignal(&riskEvent, signalSet, "destructive_verb")
	}
	if resource := resourceClass(combined); resource != "" {
		riskEvent.ResourceClass = resource
		addSignal(&riskEvent, signalSet, "persistent_resource")
	}
	if riskEvent.OperationClass == "delete" && isPersistentResource(riskEvent.ResourceClass) {
		riskEvent.Type = EventDestructiveProviderOperation
	}
	if riskEvent.Type == EventNormalToolCall && looksUnknownHighRisk(combined) {
		riskEvent.Type = EventUnknown
		addSignal(&riskEvent, signalSet, "unknown_high_risk")
	}
	if explicitIntent(combined) {
		riskEvent.ExplicitUserIntent = true
		addSignal(&riskEvent, signalSet, "explicit_user_intent")
	}
	if riskEvent.Provider == "" && riskEvent.Type == EventDirectProviderAPICall {
		riskEvent.Provider = "unknown"
		riskEvent.ProviderCategory = "infrastructure"
	}
	if riskEvent.ProviderCategory == "source_control" && riskEvent.ResourceClass == "unknown" {
		riskEvent.ResourceClass = "repo"
	}
	if riskEvent.ProviderCategory == "source_control" && riskEvent.Environment == "unknown" {
		riskEvent.Environment = "local"
	}
	return riskEvent
}

func classifyBash(event *RiskEvent, signalSet map[string]struct{}, command, combined string) {
	if strings.Contains(command, "cat .env") || strings.Contains(command, "printenv") {
		event.Type = EventCredentialAccess
		event.CredentialObserved = true
		event.CredentialSource = "command_output"
		if strings.Contains(command, ".env") {
			event.PathClass = "env_file"
		}
		addSignal(event, signalSet, "shell_credential_access")
	}
	if strings.Contains(command, "curl") {
		classifyProvider(event, signalSet, command)
	}
}

func classifySourceControl(event *RiskEvent, signalSet map[string]struct{}, command string) {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return
	}
	switch fields[0] {
	case "git":
		event.Provider = "git"
		event.ProviderCategory = "source_control"
		addSignal(event, signalSet, "source_control")
		if len(fields) > 1 {
			event.Operation = fields[1]
			switch fields[1] {
			case "add", "commit", "merge", "rebase", "push", "tag":
				event.OperationClass = "write"
			case "status", "diff", "log", "show", "branch":
				event.OperationClass = "read"
			}
		}
	case "gh":
		event.Provider = "github"
		event.ProviderCategory = "source_control"
		addSignal(event, signalSet, "source_control")
		if len(fields) > 1 {
			event.Operation = strings.Join(fields[:min(len(fields), 3)], " ")
			event.OperationClass = "write"
			if fields[1] == "pr" && len(fields) > 2 {
				switch fields[2] {
				case "view", "list", "status", "checks", "diff":
					event.OperationClass = "read"
				}
			}
			if fields[1] == "repo" && len(fields) > 2 {
				switch fields[2] {
				case "view", "list":
					event.OperationClass = "read"
				}
			}
		}
	}
}

func classifyProvider(event *RiskEvent, signalSet map[string]struct{}, text string) {
	for host, provider := range directProviderHosts {
		if strings.Contains(text, host) {
			event.Type = EventDirectProviderAPICall
			event.Provider = provider
			event.DirectAPICall = true
			if provider == "github" {
				event.ProviderCategory = "source_control"
			} else {
				event.ProviderCategory = "infrastructure"
			}
			addSignal(event, signalSet, "direct_provider_api")
			return
		}
	}
}

func commandFromInput(input map[string]any) string {
	for _, key := range []string{"command", "cmd", "script"} {
		if value, ok := input[key].(string); ok {
			return value
		}
	}
	return ""
}

func pathFromInput(input map[string]any) string {
	for _, key := range []string{"file_path", "path", "filename"} {
		if value, ok := input[key].(string); ok {
			return value
		}
	}
	return ""
}

func isReadTool(tool string) bool {
	return tool == "read" || strings.Contains(tool, "read")
}

func isCredentialPath(path string) bool {
	clean := normalizedPath(path)
	base := filepath.Base(clean)
	switch base {
	case ".env", ".npmrc", ".pypirc", ".netrc":
		return true
	}
	return hasPathSegmentPrefix(clean, ".aws") ||
		hasPathSegmentPrefix(clean, ".gcloud") ||
		hasPathSegmentPrefix(clean, ".config/railway")
}

func pathClass(path string) string {
	clean := normalizedPath(path)
	base := filepath.Base(clean)
	if base == ".env" || base == ".npmrc" || base == ".pypirc" || base == ".netrc" {
		return "env_file"
	}
	if hasPathSegmentPrefix(clean, ".aws") ||
		hasPathSegmentPrefix(clean, ".gcloud") ||
		hasPathSegmentPrefix(clean, ".config/railway") {
		return "cloud_credentials"
	}
	return "unknown"
}

func normalizedPath(path string) string {
	return strings.ToLower(filepath.ToSlash(filepath.Clean(path)))
}

func hasPathSegmentPrefix(clean, prefix string) bool {
	return clean == prefix ||
		strings.HasPrefix(clean, prefix+"/") ||
		strings.Contains(clean, "/"+prefix+"/") ||
		strings.HasSuffix(clean, "/"+prefix)
}

func destructiveOperation(text string) string {
	match := destructiveWord.FindStringSubmatch(text)
	if len(match) > 1 {
		return strings.ToLower(match[1])
	}
	return ""
}

func resourceClass(text string) string {
	match := resourceWord.FindStringSubmatch(text)
	if len(match) > 1 {
		return strings.ToLower(match[1])
	}
	return ""
}

func isPersistentResource(resource string) bool {
	switch resource {
	case "database", "volume", "backup", "bucket", "project", "repo", "repository", "branch", "deployment", "namespace", "secret":
		return true
	default:
		return false
	}
}

func environmentFromText(text string) string {
	switch {
	case strings.Contains(text, "production") || strings.Contains(text, " prod"):
		return "production"
	case strings.Contains(text, "staging"):
		return "staging"
	case strings.Contains(text, "development") || strings.Contains(text, " dev"):
		return "development"
	case strings.Contains(text, "local"):
		return "local"
	default:
		return "unknown"
	}
}

func explicitIntent(text string) bool {
	return strings.Contains(text, "explicit_user_intent") || strings.Contains(text, "user_approved") || strings.Contains(text, "approved_by_user")
}

func looksUnknownHighRisk(text string) bool {
	return strings.Contains(text, "sudo ") || strings.Contains(text, "rm -rf") || strings.Contains(text, "chmod 777")
}

func summarizeRequest(toolName, path string) string {
	switch {
	case path != "":
		return fmt.Sprintf("%s %s", toolName, path)
	default:
		return toolName
	}
}

// summarizeCommand produces the summary form of a command: secrets are
// removed by the shared payloadcapture ruleset, then the result is truncated
// for display. Oversized inputs fail closed because truncating before
// redaction could split a secret match and expose its prefix.
// Classification never consumes this output — signal detection (e.g.
// observesCredential) runs on the raw command, because redaction removes the
// exact shapes those detectors match.
func summarizeCommand(value string) string {
	if len(value) > maxSummaryRedactionInputBytes {
		return oversizedCommandSummary
	}
	redacted, _ := payloadcapture.RedactText(value)
	if len(redacted) > maxCommandSummaryBytes {
		end := maxCommandSummaryBytes
		for end > 0 && !utf8.RuneStart(redacted[end]) {
			end--
		}
		return redacted[:end] + "..."
	}
	return redacted
}

func observesCredential(command string, eventType EventType) bool {
	if eventType == EventCredentialAccess {
		return true
	}
	return credentialReference.MatchString(stripHereDocs(command))
}

func commandRiskText(command string) string {
	withoutDocs := stripHereDocs(command)
	return stripQuotedText(withoutDocs)
}

func stripHereDocs(command string) string {
	lines := strings.Split(command, "\n")
	out := make([]string, 0, len(lines))
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		out = append(out, line)
		marker := heredocMarker(line)
		if marker == "" {
			continue
		}
		for i+1 < len(lines) {
			i++
			if strings.TrimSpace(lines[i]) == marker {
				break
			}
		}
	}
	return strings.Join(out, "\n")
}

func heredocMarker(line string) string {
	idx := strings.Index(line, "<<")
	if idx < 0 {
		return ""
	}
	marker := strings.TrimSpace(line[idx+2:])
	marker = strings.TrimPrefix(marker, "-")
	marker = strings.Trim(marker, `"'`)
	if marker == "" || strings.ContainsAny(marker, " \t") {
		return ""
	}
	return marker
}

func stripQuotedText(value string) string {
	var b strings.Builder
	inSingle := false
	inDouble := false
	escaped := false
	for _, r := range value {
		switch {
		case escaped:
			escaped = false
			if !inSingle && !inDouble {
				b.WriteRune(r)
			}
		case r == '\\':
			escaped = true
			if !inSingle && !inDouble {
				b.WriteRune(r)
			}
		case r == '\'' && !inDouble:
			inSingle = !inSingle
			b.WriteRune(' ')
		case r == '"' && !inSingle:
			inDouble = !inDouble
			b.WriteRune(' ')
		case inSingle || inDouble:
			if r == '\n' {
				b.WriteRune('\n')
			} else {
				b.WriteRune(' ')
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func addSignal(event *RiskEvent, signalSet map[string]struct{}, signal string) {
	if _, exists := signalSet[signal]; exists {
		return
	}
	signalSet[signal] = struct{}{}
	event.Signals = append(event.Signals, signal)
}
