package modelusage

import (
	"regexp"
	"strings"
)

// HarnessBlocks are what the agent harness wraps around or pastes into a
// prompt: reminders, command expansions and pasted content. A turn's prompt
// excerpt leaves them out.
var HarnessBlocks = regexp.MustCompile(`(?s)<system-reminder>.*?</system-reminder>|<command-message>.*?</command-message>|<pasted_content\b[^>]*>.*?</pasted_content>`)

var systemReminderBlocks = regexp.MustCompile(`(?s)<system-reminder>.*?</system-reminder>`)

// harnessEnvelopes open the messages an agent harness delivers to the agent
// as user prompts although no person wrote them. Claude Code fires
// UserPromptSubmit for them and writes them as user rows; Codex writes its
// injected context as user messages, mid-task too.
var harnessEnvelopes = []string{
	"<task-notification>",     // Claude Code: a background task finished
	"<side-sessions-event>",   // Claude desktop: a linked session reported
	"<ci-monitor-event>",      // Claude desktop: a watched pull request changed
	"<cross-session-message",  // Claude desktop: another session wrote
	"[Cross-session",          // the same, in its plain-text form
	"<environment_context>",   // Codex: working directory, date, shell
	"<external_codex_apps_",   // Codex: app integration context
	"<codex_internal_context", // Codex: internal context
}

// IsHarnessEnvelope reports whether a prompt is a harness message rather than
// a person's prompt: empty once system reminders are removed, or opening with
// one of the harness envelopes. Such a prompt starts no turn; the work after
// it belongs to the prompt before. A prompt that only begins with reminders,
// with a person's text after them, is a prompt.
func IsHarnessEnvelope(prompt string) bool {
	text := strings.TrimSpace(systemReminderBlocks.ReplaceAllString(prompt, ""))
	if text == "" {
		return true
	}
	for _, envelope := range harnessEnvelopes {
		if strings.HasPrefix(text, envelope) {
			return true
		}
	}
	return false
}
