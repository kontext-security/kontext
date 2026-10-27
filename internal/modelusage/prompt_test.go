package modelusage

import "testing"

func TestIsHarnessEnvelope(t *testing.T) {
	for _, test := range []struct {
		name   string
		prompt string
		want   bool
	}{
		{"empty", "", true},
		{"whitespace", " \n\t", true},
		{"reminders only", "<system-reminder>\nThe user opened a file.\n</system-reminder>\n<system-reminder>x</system-reminder>", true},
		{"task notification", "<task-notification>\n<task-id>a1</task-id>\n<status>completed</status>\n</task-notification>", true},
		{"side-sessions event", "<side-sessions-event>Session X ended a turn.</side-sessions-event>", true},
		{"ci monitor event", "<ci-monitor-event>checks failed</ci-monitor-event>", true},
		{"cross-session message", `<cross-session-message from="local_1" name="parent">do the thing</cross-session-message>`, true},
		{"cross-session plain text", "[Cross-session message from parent] do the thing", true},
		{"subagent hand-back", "<agent-message from=\"a13320f5adabb3da9\">\n[Subagent hand-back] The text you asked for.\n</agent-message>", true},
		{"shell command", "<bash-input>git status</bash-input>", true},
		{"shell command after reminders", "<system-reminder>\nLinked sessions now\n</system-reminder>\n<bash-input>awk '/Key:/' notes.txt</bash-input>", true},
		{"local command output", "<local-command-stdout>Set model to opus</local-command-stdout>", true},
		{"codex environment context", "<environment_context>\n  <cwd>/tmp</cwd>\n</environment_context>", true},
		{"codex app context", `<external_codex_apps_open_page>{"page_id":null}</external_codex_apps_open_page>`, true},
		{"codex internal context", "<codex_internal_context>…</codex_internal_context>", true},
		{"envelope after reminders and space", "<system-reminder>r</system-reminder>\n\n  <task-notification>done</task-notification>", true},
		// Real prompts often arrive with reminder blocks prepended.
		{"reminder then a person's text", "<system-reminder>\nThe user opened report.md\n</system-reminder>\nfix the failing cost summary spec", false},
		{"plain prompt", "fix the failing cost summary spec", false},
		{"slash command", "/review the diff", false},
		{"envelope quoted later in a prompt", "why did this <task-notification> arrive twice?", false},
		{"other markup", "<div>render this</div>", false},
		{"lookalike", "<task-notifications> are noisy, mute them", false},
		{"bash-input quoted later", "explain what <bash-input> rows are", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := IsHarnessEnvelope(test.prompt); got != test.want {
				t.Fatalf("IsHarnessEnvelope(%q) = %v, want %v", test.prompt, got, test.want)
			}
		})
	}
}
