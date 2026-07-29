package risk

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/kontext-security/kontext-cli/internal/payloadcapture"
)

func TestNormalizeCredentialFileRead(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Read", ToolInput: map[string]any{"file_path": ".env"}})
	if event.Type != EventCredentialAccess {
		t.Fatalf("type = %s, want %s", event.Type, EventCredentialAccess)
	}
	if event.PathClass != "env_file" {
		t.Fatalf("path class = %s", event.PathClass)
	}
}

func TestNormalizeRelativeCloudCredentialFileRead(t *testing.T) {
	for _, path := range []string{
		".aws/credentials",
		"./.gcloud/application_default_credentials.json",
		".config/railway/config.json",
		"nested/.aws/config",
	} {
		t.Run(path, func(t *testing.T) {
			event := NormalizeHookEvent(HookEvent{ToolName: "Read", ToolInput: map[string]any{"file_path": path}})
			if event.Type != EventCredentialAccess {
				t.Fatalf("type = %s, want %s", event.Type, EventCredentialAccess)
			}
			if event.PathClass != "cloud_credentials" {
				t.Fatalf("path class = %s, want cloud_credentials", event.PathClass)
			}
		})
	}
}

func TestNormalizeShellCredentialAccess(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": "cat .env"}})
	if event.Type != EventCredentialAccess {
		t.Fatalf("type = %s", event.Type)
	}
	if event.CredentialSource != "command_output" {
		t.Fatalf("credential source = %s", event.CredentialSource)
	}
}

func TestNormalizeDirectProviderAPI(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": "curl https://api.railway.app/graphql -H 'Authorization: Bearer secret'"}})
	if event.Type != EventDirectProviderAPICall {
		t.Fatalf("type = %s", event.Type)
	}
	if !event.CredentialObserved {
		t.Fatal("credential was not observed")
	}
}

func TestNormalizeDestructiveOperation(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": "railway volume delete production"}})
	if event.Type != EventDestructiveProviderOperation {
		t.Fatalf("type = %s", event.Type)
	}
	if event.OperationClass != "delete" {
		t.Fatalf("operation class = %s", event.OperationClass)
	}
}

func TestNormalizeDestructiveSourceControlOperation(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": "gh repo delete kontext-security/guard"}})
	if event.Type != EventDestructiveProviderOperation {
		t.Fatalf("type = %s", event.Type)
	}
	if event.ProviderCategory != "source_control" {
		t.Fatalf("provider category = %s", event.ProviderCategory)
	}
	if event.ResourceClass != "repo" {
		t.Fatalf("resource class = %s", event.ResourceClass)
	}
}

func TestNormalizeSourceControlReadDefaultsRepoAndLocalEnvironment(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": "git status"}})
	if event.Provider != "git" {
		t.Fatalf("provider = %s, want git", event.Provider)
	}
	if event.ProviderCategory != "source_control" {
		t.Fatalf("provider category = %s, want source_control", event.ProviderCategory)
	}
	if event.Operation != "status" || event.OperationClass != "read" {
		t.Fatalf("operation = %s/%s, want status/read", event.Operation, event.OperationClass)
	}
	if event.ResourceClass != "repo" {
		t.Fatalf("resource class = %s, want repo", event.ResourceClass)
	}
	if event.Environment != "local" {
		t.Fatalf("environment = %s, want local", event.Environment)
	}
}

func TestNormalizeGitHubRepoViewIsReadOnly(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": "gh repo view kontext-security/kontext-cli"}})
	if event.Provider != "github" {
		t.Fatalf("provider = %s, want github", event.Provider)
	}
	if event.Operation != "gh repo view" || event.OperationClass != "read" {
		t.Fatalf("operation = %s/%s, want gh repo view/read", event.Operation, event.OperationClass)
	}
	if event.ResourceClass != "repo" {
		t.Fatalf("resource class = %s, want repo", event.ResourceClass)
	}
	if event.Environment != "local" {
		t.Fatalf("environment = %s, want local", event.Environment)
	}
}

func TestNormalizeGitCommitIgnoresCommitMessageBody(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": `git commit -m "$(cat <<'EOF'
feat: improve dashboard

Mentions production database delete only as copied text.
EOF
)"`}})
	if event.Type != EventNormalToolCall {
		t.Fatalf("type = %s", event.Type)
	}
	if event.OperationClass != "write" {
		t.Fatalf("operation class = %s", event.OperationClass)
	}
	if event.Environment == "production" {
		t.Fatal("environment should not be inferred from commit body")
	}
	if event.CredentialObserved {
		t.Fatal("credential material should not be inferred from commit body")
	}
	for _, signal := range event.Signals {
		if signal == "destructive_verb" || signal == "persistent_resource" {
			t.Fatalf("unexpected signal %s", signal)
		}
	}
}

func TestNormalizeGitHubPRDoesNotTreatBodyAsCredential(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": `gh pr create --title "feat: dashboard" --body "$(cat <<'EOF'
This mentions token handling in documentation but does not pass a token.
EOF
)"`}})
	if event.ProviderCategory != "source_control" {
		t.Fatalf("provider category = %s", event.ProviderCategory)
	}
	if event.CredentialObserved {
		t.Fatal("credential material should not be inferred from PR body text")
	}
}

func TestNormalizeDirectProviderAPIStillSeesAuthorizationHeader(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": `curl https://api.cloudflare.com/client/v4/zones -H "Authorization: Bearer abc123"`}})
	if event.Type != EventDirectProviderAPICall {
		t.Fatalf("type = %s", event.Type)
	}
	if !event.CredentialObserved {
		t.Fatal("credential material was not observed")
	}
}

func TestNormalizeDirectProviderAPIGoogleCloud(t *testing.T) {
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": `curl https://storage.googleapis.com/storage/v1/b/example-bucket/o`}})
	if event.Type != EventDirectProviderAPICall {
		t.Fatalf("type = %s", event.Type)
	}
	if event.Provider != "google_cloud" {
		t.Fatalf("provider = %s, want google_cloud", event.Provider)
	}
	if event.ProviderCategory != "infrastructure" {
		t.Fatalf("provider category = %s, want infrastructure", event.ProviderCategory)
	}
}

func TestNormalizeRedactsCredentialValuesFromSummaries(t *testing.T) {
	cases := []struct {
		name        string
		command     string
		secret      string
		wantSummary string
	}{
		{"token assignment", `API_TOKEN=real-secret-123 curl https://api.cloudflare.com`, "real-secret-123", `API_TOKEN=[REDACTED_SECRET] curl https://api.cloudflare.com`},
		{"access key assignment", `ACCESS_KEY=access-secret-123 echo ok`, "access-secret-123", `ACCESS_KEY=[REDACTED_SECRET] echo ok`},
		{"bearer header", `curl -H "Authorization: Bearer bearer-secret-123"`, "bearer-secret-123", `curl -H "Authorization: Bearer [REDACTED_SECRET]"`},
		{"plain authorization header", `curl -H 'Authorization: header-secret-123' example.com`, "header-secret-123", `curl -H 'Authorization: [REDACTED_SECRET]' example.com`},
		{"basic authorization header", `curl -H 'Authorization: Basic dXNlcjpwYXNzd29yZA==' example.com`, "dXNlcjpwYXNzd29yZA==", `curl -H 'Authorization: Basic [REDACTED_SECRET]' example.com`},
		{"short bearer", `echo Bearer abc123`, "abc123", `echo Bearer [REDACTED_SECRET]`},
		{"password assignment", `mysql --password=password-secret-123 -u root`, "password-secret-123", `mysql --password=[REDACTED_SECRET] -u root`},
		{"pwd assignment", `PWD=pwd-secret-123 echo ok`, "pwd-secret-123", `PWD=[REDACTED_SECRET] echo ok`},
		{"pass flag", `login --pass pass-secret-123`, "pass-secret-123", `login --pass [REDACTED_SECRET]`},
		{"uppercase password export", `export PASSWORD=password-secret-123`, "password-secret-123", `export PASSWORD=[REDACTED_SECRET]`},
		{"bare github token", `echo ghp_AbCdEfGhIjKlMnOpQrStUvWx123456`, "ghp_AbCdEfGhIjKlMnOpQrStUvWx123456", `echo [REDACTED_SECRET]`},
		{"bare aws access key id", `aws sts get-caller-identity # AKIAIOSFODNN7EXAMPLE`, "AKIAIOSFODNN7EXAMPLE", `aws sts get-caller-identity # [REDACTED_SECRET]`},
		{"header value with redactable label", `curl -H 'x-api-key: header-secret-123' https://x.io`, "header-secret-123", `curl -H 'x-api-key: [REDACTED_SECRET]' https://x.io`},
		{"semicolon separator", `printf ok;TOKEN=secret echo next`, "secret", `printf ok;TOKEN=[REDACTED_SECRET] echo next`},
		{"pipe separator", `printf ok|TOKEN=secret echo next`, "secret", `printf ok|TOKEN=[REDACTED_SECRET] echo next`},
		{"outer quotes", `echo "TOKEN=secret"`, "secret", `echo "TOKEN=[REDACTED_SECRET]"`},
		{"mixed shell word", `TOKEN=foo"bar" echo next`, "bar", `TOKEN=[REDACTED_SECRET] echo next`},
		{"query separator", `curl 'https://x.test?code=query-secret&state=x'`, "query-secret", `curl 'https://x.test?code=[REDACTED_SECRET]&state=x'`},
		{"json command", `curl -d '{"password":"json-secret-123"}'`, "json-secret-123", `curl -d '{"password":"[REDACTED_SECRET]"}'`},
		{"curl user password", `curl -u user:curl-secret-123 https://x.test`, "curl-secret-123", `curl -u [REDACTED_SECRET] https://x.test`},
		{"unclosed quote", `TOKEN="unterminated-secret`, "unterminated-secret", `TOKEN=[REDACTED_SECRET]`},
		{"unclosed quote mid-value", `TOKEN=a"broken-secret deploy`, "broken-secret", `TOKEN=[REDACTED_SECRET] deploy`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": tc.command}})
			for name, value := range map[string]string{
				"command": event.CommandSummary,
				"request": event.RequestSummary,
			} {
				if strings.Contains(value, tc.secret) {
					t.Fatalf("%s summary leaked credential value: %q", name, value)
				}
				if value != tc.wantSummary {
					t.Fatalf("%s summary = %q, want %q", name, value, tc.wantSummary)
				}
			}
		})
	}
}

func TestNormalizeOmitsOversizedCommandSummaryButClassifiesFullCommand(t *testing.T) {
	command := "TOKEN=oversized-secret " + strings.Repeat("x", maxSummaryRedactionInputBytes+1) + " drop production database"
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": command}})

	if event.CommandSummary != oversizedCommandSummary || event.RequestSummary != oversizedCommandSummary {
		t.Fatalf("summaries = %q / %q, want oversized marker", event.CommandSummary, event.RequestSummary)
	}
	if strings.Contains(event.CommandSummary, "oversized-secret") {
		t.Fatalf("oversized summary leaked credential: %q", event.CommandSummary)
	}
	if event.Type != EventDestructiveProviderOperation || event.Environment != "production" {
		t.Fatalf("full command was not classified: %+v", event)
	}
}

func TestNormalizeRedactsCommandAtSummaryInputLimit(t *testing.T) {
	secret := "limit-secret"
	prefix := "TOKEN=" + secret + " "
	command := prefix + strings.Repeat("x", maxSummaryRedactionInputBytes-len(prefix))
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": command}})

	if strings.Contains(event.CommandSummary, secret) || !strings.Contains(event.CommandSummary, payloadcapture.RedactedPlaceholder) {
		t.Fatalf("summary at limit was not safely redacted: %q", event.CommandSummary)
	}
	if event.CommandSummary != event.RequestSummary {
		t.Fatalf("command summaries differ: %q / %q", event.CommandSummary, event.RequestSummary)
	}
}

func TestNormalizeTruncatesCommandSummaryAtUTF8Boundary(t *testing.T) {
	command := strings.Repeat("x", maxCommandSummaryBytes-1) + "€ trailing text"
	event := NormalizeHookEvent(HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": command}})

	if !utf8.ValidString(event.CommandSummary) {
		t.Fatalf("summary is not valid UTF-8: %q", event.CommandSummary)
	}
	if len(event.CommandSummary) > maxCommandSummaryBytes+len("...") {
		t.Fatalf("summary has %d bytes, want at most %d", len(event.CommandSummary), maxCommandSummaryBytes+len("..."))
	}
	if event.CommandSummary != event.RequestSummary {
		t.Fatalf("command summaries differ: %q / %q", event.CommandSummary, event.RequestSummary)
	}
}

func BenchmarkNormalizeHookEventCommandSummary(b *testing.B) {
	for _, size := range []int{240, 4 << 10, maxSummaryRedactionInputBytes, 1 << 20} {
		b.Run(fmt.Sprintf("bytes=%d", size), func(b *testing.B) {
			command := strings.Repeat("x", size)
			event := HookEvent{ToolName: "Bash", ToolInput: map[string]any{"command": command}}
			b.ReportAllocs()
			for b.Loop() {
				_ = NormalizeHookEvent(event)
			}
		})
	}
}

func TestDeterministicDecisionBlocksDestructiveCommand(t *testing.T) {
	decision, err := DecideRisk(HookEvent{HookEventName: "PreToolUse", ToolName: "Bash", ToolInput: map[string]any{"command": "drop database"}})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != DecisionDeny {
		t.Fatalf("decision = %s", decision.Decision)
	}
}

func TestDeterministicDecisionAllowsNormalToolCalls(t *testing.T) {
	decision, err := DecideRisk(HookEvent{HookEventName: "PreToolUse", ToolName: "Read", ToolInput: map[string]any{"file_path": "README.md"}})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != DecisionAllow {
		t.Fatalf("decision = %s", decision.Decision)
	}
}

func TestDeterministicDecisionBlocksRelativeCloudCredentialRead(t *testing.T) {
	decision, err := DecideRisk(HookEvent{
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolInput:     map[string]any{"file_path": ".aws/credentials"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != DecisionDeny {
		t.Fatalf("decision = %s, want %s", decision.Decision, DecisionDeny)
	}
	if decision.ReasonCode != "credential_access_without_intent" {
		t.Fatalf("reason code = %s", decision.ReasonCode)
	}
}

func TestAsyncTelemetryAllowsWithoutRiskModel(t *testing.T) {
	decision, err := DecideRisk(HookEvent{HookEventName: "UserPromptSubmit", ToolName: "Read"})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != DecisionAllow {
		t.Fatalf("decision = %s", decision.Decision)
	}
}

func TestAddSignalPreservesFirstSeenOrderAndSkipsDuplicates(t *testing.T) {
	t.Parallel()

	event := RiskEvent{}
	signalSet := make(map[string]struct{}, 3)

	addSignal(&event, signalSet, "source_control")
	addSignal(&event, signalSet, "direct_provider_api")
	addSignal(&event, signalSet, "source_control")
	addSignal(&event, signalSet, "credential_observed")
	addSignal(&event, signalSet, "direct_provider_api")

	want := []string{"source_control", "direct_provider_api", "credential_observed"}
	if !reflect.DeepEqual(event.Signals, want) {
		t.Fatalf("signals = %#v, want %#v", event.Signals, want)
	}
}
