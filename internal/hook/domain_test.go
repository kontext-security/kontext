package hook

import "testing"

func TestNormalizeDecision(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want Decision
		ok   bool
	}{
		{name: "allow lowercase", in: "allow", want: DecisionAllow, ok: true},
		{name: "allow uppercase", in: "ALLOW", want: DecisionAllow, ok: true},
		{name: "deny mixed case", in: "DeNy", want: DecisionDeny, ok: true},
		{name: "ask unsupported", in: " ask ", ok: false},
		{name: "unknown", in: "retry", ok: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := NormalizeDecision(tt.in)
			if ok != tt.ok {
				t.Fatalf("NormalizeDecision(%q) ok = %v, want %v", tt.in, ok, tt.ok)
			}
			if got != tt.want {
				t.Fatalf("NormalizeDecision(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestResultReasonOrDefault(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   Result
		want string
	}{
		{
			name: "deny default",
			in:   Result{Decision: DecisionDeny},
			want: "Blocked by Kontext access policy.",
		},
		{
			name: "allow custom",
			in:   Result{Decision: DecisionAllow, Reason: "allowed"},
			want: "allowed",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.in.ReasonOrDefault(); got != tt.want {
				t.Fatalf("ReasonOrDefault() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHookNameCanBlock(t *testing.T) {
	t.Parallel()

	if !HookPreToolUse.CanBlock() {
		t.Fatalf("HookPreToolUse.CanBlock() = false, want true")
	}
	if !HookUserPromptSubmit.CanBlock() {
		t.Fatalf("HookUserPromptSubmit.CanBlock() = false, want true")
	}
	if HookPostToolUse.CanBlock() {
		t.Fatalf("HookPostToolUse.CanBlock() = true, want false")
	}
	if HookPostToolUseFailed.CanBlock() {
		t.Fatalf("HookPostToolUseFailed.CanBlock() = true, want false")
	}
	if HookSessionEnd.CanBlock() {
		t.Fatalf("HookSessionEnd.CanBlock() = true, want false")
	}
	if HookStop.CanBlock() {
		t.Fatalf("HookStop.CanBlock() = true, want false")
	}
}

func TestParseEventAlias(t *testing.T) {
	t.Parallel()

	tests := []struct {
		alias string
		want  HookName
	}{
		{alias: "session-start", want: HookSessionStart},
		{alias: "pre-tool-use", want: HookPreToolUse},
		{alias: "post-tool-use", want: HookPostToolUse},
		{alias: "post-tool-use-failure", want: HookPostToolUseFailed},
		{alias: "session-end", want: HookSessionEnd},
		{alias: "user-prompt-submit", want: HookUserPromptSubmit},
		{alias: "stop", want: HookStop},
		{alias: " Pre-Tool-Use ", want: HookPreToolUse},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.alias, func(t *testing.T) {
			t.Parallel()

			got, ok := ParseEventAlias(tt.alias)
			if !ok {
				t.Fatalf("ParseEventAlias(%q) ok = false", tt.alias)
			}
			if got != tt.want {
				t.Fatalf("ParseEventAlias(%q) = %q, want %q", tt.alias, got, tt.want)
			}
		})
	}

	if _, ok := ParseEventAlias("pretooluse"); ok {
		t.Fatal("ParseEventAlias(pretooluse) ok = true, want false")
	}
}

func TestAliasForEvent(t *testing.T) {
	t.Parallel()

	got, ok := AliasForEvent(HookUserPromptSubmit)
	if !ok {
		t.Fatal("AliasForEvent(HookUserPromptSubmit) ok = false")
	}
	if got != "user-prompt-submit" {
		t.Fatalf("AliasForEvent(HookUserPromptSubmit) = %q, want user-prompt-submit", got)
	}
	if _, ok := AliasForEvent(HookName("Unknown")); ok {
		t.Fatal("AliasForEvent(Unknown) ok = true, want false")
	}
}
