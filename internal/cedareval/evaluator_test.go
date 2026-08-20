package cedareval

import (
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/hook"
)

func TestBuildRequest(t *testing.T) {
	t.Parallel()

	request, diagnostics, err := BuildRequest(ToolUseInput{
		EvaluationPrincipal: EvaluationPrincipal{
			EntityType: PrincipalEntityType,
			EntityID:   "alice@example.com",
		},
		ToolName:  "mcp__alias__Tool/With Unicode 🪵",
		ToolInput: map[string]any{"command": "git status"},
	})
	if err != nil {
		t.Fatalf("BuildRequest() error = %v", err)
	}
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %v, want none", diagnostics)
	}
	if got := request.Principal.String(); got != `Kontext::User::"alice@example.com"` {
		t.Errorf("Principal = %s, want exact structured user", got)
	}
	if got := request.Action.String(); got != `Kontext::Action::"ToolUse"` {
		t.Errorf("Action = %s, want ToolUse", got)
	}
	if got := request.Resource.String(); got != `Kontext::Tool::"mcp__alias__Tool/With Unicode 🪵"` {
		t.Errorf("Resource = %s, want exact tool name", got)
	}
}

func TestInputFromEvent(t *testing.T) {
	t.Parallel()

	principal := EvaluationPrincipal{EntityType: PrincipalEntityType, EntityID: "alice@example.com"}
	event := hook.Event{
		Agent:     "claude",
		HookName:  hook.HookPreToolUse,
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "git status"},
		CWD:       "/private/project",
	}
	input, err := InputFromEvent(principal, event)
	if err != nil {
		t.Fatalf("InputFromEvent() error = %v", err)
	}
	want := ToolUseInput{
		EvaluationPrincipal: principal,
		ToolName:            "Bash",
		ToolInput:           map[string]any{"command": "git status"},
	}
	if !reflect.DeepEqual(input, want) {
		t.Fatalf("InputFromEvent() = %#v, want %#v", input, want)
	}

	_, err = InputFromEvent(principal, hook.Event{HookName: hook.HookPostToolUse})
	if err == nil {
		t.Fatal("InputFromEvent() error = nil, want non-pre-use rejection")
	}
}

func TestConvertToolInputLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		input        map[string]any
		expectedCode string
	}{
		{
			name:         "maximum depth",
			input:        nestedInput(ContextMaxDepth + 1),
			expectedCode: "maximum_depth_exceeded",
		},
		{
			name:         "maximum values",
			input:        wideInput(ContextMaxValues),
			expectedCode: "maximum_values_exceeded",
		},
		{
			name:         "invalid value",
			input:        map[string]any{"channel": make(chan struct{})},
			expectedCode: "invalid_json_value",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := ConvertToolInput(tt.input)
			var conversionError *ConversionError
			if !errors.As(err, &conversionError) {
				t.Fatalf("ConvertToolInput() error = %v, want ConversionError", err)
			}
			if conversionError.Code != tt.expectedCode {
				t.Fatalf("ConversionError.Code = %q, want %q", conversionError.Code, tt.expectedCode)
			}
		})
	}
}

func TestConvertToolInputSortsDiagnosticsByJSONPointer(t *testing.T) {
	t.Parallel()

	_, diagnostics, err := ConvertToolInput(map[string]any{
		"z": nil,
		"a": map[string]any{
			"~key/part": nil,
		},
	})
	if err != nil {
		t.Fatalf("ConvertToolInput() error = %v", err)
	}
	want := []ContextDiagnostic{
		{Code: "null_omitted", Path: "/a/~0key~1part"},
		{Code: "null_omitted", Path: "/z"},
	}
	if !reflect.DeepEqual(diagnostics, want) {
		t.Fatalf("diagnostics = %v, want %v", diagnostics, want)
	}
}

func TestConvertToolInputNumericRepresentations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value any
	}{
		{name: "json integer", value: json.Number("42")},
		{name: "json exponent integer", value: json.Number("1e3")},
		{name: "go integer", value: int64(42)},
		{name: "go unsigned integer", value: uint64(42)},
		{name: "float integer", value: float64(42)},
		{name: "json decimal", value: json.Number("1.25")},
		{name: "json long-tail binary64 decimal", value: json.Number("0.00010000000000000001")},
		{name: "json exponent decimal", value: json.Number("1e-4")},
		{name: "float decimal", value: 1.25},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := ConvertToolInput(map[string]any{"value": tt.value})
			if err != nil {
				t.Fatalf("ConvertToolInput() error = %v", err)
			}
		})
	}
}

func TestECMAFixed4UsesJavaScriptTieBreaking(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		value      float64
		wantFixed  string
		wantScaled int64
	}{
		{
			name:       "positive exact halfway",
			value:      549755813888.03125,
			wantFixed:  "549755813888.0313",
			wantScaled: 5497558138880313,
		},
		{
			name:       "negative exact halfway",
			value:      -549755813888.03125,
			wantFixed:  "-549755813888.0313",
			wantScaled: -5497558138880313,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fixed, scaled, ok := ecmaFixed4(tt.value)
			if !ok {
				t.Fatal("ecmaFixed4() ok = false, want true")
			}
			if fixed != tt.wantFixed || scaled != tt.wantScaled {
				t.Fatalf("ecmaFixed4() = (%q, %d), want (%q, %d)", fixed, scaled, tt.wantFixed, tt.wantScaled)
			}
			if _, _, err := ConvertToolInput(map[string]any{"value": tt.value}); err != nil {
				t.Fatalf("ConvertToolInput() error = %v", err)
			}
		})
	}
}

func TestBuildRequestRejectsInvalidUTF8Identifiers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		principal string
		toolName  string
	}{
		{name: "principal", principal: string([]byte{0xff}), toolName: "Bash"},
		{name: "tool", principal: "alice@example.com", toolName: string([]byte{0xff})},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := BuildRequest(ToolUseInput{
				EvaluationPrincipal: EvaluationPrincipal{
					EntityType: PrincipalEntityType,
					EntityID:   tt.principal,
				},
				ToolName:  tt.toolName,
				ToolInput: map[string]any{},
			})
			if err == nil || !strings.Contains(err.Error(), "valid UTF-8") {
				t.Fatalf("BuildRequest() error = %v, want valid UTF-8 rejection", err)
			}
		})
	}
}

func TestEvaluatorPreservesEngineDiagnostics(t *testing.T) {
	t.Parallel()

	evaluator, err := New(`@id("unguarded")
permit(principal, action, resource) when { context.command == "git status" };`)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	result, err := evaluator.Evaluate(ToolUseInput{
		EvaluationPrincipal: EvaluationPrincipal{
			EntityType: PrincipalEntityType,
			EntityID:   "alice@example.com",
		},
		ToolName:  "Bash",
		ToolInput: map[string]any{},
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if result.Decision != DecisionDeny {
		t.Fatalf("Decision = %q, want deny", result.Decision)
	}
	if len(result.EngineDiagnostics.Errors) != 1 {
		t.Fatalf("EngineDiagnostics.Errors = %v, want one error", result.EngineDiagnostics.Errors)
	}
}

func TestNewRejectsInvalidPolicyMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		policyText string
		wantError  string
	}{
		{
			name:       "missing id",
			policyText: `permit(principal, action, resource);`,
			wantError:  "no non-empty @id annotation",
		},
		{
			name:       "empty id",
			policyText: `@id("") permit(principal, action, resource);`,
			wantError:  "no non-empty @id annotation",
		},
		{
			name: "duplicate id",
			policyText: `@id("duplicate") permit(principal, action, resource);
@id("duplicate") forbid(principal, action, resource);`,
			wantError: "duplicate @id",
		},
		{
			name:       "unsupported ask",
			policyText: `@id("bad_ask") @ask("true") permit(principal, action, resource);`,
			wantError:  "unsupported @ask value",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := New(tt.policyText)
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("New() error = %v, want %q", err, tt.wantError)
			}
		})
	}
}

func TestNewRejectsInvalidPolicyDocuments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		policyText string
	}{
		{name: "invalid", policyText: "permit("},
		{name: "too large", policyText: strings.Repeat("x", PolicyMaxBytes+1)},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(tt.policyText); err == nil {
				t.Fatal("New() error = nil, want rejection")
			}
		})
	}
}

func TestEmptyPolicySetDefaultsToDeny(t *testing.T) {
	t.Parallel()

	evaluator, err := New("")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	result, err := evaluator.Evaluate(ToolUseInput{
		EvaluationPrincipal: EvaluationPrincipal{
			EntityType: PrincipalEntityType,
			EntityID:   "alice@example.com",
		},
		ToolName:  "Read",
		ToolInput: map[string]any{},
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if result.Decision != DecisionDeny || result.Ask {
		t.Fatalf("result = %#v, want default deny without ask", result)
	}
}

func TestBuildRequestRejectsNilToolInput(t *testing.T) {
	t.Parallel()

	_, _, err := BuildRequest(ToolUseInput{
		EvaluationPrincipal: EvaluationPrincipal{
			EntityType: PrincipalEntityType,
			EntityID:   "alice@example.com",
		},
		ToolName: "Read",
	})
	if err == nil || !strings.Contains(err.Error(), "JSON object") {
		t.Fatalf("BuildRequest() error = %v, want JSON object rejection", err)
	}
}

func nestedInput(depth int) map[string]any {
	root := map[string]any{}
	current := root
	for range depth {
		next := map[string]any{}
		current["next"] = next
		current = next
	}
	return root
}

func wideInput(values int) map[string]any {
	input := make(map[string]any, values)
	for i := range values {
		input[strconv.Itoa(i)] = true
	}
	return input
}
