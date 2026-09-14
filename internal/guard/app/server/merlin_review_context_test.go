package server

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestMerlinReviewContextRedactsNestedResponsesBeforeTruncation(t *testing.T) {
	history := `[{"tool":"search_mail","arguments":{"password":"ordinary-value"},"observation":"{\"access_token\":\"other-value\",\"body\":\"Invoice for Alice\"}"}]`
	result := merlinReviewContext("Summarize invoices. token=private-value", history)
	encoded, _ := json.Marshal(result)
	for _, secret := range []string{"ordinary-value", "other-value", "private-value"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("secret retained: %s", secret)
		}
	}
	if !strings.Contains(result.InteractionHistory, "Invoice for Alice") || result.Truncated {
		t.Fatalf("useful evidence lost: %+v", result)
	}
	large := merlinReviewContext(strings.Repeat("世界", 2000), `[{"tool":"search","observation":"`+strings.Repeat("世界", 4000)+`"}]`)
	if !large.Truncated || len(large.UserRequest) > 2000 || len(large.InteractionHistory) > 6000 || !utf8.ValidString(large.UserRequest) || !utf8.ValidString(large.InteractionHistory) {
		t.Fatalf("invalid bounded context: %+v", large)
	}
}

func TestMerlinReviewContextRedactsConnectionCredentialsInPlainErrors(t *testing.T) {
	for _, scheme := range []string{"postgres", "mysql", "redis", "mongodb+srv", "http", "https"} {
		for _, password := range []string{"ordinary-pass%21", "p@ss", "prefix@middle@suffix"} {
			t.Run(scheme+"/"+password, func(t *testing.T) {
				uri := scheme + "://alice:" + password + "@db.example.test/invoices"
				history, err := json.Marshal([]any{map[string]any{"tool": "database_query", "observation": "connection refused: " + uri}})
				if err != nil {
					t.Fatal(err)
				}
				context := merlinReviewContext("Check "+uri, string(history))
				redactedURI := scheme + "://[REDACTED_SECRET]@db.example.test/invoices"
				if scheme == "http" || scheme == "https" {
					// The existing shared HTTP rule also removes the scheme.
					redactedURI = "[REDACTED_SECRET]db.example.test/invoices"
				}
				if context.UserRequest != "Check "+redactedURI {
					t.Fatalf("unexpected request redaction: %s", context.UserRequest)
				}
				var events []map[string]any
				if err := json.Unmarshal([]byte(context.InteractionHistory), &events); err != nil {
					t.Fatal(err)
				}
				if len(events) != 1 || events[0]["observation"] != "connection refused: "+redactedURI {
					t.Fatalf("unexpected observation redaction: %s", context.InteractionHistory)
				}
				if redactMerlinReviewText(context.UserRequest) != context.UserRequest {
					t.Fatal("review redaction is not idempotent")
				}
			})
		}
	}
}

func TestMerlinReviewRedactionPreservesAtSignsOutsideCredentials(t *testing.T) {
	tail := "db.example.test/invoices/contact@example.test?recipient=bob@example.test#owner@team"
	text := "postgres://alice:p@ss@" + tail + " https://bob:a@@b@other.test/path"
	want := "postgres://[REDACTED_SECRET]@" + tail + " [REDACTED_SECRET]other.test/path"
	if got := redactMerlinReviewText(text); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got := redactMerlinReviewText("https://" + tail); got != "https://"+tail {
		t.Fatalf("non-secret URL changed: %s", got)
	}
}

func TestMerlinReviewContextRedactsURLsInDecodedResponsesAndNestedArguments(t *testing.T) {
	uri := "https://alice:p@nested-suffix@db.example.test/invoices"
	response, _ := json.Marshal(map[string]any{"endpoints": []any{uri}})
	history, _ := json.Marshal([]any{map[string]any{
		"arguments":   map[string]any{"endpoints": []any{uri}},
		"observation": string(response),
	}})
	context := merlinReviewContext("Check invoices", string(history))
	if strings.Contains(context.InteractionHistory, "nested-suffix") {
		t.Fatal("password suffix survived nested URL redaction")
	}
	if strings.Count(context.InteractionHistory, "[REDACTED_SECRET]db.example.test/invoices") != 2 {
		t.Fatalf("unexpected nested URL evidence: %s", context.InteractionHistory)
	}
}
