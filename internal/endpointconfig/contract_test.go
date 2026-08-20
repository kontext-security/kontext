package endpointconfig

import (
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/payloadcapture"
)

func TestResponseValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Response)
		wantErr string
	}{
		{name: "valid"},
		{name: "unsupported version", mutate: func(response *Response) { response.ResponseVersion = 1 }, wantErr: "version"},
		{name: "unknown mode", mutate: func(response *Response) { response.Config.PayloadCaptureMode = "unknown" }, wantErr: "mode"},
		{name: "identity mismatch", mutate: func(response *Response) { response.ConfigIdentity = strings.Repeat("f", 64) }, wantErr: "identity"},
		// v2 always emits the guardrail flag. A response without it cannot be
		// identity-checked, since its preimage would differ from the server's.
		{name: "missing guardrail flag", mutate: func(response *Response) { response.Config.GuardrailLLMEnabled = nil }, wantErr: "guardrailLlmEnabled"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := testResponse(t, payloadcapture.ModeSummary)
			if test.mutate != nil {
				test.mutate(&response)
			}
			err := response.Validate()
			if test.wantErr == "" && err != nil {
				t.Fatal(err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("Validate() error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

func TestDecodeStrictRejectsUnknownAndTrailingFields(t *testing.T) {
	response := testResponse(t, payloadcapture.ModeFull)
	valid := `{"responseVersion":2,"config":{"payloadCaptureMode":"full","guardrailLlmEnabled":true},"configIdentity":"` + response.ConfigIdentity + `"}`
	for _, body := range []string{
		strings.TrimSuffix(valid, "}") + `,"policyText":"permit();"}`,
		valid + `{}`,
	} {
		var decoded Response
		if err := decodeStrict(strings.NewReader(body), &decoded); err == nil {
			t.Fatalf("decodeStrict(%q) error = nil", body)
		}
	}
}
