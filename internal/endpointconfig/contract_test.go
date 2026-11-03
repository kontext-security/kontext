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
		{name: "previous version", mutate: func(response *Response) { response.ResponseVersion = 3 }, wantErr: "version"},
		// v5 always emits every switch. A response without one cannot be
		// identity-checked, since its preimage would differ from the server's.
		{name: "missing work-type switch", mutate: func(response *Response) { response.Config.WorkTypeClassification = nil }, wantErr: "workTypeClassification"},
		{name: "missing compaction switch", mutate: func(response *Response) { response.Config.ToolOutputCompaction = nil }, wantErr: "toolOutputCompaction"},
		{name: "missing Codex proxy switch", mutate: func(response *Response) { response.Config.CodexProxy = nil }, wantErr: "codexProxy"},
		// The fallback version's identity covers no Codex proxy switch, so a
		// v4 response must not carry one, and a v5 identity never passes for
		// a v4 response.
		{name: "fallback version", mutate: func(response *Response) { *response = fallbackResponse(t, payloadcapture.ModeSummary, true) }},
		{name: "fallback version with the Codex proxy switch", mutate: func(response *Response) {
			*response = fallbackResponse(t, payloadcapture.ModeSummary, true)
			response.Config.CodexProxy = boolPtr(false)
		}, wantErr: "codexProxy"},
		{name: "fallback version with a v5 identity", mutate: func(response *Response) {
			identity := response.ConfigIdentity
			*response = fallbackResponse(t, payloadcapture.ModeSummary, false)
			response.ConfigIdentity = identity
		}, wantErr: "identity"},
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
	valid := `{"responseVersion":5,"config":{"payloadCaptureMode":"full","workTypeClassification":true,"toolOutputCompaction":false,"codexProxy":true},"configIdentity":"` + response.ConfigIdentity + `"}`
	var decoded Response
	if err := decodeStrict(strings.NewReader(valid), &decoded); err != nil || decoded.Validate() != nil {
		t.Fatalf("decodeStrict(valid) = %v, %v", err, decoded.Validate())
	}
	for _, body := range []string{
		strings.TrimSuffix(valid, "}") + `,"policyText":"permit();"}`,
		valid + `{}`,
		// The retired v2 flag is not part of v5.
		`{"responseVersion":5,"config":{"payloadCaptureMode":"full","workTypeClassification":true,"toolOutputCompaction":false,"codexProxy":true,"guardrailLlmEnabled":true},"configIdentity":"` + response.ConfigIdentity + `"}`,
	} {
		var decoded Response
		if err := decodeStrict(strings.NewReader(body), &decoded); err == nil {
			t.Fatalf("decodeStrict(%q) error = nil", body)
		}
	}
}
