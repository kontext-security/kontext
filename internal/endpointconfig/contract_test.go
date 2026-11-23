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
		// v7 always emits every switch. A response without one cannot be
		// identity-checked, since its preimage would differ from the server's.
		{name: "missing work-type switch", mutate: func(response *Response) { response.Config.WorkTypeClassification = nil }, wantErr: "workTypeClassification"},
		{name: "missing compaction switch", mutate: func(response *Response) { response.Config.ToolOutputCompaction = nil }, wantErr: "toolOutputCompaction"},
		{name: "missing Codex proxy switch", mutate: func(response *Response) { response.Config.CodexProxy = nil }, wantErr: "codexProxy"},
		{name: "missing hook inventory switch", mutate: func(response *Response) { response.Config.HookInventory = nil }, wantErr: "hookInventory"},
		{name: "missing hook state", mutate: func(response *Response) { response.Config.HookState = nil }, wantErr: "hookState"},
		{name: "v5 is no longer read", mutate: func(response *Response) { response.ResponseVersion = 5 }, wantErr: "version"},
		// There is no removed: the cloud refuses it, and so does this side.
		{name: "removed is not a state", mutate: func(response *Response) { response.Config.HookState.Desired = "removed" }, wantErr: "desired hook state"},
		{name: "negative generation", mutate: func(response *Response) { response.Config.HookState.Generation = -1 }, wantErr: "generation"},
		{name: "generation past what a double holds", mutate: func(response *Response) { response.Config.HookState.Generation = 1 << 53 }, wantErr: "generation"},
		{name: "short repair nonce", mutate: func(response *Response) { nonce := "short"; response.Config.HookState.RepairNonce = &nonce }, wantErr: "nonce"},
		// The fallback version's identity covers no hook state, so a v6
		// response must not carry one, and a v7 identity never passes for a
		// v6 response.
		{name: "fallback version", mutate: func(response *Response) { *response = fallbackResponse(t, payloadcapture.ModeSummary, true) }},
		{name: "fallback version with a hook state", mutate: func(response *Response) {
			*response = fallbackResponse(t, payloadcapture.ModeSummary, true)
			state := UnmanagedHookState
			response.Config.HookState = &state
		}, wantErr: "hookState"},
		{name: "fallback version with a v7 identity", mutate: func(response *Response) {
			identity := response.ConfigIdentity
			*response = fallbackResponse(t, payloadcapture.ModeSummary, false)
			response.ConfigIdentity = identity
		}, wantErr: "identity"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := testResponse(t, payloadcapture.ModeSummary)
			// Each case mutates its own copy of the hook state.
			state := *response.Config.HookState
			response.Config.HookState = &state
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
	valid := `{"responseVersion":7,"config":{"payloadCaptureMode":"full","workTypeClassification":true,"toolOutputCompaction":false,"codexProxy":true,"hookInventory":false,"hookState":{"desired":"unmanaged","generation":0,"repairNonce":null}},"configIdentity":"` + response.ConfigIdentity + `"}`
	var decoded Response
	if err := decodeStrict(strings.NewReader(valid), &decoded); err != nil || decoded.Validate() != nil {
		t.Fatalf("decodeStrict(valid) = %v, %v", err, decoded.Validate())
	}
	for _, body := range []string{
		strings.TrimSuffix(valid, "}") + `,"policyText":"permit();"}`,
		valid + `{}`,
		// The retired v2 flag is not part of v7.
		strings.Replace(valid, `"hookInventory":false,`, `"hookInventory":false,"guardrailLlmEnabled":true,`, 1),
		// Every hook state key is required, spelled exactly, and alone.
		strings.Replace(valid, `,"repairNonce":null`, ``, 1),
		strings.Replace(valid, `"desired":`, `"Desired":`, 1),
		strings.Replace(valid, `"repairNonce":null`, `"repairNonce":null,"removeAt":null`, 1),
		strings.Replace(valid, `{"desired":"unmanaged","generation":0,"repairNonce":null}`, `null`, 1),
		// Only the nonce may be null; a null generation would read as 0.
		strings.Replace(valid, `"generation":0`, `"generation":null`, 1),
		strings.Replace(valid, `"desired":"unmanaged"`, `"desired":null`, 1),
	} {
		// Refused on decode, or (a null hook state) on validation.
		var decoded Response
		if err := decodeStrict(strings.NewReader(body), &decoded); err == nil && decoded.Validate() == nil {
			t.Fatalf("decodeStrict(%q) and Validate() accepted it", body)
		}
	}
}
