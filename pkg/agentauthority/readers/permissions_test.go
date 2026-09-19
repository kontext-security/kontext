package readers

import "testing"

func TestPermissionReaders(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		read                     func([]byte) (PermissionConfig, error)
		on, off, absent, invalid string
	}{
		{"windsurf", Windsurf, `{"windsurf.autoExecutionPolicy":"auto"}`, `{"windsurf.autoExecutionPolicy":"off"}`, `{"other":true}`, `{"windsurf.autoExecutionPolicy":true}`},
		{"gemini", Gemini, `{"general":{"defaultApprovalMode":"auto_edit"}}`, `{"general":{"defaultApprovalMode":"plan"}}`, `{"general":{}}`, `{"general":{"defaultApprovalMode":true}}`},
		{"cline", Cline, `{"autoApprovalSettings":{"actions":{"executeAllCommands":true}}}`, `{"autoApprovalSettings":{"actions":{"executeAllCommands":false,"executeSafeCommands":true,"editFiles":true}}}`, `{"autoApprovalSettings":{"actions":{"editFiles":true}}}`, `{"autoApprovalSettings":{"actions":{"executeAllCommands":"true"}}}`},
		{"opencode", OpenCode, `{"permission":{"bash":"allow"}}`, `{"permission":{"bash":{"*":"ask","git *":"allow"}}}`, `{"permission":{"bash":{"git *":"allow"},"edit":"allow"}}`, `{"permission":{"bash":{"*":true}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, input := range []struct {
				data, mode string
				invalid    bool
			}{
				{tc.on, "auto", false}, {tc.off, "default", false}, {tc.absent, "", false}, {`{}`, "", false}, {tc.invalid, "", true}, {`{`, "", true},
			} {
				result, err := tc.read([]byte(input.data))
				if (err != nil) != input.invalid || !input.invalid && result.DefaultMode != input.mode {
					t.Errorf("input %s: mode=%q err=%v", input.data, result.DefaultMode, err)
				}
			}
		})
	}
}

func TestJSONCSettings(t *testing.T) {
	for _, data := range []string{
		"{ // comment\n \"permission\": {\"bash\": \"allow\",},}",
		`{"permission":/* comment */{"bash":{"*":"allow",},},"unrelated":"https://example.test/*a*/\\\"//",}`,
	} {
		c, err := OpenCode([]byte(data))
		if err != nil || c.DefaultMode != "auto" {
			t.Fatalf("JSONC: %+v %v", c, err)
		}
	}
	for _, data := range []string{`{/* missing end`, `{"permission":{"bash":"allow"},,}`, `{"unused":[,],"permission":{"bash":"allow"}}`} {
		if _, err := OpenCode([]byte(data)); err == nil {
			t.Fatalf("accepted invalid JSONC %s", data)
		}
	}
}
