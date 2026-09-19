package readers

import (
	"fmt"
	"testing"
)

func TestPermissionReaders(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		read                     func([]byte) (PermissionConfig, error)
		on, off, absent, invalid string
	}{
		{"qwen", Qwen, `{"tools":{"approvalMode":"yolo"}}`, `{"tools":{"approvalMode":"default"}}`, `{"general":{"defaultApprovalMode":"auto_edit"}}`, `{"tools":{"approvalMode":true}}`},
		{"openclaw", OpenClaw, `{"tools":{"exec":{"mode":"full"}}}`, `{"tools":{"exec":{"mode":"ask"}}}`, `{"tools":{}}`, `{"tools":{"exec":{"mode":true}}}`},
		{"factory", Factory, `{"sessionDefaultSettings":{"autonomyLevel":"high"}}`, `{"sessionDefaultSettings":{"autonomyLevel":"off"}}`, `{"sessionDefaultSettings":{}}`, `{"sessionDefaultSettings":{"autonomyLevel":true}}`},
		{"auggie", Auggie, `{"toolPermissions":[{"toolName":"*","permission":{"type":"allow"}}]}`, `{"toolPermissions":[]}`, `{"mcpServers":{}}`, `{"toolPermissions":true}`},
		{"crush", Crush, `{"permissions":{"allowed_tools":["bash"]}}`, `{"permissions":{"allowed_tools":[]}}`, `{"permissions":{}}`, `{"permissions":{"allowed_tools":true}}`},
		{"junie", Junie, `{"brave":true}`, `{"brave":false}`, `{"other":true}`, `{"brave":"true"}`},
		{"goose", Goose, "GOOSE_MODE: auto", "GOOSE_MODE: approve", "other: true", "GOOSE_MODE: []"},
		{"hermes", Hermes, "approvals: {mode: off}", "approvals: {mode: manual}", "approvals: {}", "approvals: {mode: []}"},
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

func TestCatalogTOMLPermissions(t *testing.T) {
	for _, tc := range []struct {
		name             string
		read             func([]byte) (PermissionConfig, error)
		on, off, invalid string
	}{
		{"kimi legacy", Kimi, "default_yolo = true", "default_yolo = false", "default_yolo = \"true\""},
		{"kimi", Kimi, `default_permission_mode = "auto"`, `default_permission_mode = "manual"`, `default_permission_mode = true`},
		{"grok", Grok, "[ui]\npermission_mode = \"always-approve\"", "[ui]\npermission_mode = \"ask\"", "[ui]\npermission_mode = true"},
	} {
		for _, input := range []struct {
			data, mode string
			invalid    bool
		}{{tc.on, "auto", false}, {tc.off, "default", false}, {"", "", false}, {tc.invalid, "", true}, {"[", "", true}} {
			result, err := tc.read([]byte(input.data))
			if (err != nil) != input.invalid || !input.invalid && result.DefaultMode != input.mode {
				t.Errorf("%s %q: %+v %v", tc.name, input.data, result, err)
			}
		}
	}
}

func TestCatalogModesAndMCPShapes(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		read                     func([]byte) (PermissionConfig, error)
		data, mode, command, url string
	}{
		{"qwen http", Qwen, `{"tools":{"approvalMode":"auto-edit"},"mcpServers":{"server":{"httpUrl":"https://example.test/mcp"}}}`, "auto", "", "https://example.test/mcp"},
		{"qwen classifier", Qwen, `{"tools":{"approvalMode":"auto"}}`, "default", "", ""},
		{"kimi yolo", Kimi, `default_permission_mode = "yolo"`, "auto", "", ""},
		{"kimi precedence", Kimi, "default_permission_mode = \"manual\"\ndefault_yolo = true", "default", "", ""},
		{"auggie deny first", Auggie, `{"toolPermissions":[{"toolName":"Bash","permission":{"type":"deny"}},{"toolName":"*","permission":{"type":"allow"}}]}`, "default", "", ""},
		{"auggie deny later", Auggie, `{"toolPermissions":[{"toolName":"*","permission":{"type":"allow"}},{"toolName":"Bash","permission":{"type":"deny"}}]}`, "auto", "", ""},
		{"auggie per-tool", Auggie, `{"toolPermissions":[{"toolName":"Bash","permission":{"type":"allow"},"shellInputRegex":"secret"}]}`, "default", "", ""},
		{"auggie mcp", Auggie, `{"mcpServers":{"server":{"command":"npx"}},"toolPermissions":[{"toolName":"*","permission":{"type":"allow"},"shellInputRegex":{}}]}`, "auto", "npx", ""},
		{"crush other tools", Crush, `{"permissions":{"allowed_tools":["read","Bash","*"]}}`, "default", "", ""},
		{"factory top fallback", Factory, `{"autonomyLevel":"auto-high","sessionDefaultSettings":{"autonomyLevel":"off"}}`, "default", "", ""},
		{"factory legacy", Factory, `{"sessionDefaultSettings":{"autonomyMode":"auto-high"}}`, "auto", "", ""},
		{"factory precedence", Factory, `{"sessionDefaultSettings":{"autonomyMode":"auto-high","autonomyLevel":"off"}}`, "default", "", ""},
		{"factory partial", Factory, `{"sessionDefaultSettings":{"autonomyLevel":"medium"}}`, "default", "", ""},
		{"openclaw legacy", OpenClaw, `{"tools":{"exec":{"security":"full","ask":"off"}}}`, "auto", "", ""},
		{"openclaw precedence", OpenClaw, `{"tools":{"exec":{"mode":"ask","security":"full","ask":"off"}}}`, "default", "", ""},
		{"openclaw partial", OpenClaw, `{"tools":{"exec":{"security":"full"}}}`, "default", "", ""},
		{"devin", Devin, `{"mcpServers":{"server":{"command":"npx"}},"permissionMode":"bypass"}`, "", "npx", ""},
		{"crush", Crush, `{"mcp":{"server":{"command":"npx"}},"permissions":{"skip_requests":true}}`, "", "npx", ""},
		{"kilo scalar", OpenCode, `{"permission":"allow","mcp":{"server":{"command":["npx","server"]}}}`, "auto", "npx", ""},
		{"hermes quoted false", Hermes, "approvals: {mode: 'false'}", "default", "", ""},
		{"hermes boolean", Hermes, "approvals: {mode: false}", "auto", "", ""},
		{"hermes normalize", Hermes, "approvals: {mode: ' OFF '}", "auto", "", ""},
		{"goose http", Goose, "extensions: {server: {type: streamable_http, uri: 'https://example.test/mcp'}}", "", "", "https://example.test/mcp"},
		{"goose builtin", Goose, "extensions: {server: {type: builtin, cmd: ignored}}", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := tc.read([]byte(tc.data))
			server := c.MCPServers["server"]
			if err != nil || c.DefaultMode != tc.mode || server.Command != tc.command || server.URL != tc.url {
				t.Fatalf("got %+v server=%+v err=%v", c, server, err)
			}
		})
	}
}

func TestCatalogPluginActivation(t *testing.T) {
	c, err := OpenClaw([]byte(`{"plugins":{"allow":["allowed","denied","disabled"],"deny":["denied"],"entries":{"disabled":{"enabled":false}}}}`))
	if err != nil || c.PluginsDefault || !c.PluginStates["allowed"] || c.PluginStates["denied"] || c.PluginStates["disabled"] {
		t.Fatalf("OpenClaw: %+v %v", c, err)
	}
	c, err = OpenClaw([]byte(`{"plugins":{"enabled":false,"allow":["allowed"]}}`))
	if err != nil || c.PluginsDefault || c.PluginStates["allowed"] {
		t.Fatalf("global disable: %+v %v", c, err)
	}
	c, err = Hermes([]byte("plugins: {enabled: [on, blocked], disabled: [blocked]}"))
	if err != nil || !c.PluginStates["on"] || c.PluginStates["blocked"] {
		t.Fatalf("Hermes: %+v %v", c, err)
	}
	states, err := QwenLegacyPluginStates([]byte(`{"on":{"overrides":["!/*","/*"]},"off":{"overrides":["!/*"]},"project":{"overrides":["!/private/project/*"]}}`))
	if err != nil || !states["on"] || states["off"] || len(states) != 2 {
		t.Fatalf("legacy Qwen: %+v %v", states, err)
	}
	states, err = QwenPluginStates([]byte(`{"extensions":{"id":{"name":"on","defaultActivation":"enabled"},"id2":{"name":"off","defaultActivation":"disabled"}}}`))
	if err != nil || !states["on"] || states["off"] {
		t.Fatalf("Qwen: %+v %v", states, err)
	}
	states, err = PiPluginStates([]byte(`{"packages":["npm:@example/one@1.0.0",{"source":"npm:two@next"},"/external/path"]}`))
	if err != nil || !states["@example/one"] || !states["two"] || len(states) != 2 {
		t.Fatalf("Pi: %+v %v", states, err)
	}
	if name, err := PiManifest([]byte(`{"name":"dependency"}`)); err != nil || name != "" {
		t.Fatal("dependency reported as Pi plugin")
	}
}

func TestCatalogManifestKeys(t *testing.T) {
	data := []byte(`{"id":"openclaw-id","name":"qwen-name"}`)
	name, err := ManifestJSON(data)
	if err != nil || name != "qwen-name" {
		t.Fatalf("Qwen manifest: %s %v", name, err)
	}
	name, err = OpenClawManifest(data)
	if err != nil || name != "openclaw-id" {
		t.Fatalf("OpenClaw manifest: %s %v", name, err)
	}
}

func TestFactoryAutonomyKeys(t *testing.T) {
	for _, shape := range []string{`{"autonomyLevel":%q}`, `{"sessionDefaultSettings":{"autonomyLevel":%q}}`, `{"sessionDefaultSettings":{"autonomyMode":%q}}`} {
		for _, level := range []string{"high", "auto-high", "off", "medium"} {
			c, err := Factory([]byte(fmt.Sprintf(shape, level)))
			want := approvalMode(true, level == "high" || level == "auto-high")
			if err != nil || c.DefaultMode != want {
				t.Fatalf("%s %s: %+v %v", shape, level, c, err)
			}
		}
	}
}
