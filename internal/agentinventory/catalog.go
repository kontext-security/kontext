// Package agentinventory discovers known agents from directory metadata only.
package agentinventory

type Wired string

const (
	WiredYes         Wired = "yes"
	WiredNo          Wired = "no"
	WiredError       Wired = "error"
	WiredUnsupported Wired = "unsupported"
)

type Agent struct {
	ID             string  `json:"id"`
	ConfigPath     string  `json:"config_path"`
	Wired          Wired   `json:"wired"`
	LastActivityAt *string `json:"last_activity_at"`
}

type Inventory struct {
	Agents     []Agent `json:"agents"`
	ReportedAt string  `json:"agents_reported_at"`
	Incomplete bool    `json:"incomplete,omitempty"`
}

type Descriptor struct {
	ID           string
	Name         string
	ConfigDirs   []string
	ConfigEnv    string
	ActivityRoot string
}

// Catalog has the same ids and order as DISCOVERED_AGENT_IDS in the API.
var Catalog = []Descriptor{
	{"claude_code", "Claude Code", []string{".claude"}, "CLAUDE_CONFIG_DIR", "<config>/projects"},
	{"claude_cowork", "Claude Cowork", []string{"Library/Application Support/Claude/local-agent-mode-sessions"}, "", "<config>"},
	{"codex", "Codex", []string{".codex"}, "CODEX_HOME", "<config>/sessions"},
	{"gemini_cli", "Gemini CLI", []string{".gemini"}, "GEMINI_CLI_HOME", "<config>/tmp"},
	{"cursor", "Cursor", []string{".cursor"}, "", "<config>/projects"},
	{"windsurf", "Windsurf", []string{".windsurf", ".codeium/windsurf"}, "", ".windsurf/transcripts"},
	{"copilot_cli", "GitHub Copilot CLI", []string{".copilot"}, "COPILOT_HOME", "<config>/session-state"},
	{"opencode", "OpenCode", []string{".config/opencode"}, "OPENCODE_CONFIG_DIR", ".local/share/opencode/storage"},
	{"openclaw", "OpenClaw", []string{".openclaw", ".clawdbot"}, "OPENCLAW_STATE_DIR", "<config>/agents"},
	{"pi", "Pi", []string{".pi/agent"}, "PI_CODING_AGENT_DIR", "<config>/sessions"},
	{"kimi_code", "Kimi Code", []string{".kimi-code"}, "KIMI_CODE_HOME", "<config>/sessions"},
	{"qwen_code", "Qwen Code", []string{".qwen"}, "QWEN_HOME", ""},
	{"cline", "Cline", []string{".cline"}, "CLINE_DIR", ""},
	{"amp", "Amp", []string{".config/amp"}, "XDG_CONFIG_HOME", ""},
	{"auggie", "Auggie", []string{".augment"}, "", ""},
	{"kiro", "Kiro", []string{".kiro"}, "KIRO_HOME", ""},
	{"goose", "Goose", []string{".config/goose"}, "XDG_CONFIG_HOME", ""},
	{"kilo", "Kilo Code", []string{".config/kilo"}, "XDG_CONFIG_HOME", ""},
	{"crush", "Crush", []string{".config/crush"}, "CRUSH_GLOBAL_CONFIG", ""},
	{"junie", "Junie", []string{".junie"}, "", ""},
	{"antigravity", "Antigravity", []string{".gemini/antigravity-cli", ".gemini/antigravity"}, "", ""},
	{"factory_droid", "Factory Droid", []string{".factory"}, "", ""},
	{"grok_build", "Grok Build", []string{".grok"}, "GROK_HOME", ""},
	{"devin_cli", "Devin CLI", []string{".config/devin"}, "XDG_CONFIG_HOME", ""},
	{"hermes", "Hermes", []string{".hermes"}, "HERMES_HOME", ""},
}

func DisplayName(id string) string {
	for _, descriptor := range Catalog {
		if descriptor.ID == id {
			return descriptor.Name
		}
	}
	return id
}
