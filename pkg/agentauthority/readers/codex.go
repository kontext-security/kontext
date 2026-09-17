package readers

import "github.com/BurntSushi/toml"

type CodexConfig struct {
	MCPServers     map[string]MCP `toml:"mcp_servers"`
	SandboxMode    string         `toml:"sandbox_mode"`
	ApprovalPolicy string         `toml:"approval_policy"`
}

func Codex(data []byte) (CodexConfig, error) {
	var config CodexConfig
	_, err := toml.Decode(string(data), &config)
	return config, err
}
