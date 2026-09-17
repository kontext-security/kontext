package readers

import "encoding/json"

type ClaudeRoot struct {
	MCPServers map[string]MCP `json:"mcpServers"`
	Projects   map[string]struct {
		MCPServers            map[string]MCP `json:"mcpServers"`
		EnabledMcpjsonServers []string       `json:"enabledMcpjsonServers"`
	} `json:"projects"`
}
type ClaudeSettings struct {
	Permissions struct {
		DefaultMode *string  `json:"defaultMode"`
		Allow       []string `json:"allow"`
		Deny        []string `json:"deny"`
	} `json:"permissions"`
	Sandbox struct {
		Enabled          *bool `json:"enabled"`
		AllowUnsandboxed *bool `json:"allowUnsandboxedCommands"`
		Network          struct {
			AllowedDomains []string `json:"allowedDomains"`
		} `json:"network"`
	} `json:"sandbox"`
	EnabledPlugins map[string]bool `json:"enabledPlugins"`
}

func Claude(data []byte) (ClaudeRoot, error) {
	var c ClaudeRoot
	err := json.Unmarshal(data, &c)
	return c, err
}
func Settings(data []byte) (ClaudeSettings, error) {
	var c ClaudeSettings
	err := json.Unmarshal(data, &c)
	return c, err
}
