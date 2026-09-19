package readers

import "encoding/json"

func Gemini(data []byte) (PermissionConfig, error) {
	var config struct {
		General struct {
			DefaultApprovalMode *string `json:"defaultApprovalMode"`
		} `json:"general"`
		MCPServers map[string]MCP `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return PermissionConfig{}, err
	}
	mode := ""
	if config.General.DefaultApprovalMode != nil {
		mode = approvalMode(true, *config.General.DefaultApprovalMode == "auto_edit")
	}
	return PermissionConfig{DefaultMode: mode, MCPServers: config.MCPServers}, nil
}
