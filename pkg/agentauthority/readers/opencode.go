package readers

import "encoding/json"

func OpenCode(data []byte) (PermissionConfig, error) {
	data, err := jsonc(data)
	if err != nil {
		return PermissionConfig{}, err
	}
	var config struct {
		Permission map[string]json.RawMessage `json:"permission"`
	}
	if err = json.Unmarshal(data, &config); err != nil {
		return PermissionConfig{}, err
	}
	raw := config.Permission["bash"]
	var permission *string
	if len(raw) > 0 {
		if err = json.Unmarshal(raw, &permission); err != nil {
			permission = nil
			var rules map[string]json.RawMessage
			if err = json.Unmarshal(raw, &rules); err != nil {
				return PermissionConfig{}, err
			}
			if wildcard := rules["*"]; len(wildcard) > 0 {
				if err = json.Unmarshal(wildcard, &permission); err != nil {
					return PermissionConfig{}, err
				}
			}
		}
	}
	mode := ""
	if permission != nil {
		mode = approvalMode(true, *permission == "allow")
	}
	servers, err := GenericMCP(data, "mcp")
	return PermissionConfig{DefaultMode: mode, MCPServers: servers}, err
}
