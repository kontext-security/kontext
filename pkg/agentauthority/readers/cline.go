package readers

import "encoding/json"

func Cline(data []byte) (PermissionConfig, error) {
	var config struct {
		AutoApprovalSettings struct {
			Actions struct {
				ExecuteAllCommands *bool `json:"executeAllCommands"`
			} `json:"actions"`
		} `json:"autoApprovalSettings"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return PermissionConfig{}, err
	}
	enabled := config.AutoApprovalSettings.Actions.ExecuteAllCommands
	return PermissionConfig{DefaultMode: approvalMode(enabled != nil, enabled != nil && *enabled)}, nil
}
