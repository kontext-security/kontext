package readers

import "encoding/json"

func Windsurf(data []byte) (PermissionConfig, error) {
	var config struct {
		Policy *string `json:"windsurf.autoExecutionPolicy"`
	}
	data, err := jsonc(data)
	if err != nil {
		return PermissionConfig{}, err
	}
	if err = json.Unmarshal(data, &config); err != nil {
		return PermissionConfig{}, err
	}
	mode := ""
	if config.Policy != nil {
		mode = approvalMode(true, *config.Policy == "auto" || *config.Policy == "turbo")
	}
	return PermissionConfig{DefaultMode: mode}, nil
}
