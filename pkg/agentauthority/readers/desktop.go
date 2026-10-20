package readers

import (
	"encoding/json"
	"maps"
	"slices"
)

type Extension struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func DesktopExtension(data []byte) (Extension, error) {
	var e Extension
	err := json.Unmarshal(data, &e)
	return e, err
}

type SessionConnector struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

// ClaudeSession reads only the connector list from a Claude desktop session
// file. The app writes it as an array or as an object keyed by id.
func ClaudeSession(data []byte) ([]SessionConnector, error) {
	var file struct {
		Connectors json.RawMessage `json:"remoteMcpServersConfig"`
	}
	if err := json.Unmarshal(data, &file); err != nil || len(file.Connectors) == 0 {
		return nil, err
	}
	var list []SessionConnector
	if json.Unmarshal(file.Connectors, &list) == nil {
		return list, nil
	}
	var byID map[string]SessionConnector
	if err := json.Unmarshal(file.Connectors, &byID); err != nil {
		return nil, err
	}
	for _, key := range slices.Sorted(maps.Keys(byID)) {
		list = append(list, byID[key])
	}
	return list, nil
}
