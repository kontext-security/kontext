package readers

import "encoding/json"

type MCP struct {
	Command string   `json:"command" toml:"command" yaml:"command"`
	Args    []string `json:"args" toml:"args" yaml:"args"`
	URL     string   `json:"url" toml:"url" yaml:"url"`
}

func GenericMCP(data []byte, key string) (map[string]MCP, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	raw := root[key]
	if len(raw) == 0 {
		return nil, nil
	}
	if key == "mcp" {
		var entries map[string]struct {
			Command []string `json:"command"`
			URL     string   `json:"url"`
		}
		if err := json.Unmarshal(raw, &entries); err != nil {
			return nil, err
		}
		result := map[string]MCP{}
		for name, entry := range entries {
			m := MCP{URL: entry.URL}
			if len(entry.Command) > 0 {
				m.Command = entry.Command[0]
				m.Args = entry.Command[1:]
			}
			result[name] = m
		}
		return result, nil
	}
	var entries map[string]struct {
		MCP
		// The legacy key Antigravity still accepts for a remote server.
		ServerURL string `json:"serverUrl"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, err
	}
	if entries == nil {
		return nil, nil
	}
	result := make(map[string]MCP, len(entries))
	for name, entry := range entries {
		if entry.URL == "" {
			entry.URL = entry.ServerURL
		}
		result[name] = entry.MCP
	}
	return result, nil
}
