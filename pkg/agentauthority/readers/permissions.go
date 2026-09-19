package readers

// PermissionConfig retains only reportable facts, never rules or settings blobs.
type PermissionConfig struct {
	DefaultMode    string
	MCPServers     map[string]MCP
	PluginStates   map[string]bool
	PluginsDefault bool
}

func approvalMode(present, enabled bool) string {
	if !present {
		return ""
	}
	if enabled {
		return "auto"
	}
	return "default"
}
