package readers

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

// These readers describe persisted defaults, not effective session policy.
// Sources and intentional gaps are recorded in docs/authority-catalog-readers.md.
func decodeJSONC(data []byte, value any) error {
	clean, err := jsonc(data)
	if err != nil {
		return err
	}
	return json.Unmarshal(clean, value)
}

func Qwen(data []byte) (PermissionConfig, error) {
	var c struct {
		Tools struct {
			ApprovalMode *string `json:"approvalMode"`
		} `json:"tools"`
		MCPServers map[string]struct {
			MCP
			HTTPURL string `json:"httpUrl"`
		} `json:"mcpServers"`
	}
	err := decodeJSONC(data, &c)
	mode := ""
	if c.Tools.ApprovalMode != nil {
		mode = approvalMode(true, *c.Tools.ApprovalMode == "yolo" || *c.Tools.ApprovalMode == "auto-edit")
	}
	servers := map[string]MCP{}
	for name, server := range c.MCPServers {
		m := server.MCP
		if server.HTTPURL != "" {
			m.URL = server.HTTPURL
		}
		servers[name] = m
	}
	return PermissionConfig{DefaultMode: mode, MCPServers: servers}, err
}

func OpenClaw(data []byte) (PermissionConfig, error) {
	var c struct {
		Plugins struct {
			Enabled *bool    `json:"enabled"`
			Allow   []string `json:"allow"`
			Deny    []string `json:"deny"`
			Entries map[string]struct {
				Enabled *bool `json:"enabled"`
			} `json:"entries"`
		} `json:"plugins"`
		Tools struct {
			Exec struct {
				Mode     *string `json:"mode"`
				Security *string `json:"security"`
				Ask      *string `json:"ask"`
			} `json:"exec"`
		} `json:"tools"`
		MCP struct {
			Servers map[string]MCP `json:"servers"`
		} `json:"mcp"`
	}
	err := decodeJSONC(data, &c)
	mode := ""
	if e := c.Tools.Exec; e.Mode != nil {
		mode = approvalMode(true, *e.Mode == "full")
	} else if e.Security != nil || e.Ask != nil {
		mode = approvalMode(true, e.Security != nil && *e.Security == "full" && e.Ask != nil && *e.Ask == "off")
	}
	active := c.Plugins.Enabled == nil || *c.Plugins.Enabled
	states := map[string]bool{}
	for _, name := range c.Plugins.Allow {
		states[name] = active
	}
	for name, entry := range c.Plugins.Entries {
		if entry.Enabled != nil && !*entry.Enabled {
			states[name] = false
		}
	}
	for _, name := range c.Plugins.Deny {
		states[name] = false
	}
	return PermissionConfig{DefaultMode: mode, MCPServers: c.MCP.Servers, PluginStates: states, PluginsDefault: active && len(c.Plugins.Allow) == 0}, err
}

func Goose(data []byte) (PermissionConfig, error) {
	var c struct {
		Mode       *string `yaml:"GOOSE_MODE"`
		Extensions map[string]struct {
			Type    string   `yaml:"type"`
			Command string   `yaml:"cmd"`
			Args    []string `yaml:"args"`
			URI     string   `yaml:"uri"`
		} `yaml:"extensions"`
	}
	err := yaml.Unmarshal(data, &c)
	servers := map[string]MCP{}
	for name, e := range c.Extensions {
		switch e.Type {
		case "stdio":
			servers[name] = MCP{Command: e.Command, Args: e.Args}
		case "sse", "streamable_http":
			servers[name] = MCP{URL: e.URI}
		}
	}
	mode := ""
	if c.Mode != nil {
		mode = approvalMode(true, *c.Mode == "auto")
	}
	return PermissionConfig{DefaultMode: mode, MCPServers: servers}, err
}

func Factory(data []byte) (PermissionConfig, error) {
	var c struct {
		Level   *string `json:"autonomyLevel"`
		Session struct {
			Level  *string `json:"autonomyLevel"`
			Legacy *string `json:"autonomyMode"`
		} `json:"sessionDefaultSettings"`
	}
	err := json.Unmarshal(data, &c)
	mode := ""
	for _, level := range []*string{c.Session.Level, c.Session.Legacy, c.Level} {
		if level != nil {
			mode = approvalMode(true, *level == "high" || *level == "auto-high")
			break
		}
	}
	return PermissionConfig{DefaultMode: mode}, err
}

// Devin documents runtime permission modes, but no persisted default-mode key.
func Devin(data []byte) (PermissionConfig, error) {
	var c struct {
		MCPServers map[string]MCP `json:"mcpServers"`
	}
	err := decodeJSONC(data, &c)
	return PermissionConfig{MCPServers: c.MCPServers}, err
}

func Junie(data []byte) (PermissionConfig, error) {
	var c struct {
		Brave *bool `json:"brave"`
	}
	err := json.Unmarshal(data, &c)
	mode := ""
	if c.Brave != nil {
		mode = approvalMode(true, *c.Brave)
	}
	return PermissionConfig{DefaultMode: mode}, err
}

func Kimi(data []byte) (PermissionConfig, error) {
	var c struct {
		Mode *string `toml:"default_permission_mode"`
		Yolo *bool   `toml:"default_yolo"`
	}
	_, err := toml.Decode(string(data), &c)
	mode := ""
	if c.Mode != nil {
		mode = approvalMode(true, *c.Mode == "auto" || *c.Mode == "yolo")
	} else if c.Yolo != nil {
		mode = approvalMode(true, *c.Yolo)
	}
	return PermissionConfig{DefaultMode: mode}, err
}

func Grok(data []byte) (PermissionConfig, error) {
	var c struct {
		UI struct {
			Mode *string `toml:"permission_mode"`
		} `toml:"ui"`
		MCPServers map[string]MCP `toml:"mcp_servers"`
	}
	_, err := toml.Decode(string(data), &c)
	mode := ""
	if c.UI.Mode != nil {
		mode = approvalMode(true, *c.UI.Mode == "always-approve")
	}
	return PermissionConfig{DefaultMode: mode, MCPServers: c.MCPServers}, err
}

func Hermes(data []byte) (PermissionConfig, error) {
	var c struct {
		Plugins struct {
			Enabled  []string `yaml:"enabled"`
			Disabled []string `yaml:"disabled"`
		} `yaml:"plugins"`
		Approvals struct {
			Mode yaml.Node `yaml:"mode"`
		} `yaml:"approvals"`
		MCPServers map[string]MCP `yaml:"mcp_servers"`
	}
	err := yaml.Unmarshal(data, &c)
	mode := ""
	if node := c.Approvals.Mode; node.Kind != 0 && node.Tag != "!!null" {
		if node.Kind != yaml.ScalarNode || node.Tag != "!!str" && node.Tag != "!!bool" {
			return PermissionConfig{}, errors.New("invalid approval mode")
		}
		mode = approvalMode(true, node.Tag == "!!bool" && node.Value == "false" || node.Tag == "!!str" && strings.EqualFold(strings.TrimSpace(node.Value), "off"))
	}
	states := map[string]bool{}
	for _, name := range c.Plugins.Enabled {
		states[name] = true
	}
	for _, name := range c.Plugins.Disabled {
		states[name] = false
	}
	return PermissionConfig{DefaultMode: mode, MCPServers: c.MCPServers, PluginStates: states}, err
}

func Auggie(data []byte) (PermissionConfig, error) {
	var c struct {
		MCPServers      map[string]MCP `json:"mcpServers"`
		ToolPermissions *[]struct {
			ToolName   string `json:"toolName"`
			Permission struct {
				Type string `json:"type"`
			} `json:"permission"`
		} `json:"toolPermissions"`
	}
	err := json.Unmarshal(data, &c)
	mode := ""
	if c.ToolPermissions != nil {
		mode = "default"
		for _, rule := range *c.ToolPermissions {
			if rule.Permission.Type == "deny" {
				break
			}
			if rule.ToolName == "*" && rule.Permission.Type == "allow" {
				mode = "auto"
				break
			}
		}
	}
	return PermissionConfig{DefaultMode: mode, MCPServers: c.MCPServers}, err
}

// Crush's mcp command is a string, unlike OpenCode's array.
func Crush(data []byte) (PermissionConfig, error) {
	var c struct {
		MCPServers  map[string]MCP `json:"mcp"`
		Permissions struct {
			AllowedTools *[]string `json:"allowed_tools"`
		} `json:"permissions"`
	}
	err := decodeJSONC(data, &c)
	mode := ""
	if c.Permissions.AllowedTools != nil {
		mode = approvalMode(true, slices.Contains(*c.Permissions.AllowedTools, "bash"))
	}
	return PermissionConfig{DefaultMode: mode, MCPServers: c.MCPServers}, err
}

func ManifestJSON(data []byte) (string, error) {
	var c struct {
		Name string `json:"name"`
	}
	err := json.Unmarshal(data, &c)
	return c.Name, err
}
func OpenClawManifest(data []byte) (string, error) {
	var c struct {
		ID string `json:"id"`
	}
	err := json.Unmarshal(data, &c)
	return c.ID, err
}
func ManifestYAML(data []byte) (string, error) {
	var c struct {
		Name string `yaml:"name"`
	}
	err := yaml.Unmarshal(data, &c)
	return c.Name, err
}
func QwenPluginStates(data []byte) (map[string]bool, error) {
	var c struct {
		Extensions map[string]struct {
			Name       string `json:"name"`
			Activation string `json:"defaultActivation"`
		} `json:"extensions"`
	}
	err := json.Unmarshal(data, &c)
	states := map[string]bool{}
	for _, e := range c.Extensions {
		states[e.Name] = e.Activation == "enabled"
	}
	return states, err
}
func QwenLegacyPluginStates(data []byte) (map[string]bool, error) {
	var c map[string]struct {
		Overrides []string `json:"overrides"`
	}
	err := json.Unmarshal(data, &c)
	states := map[string]bool{}
	for name, e := range c {
		for _, rule := range e.Overrides {
			if rule == "/*" || rule == "!/*" {
				states[name] = rule == "/*"
			}
		}
	}
	return states, err
}
func PiPluginStates(data []byte) (map[string]bool, error) {
	var c struct {
		Packages []json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	states := map[string]bool{}
	for _, raw := range c.Packages {
		var source string
		if err := json.Unmarshal(raw, &source); err != nil {
			var entry struct {
				Source string `json:"source"`
			}
			if err := json.Unmarshal(raw, &entry); err != nil {
				return nil, err
			}
			source = entry.Source
		}
		if !strings.HasPrefix(source, "npm:") {
			continue
		}
		name := strings.TrimPrefix(source, "npm:")
		if i := strings.LastIndex(name, "@"); i > 0 {
			name = name[:i]
		}
		states[name] = true
	}
	return states, nil
}

func PiManifest(data []byte) (string, error) {
	var c struct {
		Name string          `json:"name"`
		Pi   json.RawMessage `json:"pi"`
	}
	err := json.Unmarshal(data, &c)
	if len(c.Pi) == 0 || string(c.Pi) == "null" {
		return "", err
	}
	return c.Name, err
}
