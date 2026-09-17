// Package agentauthority reads bounded local agent configuration without contacting services.
package agentauthority

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/gowebpki/jcs"
)

type AgentLocation struct{ ID, ConfigPath string }
type Report struct {
	SchemaVersion string       `json:"schema_version"`
	ScannedAt     string       `json:"scanned_at"`
	Hash          string       `json:"hash"`
	Agents        []Agent      `json:"agents"`
	Environment   Environment  `json:"environment"`
	Credentials   []Credential `json:"credentials"`
	Coverage      Coverage     `json:"coverage"`
	Truncated     bool         `json:"truncated"`
}
type Agent struct {
	ID          string      `json:"id"`
	MCPServers  []MCPServer `json:"mcp_servers"`
	Plugins     []Plugin    `json:"plugins"`
	Skills      []Skill     `json:"skills"`
	Hooks       []Hook      `json:"hooks"`
	Subagents   []Subagent  `json:"subagents"`
	Permissions Permissions `json:"permissions"`
}
type MCPServer struct {
	Name      string   `json:"name"`
	Transport string   `json:"transport"`
	Command   *string  `json:"command"`
	Args      []string `json:"args"`
	URLHost   *string  `json:"url_host"`
	Source    string   `json:"source"`
	Scope     string   `json:"scope"`
	Project   *string  `json:"project"`
}
type Plugin struct {
	Name        string  `json:"name"`
	Marketplace *string `json:"marketplace"`
	Enabled     bool    `json:"enabled"`
	MCPServers  int     `json:"mcp_servers"`
	Skills      int     `json:"skills"`
	Hooks       int     `json:"hooks"`
	Subagents   int     `json:"subagents"`
}
type Skill struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}
type Hook struct {
	Event   string `json:"event"`
	Command string `json:"command"`
	Source  string `json:"source"`
}
type Subagent struct {
	Name          string `json:"name"`
	ToolsWildcard bool   `json:"tools_wildcard"`
}
type Grant struct {
	Pattern string `json:"pattern"`
	Risk    string `json:"risk"`
}
type Permissions struct {
	DefaultMode *string           `json:"default_mode"`
	Allow       []Grant           `json:"allow"`
	DenyCount   int               `json:"deny_count"`
	Sandbox     Sandbox           `json:"sandbox"`
	Codex       *CodexPermissions `json:"codex"`
}
type Sandbox struct {
	Enabled          *bool `json:"enabled"`
	AllowUnsandboxed *bool `json:"allow_unsandboxed"`
	AllowedDomains   int   `json:"allowed_domains"`
}
type CodexPermissions struct {
	SandboxMode    *string `json:"sandbox_mode"`
	ApprovalPolicy *string `json:"approval_policy"`
}
type Environment struct {
	UID       int  `json:"uid"`
	Root      bool `json:"root"`
	Admin     bool `json:"admin"`
	Container bool `json:"container"`
}
type Credential struct {
	Kind       string  `json:"kind"`
	Path       string  `json:"path"`
	Present    bool    `json:"present"`
	ModifiedAt *string `json:"modified_at"`
	Detail     int     `json:"detail"`
	Host       *string `json:"host"`
	Login      *string `json:"login"`
}
type Coverage struct {
	UnknownFormat []string `json:"unknown_format"`
	Errors        []string `json:"errors"`
	SkippedFiles  int      `json:"skipped_files"`
}

func (r Report) CanonicalJSON() ([]byte, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(data)
}

// ContentHash excludes both the scan clock and the hash itself.
func (r Report) ContentHash() (string, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(data, &fields); err != nil {
		return "", err
	}
	delete(fields, "hash")
	delete(fields, "scanned_at")
	data, err = json.Marshal(fields)
	if err != nil {
		return "", err
	}
	data, err = jcs.Transform(data)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
