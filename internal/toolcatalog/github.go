package toolcatalog

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"
	"strings"

	"github.com/kontext-security/kontext/internal/cedareval"
)

const (
	// GitHubMCPPrefix is the namespace Claude Code gives the GitHub MCP server
	// under its default name. Operators rename servers, so resolution does not
	// depend on it; see Resolve.
	GitHubMCPPrefix        = "mcp__github__"
	mcpPrefix              = "mcp__"
	mcpSeparator           = "__"
	GitHubToolPrefix       = "github-mcp/"
	GitHubUnrecognizedTool = GitHubToolPrefix + "unrecognized"
	GitHubMCPSourceCommit  = "febc3293a4feb70e62399f39a26b082f78b9b176"
	githubMCPSource        = "github/github-mcp-server@" + GitHubMCPSourceCommit
)

//go:embed github-mcp.json
var githubCatalogJSON []byte

type githubCatalog struct {
	Source string       `json:"source"`
	Tools  []githubTool `json:"tools"`
}

type githubTool struct {
	Name       string            `json:"name"`
	ReadOnly   bool              `json:"readOnly"`
	Required   []string          `json:"required"`
	Properties map[string]string `json:"properties"`
}

var githubTools = loadGitHubTools()

func Digest() string {
	github := sha256.Sum256([]byte("github-mcp:" + GitHubMCPSourceCommit))
	toolIDs := []string{cedareval.ToolShellV2, cedareval.ToolUnknownV2}
	sort.Strings(toolIDs)
	base, _ := json.Marshal(toolIDs)
	combined := sha256.Sum256([]byte(
		"kontext:cedar-tool-catalog:v1\x00" + string(base) + "\x00" + hex.EncodeToString(github[:]),
	))
	return hex.EncodeToString(combined[:])
}

// Known reports whether toolID is one the daemon can produce for a GitHub
// MCP call: a catalogued tool under the github-mcp/ prefix, or the
// unrecognized fallback. A policy naming any other github-mcp/ id never
// matches.
func Known(toolID string) bool {
	if toolID == GitHubUnrecognizedTool {
		return true
	}
	name, ok := strings.CutPrefix(toolID, GitHubToolPrefix)
	if !ok {
		return false
	}
	_, ok = githubTools[name]
	return ok
}

// Resolve maps an MCP tool call to the pinned GitHub catalog. The server
// name is whatever the operator registered it as, so a catalogued tool name
// is recognised under any mcp__<server>__ prefix and held to its pinned
// input schema: input that no longer matches (a missing required field, a
// wrong type) resolves to the unrecognized GitHub tool, fail-closed, whatever
// the server is called. The one exception is a same-named tool on another
// product whose input carries a field GitHub's schema does not have at all
// (Linear's create_issue with teamId): that is clearly not GitHub. A server
// whose name mentions GitHub is additionally held to the catalog for tools
// it does not list, so a new GitHub tool is unrecognized rather than unknown.
func Resolve(toolName string, input map[string]any) (string, bool) {
	server, tool, ok := splitMCPToolName(toolName)
	if !ok {
		return "", false
	}
	githubServer := strings.Contains(strings.ToLower(server), "github")
	catalogued, known := githubTools[tool]
	if !known {
		if githubServer {
			return GitHubUnrecognizedTool, true
		}
		return "", false
	}
	if validInput(catalogued, input) {
		return GitHubToolPrefix + catalogued.Name, true
	}
	if !githubServer && hasForeignField(catalogued, input) {
		return "", false
	}
	return GitHubUnrecognizedTool, true
}

// hasForeignField reports input that names a field the pinned schema does
// not know. Missing or mistyped known fields are schema drift on a GitHub
// tool; a field GitHub never had is another product's tool.
func hasForeignField(tool githubTool, input map[string]any) bool {
	for field := range input {
		if _, ok := tool.Properties[field]; !ok {
			return true
		}
	}
	return false
}

func splitMCPToolName(toolName string) (server, tool string, ok bool) {
	if !strings.HasPrefix(toolName, mcpPrefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(toolName, mcpPrefix)
	server, tool, found := strings.Cut(rest, mcpSeparator)
	if !found || server == "" || tool == "" {
		return "", "", false
	}
	return server, tool, true
}

func loadGitHubTools() map[string]githubTool {
	var catalog githubCatalog
	if err := json.Unmarshal(githubCatalogJSON, &catalog); err != nil {
		panic("invalid embedded GitHub MCP catalog: " + err.Error())
	}
	if catalog.Source != githubMCPSource {
		panic("embedded GitHub MCP catalog does not match its pinned source")
	}
	tools := make(map[string]githubTool, len(catalog.Tools))
	for _, tool := range catalog.Tools {
		tools[tool.Name] = tool
	}
	return tools
}

func validInput(tool githubTool, input map[string]any) bool {
	if input == nil {
		input = map[string]any{}
	}
	for _, field := range tool.Required {
		if _, ok := input[field]; !ok {
			return false
		}
	}
	for field, value := range input {
		kind, ok := tool.Properties[field]
		if !ok || !validType(kind, value) {
			return false
		}
	}
	return true
}

func validType(kind string, value any) bool {
	if kind == "any" {
		return true
	}
	switch value := value.(type) {
	case string:
		return kind == "string"
	case bool:
		return kind == "boolean"
	case []any:
		return kind == "array"
	case map[string]any:
		return kind == "object"
	case json.Number:
		if kind == "number" {
			_, err := value.Float64()
			return err == nil
		}
		if kind == "integer" {
			_, err := value.Int64()
			return err == nil
		}
	case float64:
		return kind == "number" || kind == "integer" && math.Trunc(value) == value
	case float32, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return kind == "number" || kind == "integer"
	}
	return false
}

// githubOperations is the crosswalk from catalogued GitHub MCP write tools
// to the github/operation vocabulary the shell projection emits for git, gh
// and curl. Cedar matches MCP calls by resource id, so the presets list the
// tool ids directly; this table keeps the two surfaces named consistently
// for trace display and template authors. The pinned catalog has no
// ref-deleting, release, workflow or settings tool, so merge is the only
// row until it is re-pinned.
var githubOperations = map[string][]string{
	GitHubToolPrefix + "merge_pull_request": {"merge-pull-request"},
}

// Operations returns the github/operation values a resolved GitHub MCP tool
// id performs, or nil for reads, unrecognized and non-GitHub tools.
func Operations(toolID string) []string {
	operations := githubOperations[toolID]
	if len(operations) == 0 {
		return nil
	}
	return append([]string(nil), operations...)
}
