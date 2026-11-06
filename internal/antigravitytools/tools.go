// Package antigravitytools translates Antigravity's tool calls into the names
// and input keys the rest of Kontext reads. Shell detection, Cedar's named tools,
// risk rules and cost attribution all key on Claude Code's vocabulary (Bash with
// command, Read with file_path), which Cursor nearly shares and Antigravity does
// not. A call left untranslated is not an error anywhere downstream: it silently
// matches no rule, so every spelling the app is known to use belongs here.
package antigravitytools

import (
	"encoding/json"
	"regexp"
	"strings"
)

// mcpCall is how the app reports every MCP call, eager servers included, with
// the real server and tool in its arguments.
const mcpCall = "call_mcp_tool"

type tool struct {
	name string
	args map[string]string
}

// tools covers both spellings seen for the file tools: Google's documented list
// (view_file, write_to_file, replace_file_content) and what its models call at
// runtime (read_file, write_file, edit_file). Keys not listed pass through.
var tools = map[string]tool{
	"run_command":                {"Bash", map[string]string{"CommandLine": "command", "Cwd": "cwd", "toolSummary": "description"}},
	"read_file":                  {"Read", map[string]string{"Path": "file_path"}},
	"view_file":                  {"Read", map[string]string{"AbsolutePath": "file_path"}},
	"write_file":                 {"Write", map[string]string{"Path": "file_path", "Content": "content"}},
	"write_to_file":              {"Write", map[string]string{"TargetFile": "file_path", "CodeContent": "content"}},
	"edit_file":                  {"Edit", map[string]string{"Path": "file_path", "Target": "old_string", "Replacement": "new_string"}},
	"replace_file_content":       {"Edit", map[string]string{"TargetFile": "file_path", "TargetContent": "old_string", "ReplacementContent": "new_string"}},
	"multi_replace_file_content": {"MultiEdit", map[string]string{"TargetFile": "file_path", "ReplacementChunks": "edits"}},
	"list_dir":                   {"LS", map[string]string{"DirectoryPath": "path"}},
	"find_by_name":               {"Glob", map[string]string{"SearchDirectory": "path", "Pattern": "pattern"}},
	"grep_search":                {"Grep", map[string]string{"SearchPath": "path", "Query": "pattern"}},
	"search_web":                 {"WebSearch", nil},
	"read_url_content":           {"WebFetch", map[string]string{"Url": "url"}},
	"invoke_subagent":            {"Task", map[string]string{"Prompt": "prompt", "TypeName": "subagent_type", "Role": "description"}},
}

// modelVariant matches the effort and routing suffixes Antigravity adds to a
// model id: its default reports as gemini-3.8-flash-tiered, and the binary also
// names -extra-low, -low, -medium, -high, -max and -low-thinking variants.
var modelVariant = regexp.MustCompile(`(-(tiered|extra-low|low|medium|high|max|thinking))+$`)

// BaseModel is the id its maker publishes prices under. The variants are one
// model at one price, and pricing matches ids exactly.
func BaseModel(model string) string {
	return modelVariant.ReplaceAllString(model, "")
}

// Name returns the name Kontext records a call under. server and toolName are
// the MCP call's arguments; ok is false for an MCP call that does not name both.
func Name(name, server, toolName string) (string, bool) {
	if name == mcpCall {
		if server == "" || toolName == "" {
			return "", false
		}
		return "mcp__" + namePart(server) + "__" + namePart(toolName), true
	}
	if known, ok := tools[name]; ok {
		return known.name, true
	}
	return name, true
}

// IsMCP reports whether a call is an MCP call, and so what its server is.
func IsMCP(name string) bool { return name == mcpCall }

// Call translates a whole call into its recorded name and input.
func Call(name string, args map[string]any) (string, map[string]any, bool) {
	server, _ := args["ServerName"].(string)
	toolName, _ := args["ToolName"].(string)
	canonical, ok := Name(name, server, toolName)
	if !ok {
		return "", nil, false
	}
	if name == mcpCall {
		return canonical, mcpInput(args["Arguments"]), true
	}
	known, ok := tools[name]
	if !ok {
		if args == nil {
			args = map[string]any{}
		}
		return canonical, args, true
	}
	input := make(map[string]any, len(args))
	for key, value := range args {
		if renamed, ok := known.args[key]; ok {
			key = renamed
		}
		input[key] = value
	}
	return canonical, input, true
}

// mcpInput accepts an MCP call's arguments as an object or a JSON-encoded
// string. Policy evaluation needs an object either way.
func mcpInput(arguments any) map[string]any {
	switch value := arguments.(type) {
	case map[string]any:
		return value
	case nil:
		return map[string]any{}
	case string:
		decoder := json.NewDecoder(strings.NewReader(value))
		decoder.UseNumber()
		var object map[string]any
		if decoder.Decode(&object) == nil && object != nil {
			return object
		}
		return map[string]any{"raw": value}
	default:
		return map[string]any{"value": value}
	}
}

// namePart spells a server or tool name the way Claude Code and Codex do in
// mcp__ tool names, so MCP config lookups and tool catalogs match.
func namePart(name string) string {
	return strings.Map(func(r rune) rune {
		if r == '_' || r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			return r
		}
		return '_'
	}, name)
}
