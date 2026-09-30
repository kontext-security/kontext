package stepsafety

import (
	"encoding/json"
	"io"
	"regexp"
	"strings"
)

var schemaHeader = regexp.MustCompile(`(?m)^([A-Za-z_][A-Za-z0-9_.:/-]*):[ \t]+`)

// candidateFields matches the saved joint-CE input view. Only API binding names
// and JSON representation change; executable strings, argument keys, request and
// observation text remain intact. Never modify the hook's shared maps in place.
func candidateFields(input Input) ([4]string, error) {
	var fields [4]string
	schema, err := candidateSchema(input.AvailableToolSchemas)
	if err != nil {
		return fields, err
	}
	definitions := schemaDefinitions(schema)
	spellings := map[string]map[string]bool{}
	for _, d := range definitions {
		name := d["name"].(string)
		key := lowerASCII(name)
		if spellings[key] == nil {
			spellings[key] = map[string]bool{}
		}
		spellings[key][name] = true
	}
	name := func(s string) string {
		if len(spellings[lowerASCII(s)]) > 1 {
			return s
		}
		return lowerASCII(s)
	}
	for _, d := range definitions {
		d["name"] = name(d["name"].(string))
	}
	var schemaText string
	if schema != nil {
		if text, ok := schema.(string); ok {
			schemaText = text
		} else {
			schemaText, err = compactSortedJSON(schema)
			if err != nil {
				return fields, err
			}
		}
	}
	history := input.InteractionHistory
	if strings.TrimSpace(history) == "" {
		history = "[]"
	}
	h, err := decodeCandidateJSON(history)
	if err != nil {
		return fields, backendError(ErrorInvalidHistory, nil)
	}
	events, ok := h.([]any)
	if !ok || len(events) > maxHistoryEntries {
		return fields, backendError(ErrorInvalidHistory, nil)
	}
	for _, event := range events {
		e, ok := event.(map[string]any)
		if !ok {
			return fields, backendError(ErrorInvalidHistory, nil)
		}
		t, ok := e["tool"].(string)
		if !ok || t == "" {
			return fields, backendError(ErrorInvalidHistory, nil)
		}
		e["tool"] = name(t)
	}
	history, err = compactSortedJSON(events)
	if err != nil {
		return fields, err
	}
	args := input.ToolArguments
	// These exact interfaces use title/description as call-display metadata.
	// A TaskCreate description, WebFetch prompt, or arbitrary API payload is data.
	switch input.ToolName {
	case "Bash", "exec_command", "functions.exec_command", "mcp__workspace__bash", "mcp__cua_repl__js":
		if values, ok := args.(map[string]any); ok {
			copy := make(map[string]any, len(values))
			for k, v := range values {
				if k != "title" && k != "description" {
					copy[k] = v
				}
			}
			args = copy
		}
	}
	arguments, err := compactSortedJSON(args)
	if err != nil {
		return fields, err
	}
	return [4]string{input.UserRequest, history, strings.TrimSpace("[TOOL_NAME]\n" + name(input.ToolName) + "\n[ARGUMENTS]\n" + arguments), schemaText}, nil
}

func lowerASCII(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, s)
}

func decodeCandidateJSON(text string) (any, error) {
	d := json.NewDecoder(strings.NewReader(text))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, backendError(ErrorUnsupportedText, nil)
	}
	return v, nil
}

func candidateSchema(value any) (any, error) {
	if value == nil {
		return nil, nil
	}
	if text, ok := value.(string); ok {
		if strings.TrimSpace(text) == "" {
			return nil, nil
		}
		if parsed, err := decodeCandidateJSON(text); err == nil {
			switch parsed.(type) {
			case []any, map[string]any:
				return parsed, nil
			}
		}
		matches := schemaHeader.FindAllStringSubmatchIndex(text, -1)
		if len(matches) > 0 && strings.TrimSpace(text[:matches[0][0]]) == "" {
			var definitions []any
			for i, m := range matches {
				end := len(text)
				if i+1 < len(matches) {
					end = matches[i+1][0]
				}
				definitions = append(definitions, map[string]any{"name": text[m[2]:m[3]], "description": strings.TrimSpace(text[m[1]:end])})
			}
			return definitions, nil
		}
		// Research also accepted Python literal containers. Hooks supply JSON;
		// abstain on such unsupported containers instead of guessing a conversion.
		if strings.HasPrefix(strings.TrimSpace(text), "[") || strings.HasPrefix(strings.TrimSpace(text), "{") {
			return nil, backendError(ErrorUnsupportedText, nil)
		}
		return text, nil
	}
	text, err := compactSortedJSON(value)
	if err != nil {
		return nil, err
	}
	return decodeCandidateJSON(text)
}

func schemaDefinitions(value any) []map[string]any {
	switch v := value.(type) {
	case []any:
		var result []map[string]any
		for _, item := range v {
			result = append(result, schemaDefinitions(item)...)
		}
		return result
	case map[string]any:
		if f, ok := v["function"].(map[string]any); ok {
			return schemaDefinitions(f)
		}
		if t, ok := v["tools"].([]any); ok {
			return schemaDefinitions(t)
		}
		_, named := v["name"].(string)
		_, parameters := v["parameters"]
		_, inputSchema := v["input_schema"]
		_, description := v["description"]
		if named && (parameters || inputSchema || description || len(v) == 1) {
			return []map[string]any{v}
		}
	}
	return nil
}
