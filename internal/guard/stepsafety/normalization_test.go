package stepsafety

import (
	"encoding/json"
	"testing"
)

func TestCandidateInputSchemaBindings(t *testing.T) {
	// Hand-authored endpoint expectations extend the frozen research fixtures:
	// input_schema-only definitions must bind like parameters/description tools.
	const definition = `{"name":"Search","input_schema":{"type":"object","properties":{"Query":{"type":"string"}}}}`
	const normalized = `{"input_schema":{"properties":{"Query":{"type":"string"}},"type":"object"},"name":"search"}`
	for _, tc := range []struct{ name, schema, want string }{
		{"definition", definition, normalized},
		{"list", `[` + definition + `]`, `[` + normalized + `]`},
		{"function", `{"type":"function","function":` + definition + `}`, `{"function":` + normalized + `,"type":"function"}`},
		{"tools", `{"tools":[` + definition + `]}`, `{"tools":[` + normalized + `]}`},
		{"nested_wrappers", `{"tools":[{"type":"function","function":` + definition + `}]}`, `{"tools":[{"function":` + normalized + `,"type":"function"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var parsed any
			if err := json.Unmarshal([]byte(tc.schema), &parsed); err != nil {
				t.Fatal(err)
			}
			for _, schema := range []any{tc.schema, parsed} {
				input := Input{
					UserRequest:        "Search for Query",
					InteractionHistory: `[{"tool":"Search","arguments":{"Query":"Past"},"observation":"Search complete"}]`,
					ToolName:           "Search", ToolArguments: map[string]any{"Query": "Search"},
					AvailableToolSchemas: schema,
				}
				before, _ := json.Marshal(input)
				got, err := candidateFields(input)
				want := [4]string{
					"Search for Query",
					`[{"arguments":{"Query":"Past"},"observation":"Search complete","tool":"search"}]`,
					"[TOOL_NAME]\nsearch\n[ARGUMENTS]\n{\"Query\":\"Search\"}",
					tc.want,
				}
				if err != nil || got != want {
					t.Fatalf("normalized fields=%q, err=%v; want %q", got, err, want)
				}
				after, _ := json.Marshal(input)
				if string(before) != string(after) {
					t.Fatal("normalization mutated the hook input")
				}
			}
		})
	}
}

func TestCandidateInputSchemaCaseCollisions(t *testing.T) {
	for _, other := range []string{
		`{"name":"search","input_schema":{}}`,
		`{"name":"search","parameters":{}}`,
		`{"name":"search","description":"Different binding"}`,
	} {
		input := Input{
			ToolName: "Search", ToolArguments: map[string]any{},
			InteractionHistory:   `[{"tool":"Search"},{"tool":"search"}]`,
			AvailableToolSchemas: `[{"name":"Search","input_schema":{}},` + other + `]`,
		}
		got, err := candidateFields(input)
		if err != nil {
			t.Fatal(err)
		}
		if got[1] != input.InteractionHistory || got[2] != "[TOOL_NAME]\nSearch\n[ARGUMENTS]\n{}" {
			t.Fatalf("distinct tool bindings were merged: %q", got)
		}
		var definitions []struct{ Name string }
		if err := json.Unmarshal([]byte(got[3]), &definitions); err != nil {
			t.Fatal(err)
		}
		if len(definitions) != 2 || definitions[0].Name != "Search" || definitions[1].Name != "search" {
			t.Fatalf("schema bindings were merged: %s", got[3])
		}
	}
}

func TestCandidateInputSchemaPreservesPayloadDefinitions(t *testing.T) {
	input := Input{
		ToolName: "Search", ToolArguments: map[string]any{"name": "PayloadName"},
		AvailableToolSchemas: `{"name":"Search","input_schema":{"type":"object","properties":{"name":{"type":"string"},"nested":{"name":"PayloadName","input_schema":{},"type":"object"}}}}`,
	}
	got, err := candidateFields(input)
	want := `{"input_schema":{"properties":{"name":{"type":"string"},"nested":{"input_schema":{},"name":"PayloadName","type":"object"}},"type":"object"},"name":"search"}`
	if err != nil || got[3] != want || got[2] != "[TOOL_NAME]\nsearch\n[ARGUMENTS]\n{\"name\":\"PayloadName\"}" {
		t.Fatalf("payload content changed: fields=%q, err=%v", got, err)
	}
}
