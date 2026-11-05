package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeRowPreservesNumericArgumentsAndSchemas(t *testing.T) {
	data := []byte(`{"id":"numbers","input":{"tool_name":"lookup","tool_arguments":{"id":9007199254740993,"nested":[18446744073709551615,1.234567890123456789,1e30]},"available_tool_schemas":{"limit":9007199254740993}}}`)
	row, err := decodeRow(data)
	if err != nil {
		t.Fatal(err)
	}
	args := row.Input.ToolArguments.(map[string]any)
	if got, ok := args["id"].(json.Number); !ok || got.String() != "9007199254740993" {
		t.Fatalf("rounded ID: %v", args["id"])
	}
	nested := args["nested"].([]any)
	for i, want := range []string{"18446744073709551615", "1.234567890123456789", "1e30"} {
		if got, ok := nested[i].(json.Number); !ok || got.String() != want {
			t.Fatalf("number %d changed: %v", i, nested[i])
		}
	}
	encoded, err := json.Marshal(row.Input.AvailableToolSchemas)
	if err != nil || !strings.Contains(string(encoded), "9007199254740993") {
		t.Fatalf("rounded schema: %s, %v", encoded, err)
	}
}

func TestDecodeRowRejectsTrailingJSON(t *testing.T) {
	for _, input := range []string{`{} {}`, `{} null`, `{} trailing`, `{"input":`} {
		if _, err := decodeRow([]byte(input)); err == nil {
			t.Fatalf("accepted invalid line %q", input)
		}
	}
	if _, err := decodeRow([]byte("{} \t\r\n")); err != nil {
		t.Fatal(err)
	}
}
