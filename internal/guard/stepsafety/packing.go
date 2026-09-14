package stepsafety

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
)

const maxSequenceLength = 512

var fieldBudgets = [4]int{96, 144, 128, 128}
var fieldMarkerIDs = [4]int64{128001, 128002, 128003, 128004}

type tokenEncoder interface {
	encode(context.Context, string) ([]int64, error)
}
type packedInput struct {
	IDs            []int64
	Mask           []int64
	HistoryOmitted bool
}

func packInput(ctx context.Context, tokenizer tokenEncoder, input Input) (packedInput, error) {
	var result packedInput
	if ExcludedTool(input.ToolName) {
		return result, backendError(ErrorExcludedTool, nil)
	}
	if err := validateInputBounds(input); err != nil {
		return result, err
	}
	arguments, err := compactSortedJSON(input.ToolArguments)
	if err != nil {
		return result, err
	}
	schema, err := schemaText(input.AvailableToolSchemas)
	if err != nil {
		return result, err
	}
	fields := [4]string{input.UserRequest, input.InteractionHistory, strings.TrimSpace("[TOOL_NAME]\n" + input.ToolName + "\n[ARGUMENTS]\n" + arguments), schema}
	var selected [4][]int64
	for _, index := range []int{2, 0, 3} {
		tokens, err := tokenizer.encode(ctx, fields[index])
		if err != nil {
			return result, err
		}
		if len(tokens) > fieldBudgets[index] {
			code := ErrorActionTooLarge
			if index == 0 {
				code = ErrorRequestTooLarge
			}
			if index == 3 {
				code = ErrorSchemaTooLarge
			}
			return result, backendError(code, nil)
		}
		selected[index] = tokens
	}
	selected[1], result.HistoryOmitted, err = selectHistory(ctx, tokenizer, fields[1], fieldBudgets[1])
	if err != nil {
		return result, err
	}
	result.HistoryOmitted = result.HistoryOmitted || input.HistoryOmitted
	result.IDs, result.Mask = assembleTokens(selected)
	return result, nil
}

// Keep the training field order, special IDs, separators, and padding. Only
// history is truncated; admitted requests, actions, and schemas stay complete.
func assembleTokens(fields [4][]int64) ([]int64, []int64) {
	ids := make([]int64, 0, maxSequenceLength)
	ids = append(ids, 1)
	for i, tokens := range fields {
		ids = append(ids, fieldMarkerIDs[i])
		ids = append(ids, tokens...)
		ids = append(ids, 2)
	}
	mask := make([]int64, maxSequenceLength)
	for i := range ids {
		mask[i] = 1
	}
	ids = append(ids, make([]int64, maxSequenceLength-len(ids))...)
	return ids, mask
}

func selectHistory(ctx context.Context, tokenizer tokenEncoder, history string, budget int) ([]int64, bool, error) {
	if strings.TrimSpace(history) == "" {
		history = "[]"
	}
	var entries []json.RawMessage
	if err := json.Unmarshal([]byte(history), &entries); err != nil {
		return nil, false, backendError(ErrorInvalidHistory, nil)
	}
	if len(entries) > maxHistoryEntries {
		return nil, false, backendError(ErrorInputTooLarge, nil)
	}
	selected := make([]json.RawMessage, 0, len(entries))
	omitted := false
	for _, entry := range entries {
		var event struct {
			Tool string `json:"tool"`
		}
		if err := json.Unmarshal(entry, &event); err != nil || event.Tool == "" {
			return nil, omitted, backendError(ErrorInvalidHistory, nil)
		}
		if ExcludedTool(event.Tool) {
			omitted = true
			continue
		}
		selected = append(selected, entry)
	}
	encoded, err := compactSortedJSON(selected)
	if err != nil {
		return nil, omitted, err
	}
	tokens, err := tokenizer.encode(ctx, encoded)
	if err != nil {
		return nil, omitted, err
	}
	if len(tokens) > budget {
		// Match the training history packer after removing excluded tools:
		// first 72 + last 72 tokens at the fixed 144-token history budget.
		// The model consumes token fragments; they need not form valid JSON.
		head := (budget + 1) / 2
		tail := budget - head
		truncated := make([]int64, 0, budget)
		tokens = append(append(truncated, tokens[:head]...), tokens[len(tokens)-tail:]...)
		omitted = true
	}
	return tokens, omitted, nil
}

// The schema field used Python's default JSON separators (unlike action and
// history). Insert spaces outside strings only to preserve that contract.
func schemaText(value any) (string, error) {
	if value == nil {
		return "", nil
	}
	if text, ok := value.(string); ok {
		return text, nil
	}
	compact, err := compactSortedJSON(value)
	if err != nil {
		return "", err
	}
	var out strings.Builder
	quoted, escaped := false, false
	for _, r := range compact {
		out.WriteRune(r)
		if quoted {
			if escaped {
				escaped = false
			} else if r == '\\' {
				escaped = true
			} else if r == '"' {
				quoted = false
			}
			continue
		}
		if r == '"' {
			quoted = true
		} else if r == ':' || r == ',' {
			out.WriteByte(' ')
		}
	}
	return out.String(), nil
}

// Match known file-tool names and namespace leaves, without excluding broad
// verbs such as read_email or write_message that the model can still score.
func ExcludedTool(name string) bool {
	if len(name) > 256 {
		return false
	}
	name = strings.ToLower(strings.TrimSpace(name))
	if i := strings.LastIndex(name, "__"); i >= 0 {
		name = name[i+2:]
	}
	if i := strings.LastIndexAny(name, ".:/"); i >= 0 {
		name = name[i+1:]
	}
	switch name {
	case "read", "write", "edit", "multiedit", "notebookedit", "apply_patch", "read_file", "read_text_file", "read_multiple_files", "write_file", "edit_file", "replace_file_content", "multi_replace_file_content":
		return true
	}
	return false
}

// Reject large or malformed JSON values before allocating their serialization.
// Hook adapters supply JSON primitives; unsupported Go objects aren't inputs.
func boundedJSONSize(value any, remaining *int, depth int) error {
	if depth > 64 || *remaining < 0 {
		return backendError(ErrorInputTooLarge, nil)
	}
	*remaining -= 2
	switch v := value.(type) {
	case nil, bool, float64, float32, int, int64, json.Number:
	case string:
		*remaining -= len(v)
	case map[string]any:
		for key, item := range v {
			*remaining -= len(key) + 3
			if err := boundedJSONSize(item, remaining, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range v {
			if err := boundedJSONSize(item, remaining, depth+1); err != nil {
				return err
			}
		}
	default:
		return backendError(ErrorInference, errors.New("unsupported JSON input"))
	}
	if *remaining < 0 {
		return backendError(ErrorInputTooLarge, nil)
	}
	return nil
}
