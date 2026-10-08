package stepsafety

import (
	"context"
	"encoding/json"
	"math"
	"regexp"
	"strings"
)

const ErrorUnsupportedEffect = "unsupported_effect"
const ErrorMissingRequest = "missing_request"
const ErrorCompoundRequest = "compound_or_mutation_request"

var scopeCamel = regexp.MustCompile(`([a-z0-9])([A-Z])`)
var scopeWords = regexp.MustCompile(`[a-z0-9]+`)
var requestWords = regexp.MustCompile(`[a-z]+`)

func scopeHas(words []string, options string) bool {
	for _, option := range strings.Fields(options) {
		for _, w := range words {
			if w == option {
				return true
			}
		}
	}
	return false
}
func scopePopulated(value any) bool {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v) != ""
	case float64:
		return !math.IsNaN(v) && !math.IsInf(v, 0)
	case float32:
		return !math.IsNaN(float64(v)) && !math.IsInf(float64(v), 0)
	case int, int64:
		return true
	case json.Number:
		n, e := v.Float64()
		return e == nil && !math.IsNaN(n) && !math.IsInf(n, 0)
	case []any:
		if len(v) == 0 {
			return false
		}
		for _, x := range v {
			if !scopePopulated(x) {
				return false
			}
		}
		return true
	}
	return false
}
func recognizedScopeEffect(tool string, raw any) string {
	args, ok := raw.(map[string]any)
	if !ok {
		return ""
	}
	ws := scopeWords.FindAllString(strings.ToLower(scopeCamel.ReplaceAllString(tool, "${1} ${2}")), -1)
	if scopeHas(ws, "search find get list read inspect describe preview dry simulate check test") {
		return ""
	}
	for _, key := range []string{"dry_run", "dryRun", "preview", "simulate"} {
		if v, ok := args[key].(bool); ok && v {
			return ""
		}
	}
	keys := []string{}
	for k, v := range args {
		if scopePopulated(v) {
			keys = append(keys, strings.ToLower(k))
		}
	}
	if scopeHas(ws, "delete remove erase truncate drop wipe unlink") && scopeHas(ws, "file files email emails message messages record records database databases directory directories bucket buckets") && scopeHas(keys, "id ids file_id email_id message_id record_id path file filename name database bucket target records directory") {
		return "destructive_object_change"
	}
	if scopeHas(ws, "send transfer pay") && scopeHas(ws, "money payment payments funds") && scopeHas(keys, "recipient to account destination recipient_id account_id") {
		var amount float64
		switch n := args["amount"].(type) {
		case float64:
			amount = n
		case float32:
			amount = float64(n)
		case int:
			amount = float64(n)
		case int64:
			amount = float64(n)
		case json.Number:
			amount, _ = n.Float64()
		}
		if amount > 0 && !math.IsNaN(amount) && !math.IsInf(amount, 0) {
			return "money_transfer"
		}
	}
	if scopeHas(ws, "change reset update set rotate") && scopeHas(ws, "password passwords credential credentials") {
		for _, key := range []string{"password", "new_password", "newPassword", "credential"} {
			if v, ok := args[key].(string); ok && strings.TrimSpace(v) != "" {
				return "credential_change"
			}
		}
	}
	if scopeHas(ws, "send post publish forward") && scopeHas(ws, "email message mail") && scopeHas(keys, "recipient recipients to channel destination") && scopeHas(keys, "body content message text") {
		return "outgoing_message"
	}
	if scopeHas(ws, "share grant invite") && scopeHas(ws, "file document folder access permission") && scopeHas(keys, "recipient recipients user users email") && scopeHas(keys, "file_id document_id folder_id path resource permission") {
		return "access_share"
	}
	return ""
}

func scopedEligibility(input Input) error {
	if recognizedScopeEffect(input.ToolName, input.ToolArguments) == "" {
		return backendError(ErrorUnsupportedEffect, nil)
	}
	if strings.TrimSpace(input.UserRequest) == "" {
		return backendError(ErrorMissingRequest, nil)
	}
	if scopeHas(requestWords.FindAllString(strings.ToLower(input.UserRequest), -1), "delete remove erase transfer send change update pay create modify write add book reserve schedule cancel install run execute deploy reset adjust approve archive buy checkout clear commit disburse discard dispose drop empty forward grant invite merge move order post publish purchase purge push refund reimburse rename reply reschedule respond restart rotate save set share start stop submit unlink upload wipe") {
		return backendError(ErrorCompoundRequest, nil)
	}
	return nil
}

// packScopedInput preserves the frozen bounded contextual representation.
// The current action is complete. Request uses its head, history and schema
// use head/tail. Unsupported effects abstain before model inference.
func packScopedInput(ctx context.Context, tok tokenEncoder, input Input) (packedInput, error) {
	var out packedInput
	if err := validateInputBounds(input); err != nil {
		return out, err
	}
	if err := scopedEligibility(input); err != nil {
		return out, err
	}
	if err := requestIntentGate(ctx, input.UserRequest); err != nil {
		return out, err
	}
	fields, err := candidateFields(input)
	if err != nil {
		return out, err
	}
	var selected [4][]int64
	for i, text := range fields {
		tokens, err := tok.encode(ctx, text)
		if err != nil {
			return out, err
		}
		budget := fieldBudgets[i]
		if len(tokens) > budget {
			if i == 2 {
				return out, backendError(ErrorActionTooLarge, nil)
			}
			if i == 0 {
				tokens = tokens[:budget]
			} else {
				head := (budget + 1) / 2
				tokens = append(append([]int64{}, tokens[:head]...), tokens[len(tokens)-(budget-head):]...)
			}
			if i == 1 {
				out.HistoryOmitted = true
			}
		}
		selected[i] = tokens
	}
	out.IDs, out.Mask = assembleTokens(selected)
	out.HistoryOmitted = out.HistoryOmitted || input.HistoryOmitted
	return out, nil
}
