package agenthooks

import "strings"

// CommandHandler is the command-bearing portion of an agent hook handler.
type CommandHandler struct {
	Command string
	Args    []string
}

// CommandPredicate reports whether a hook command handler belongs to a
// particular installer or product.
type CommandPredicate func(handler CommandHandler) bool

// SplitCommand splits a shell-like command string enough for hook ownership
// detection. It supports quotes and backslash escapes, and reports false for
// unterminated quotes or trailing escapes.
func SplitCommand(command string) ([]string, bool) {
	return splitCommand(command, false)
}

// SplitLiteralCommand accepts a single command made of literal shell words.
// Health checks may ignore quoting differences, but must not treat expansions,
// redirections, or multiple commands as equivalent to a direct hook invocation.
func SplitLiteralCommand(command string) ([]string, bool) {
	return splitCommand(command, true)
}

func splitCommand(command string, literalOnly bool) ([]string, bool) {
	var fields []string
	var builder strings.Builder
	var quote rune
	inField := false

	runes := []rune(command)
	for i := 0; i < len(runes); i++ {
		char := runes[i]
		switch {
		case quote != 0:
			if literalOnly && quote == '"' && (char == '$' || char == '`') {
				return nil, false
			}
			if char == quote {
				quote = 0
				continue
			}
			if quote == '"' && char == '\\' && i+1 < len(runes) && isDoubleQuoteEscape(runes[i+1]) {
				i++
				if runes[i] != '\n' {
					builder.WriteRune(runes[i])
				}
				inField = true
				continue
			}
			builder.WriteRune(char)
			inField = true
		case char == '\\':
			if i+1 >= len(runes) {
				return nil, false
			}
			i++
			builder.WriteRune(runes[i])
			inField = true
		case char == '\'' || char == '"':
			quote = char
			inField = true
		case char == ' ' || char == '\t' || char == '\n' || char == '\r':
			if literalOnly && (char == '\n' || char == '\r') {
				return nil, false
			}
			if inField {
				fields = append(fields, builder.String())
				builder.Reset()
				inField = false
			}
		default:
			if literalOnly && strings.ContainsRune("$`;|&<>()*?[]{}~#", char) {
				return nil, false
			}
			builder.WriteRune(char)
			inField = true
		}
	}
	if quote != 0 {
		return nil, false
	}
	if inField {
		fields = append(fields, builder.String())
	}
	return fields, true
}

func isDoubleQuoteEscape(char rune) bool {
	switch char {
	case '$', '`', '"', '\\', '\n':
		return true
	default:
		return false
	}
}

func commandHandlerFromMap(handler map[string]any) (CommandHandler, bool) {
	command, ok := handler["command"].(string)
	if !ok {
		return CommandHandler{}, false
	}
	args, ok := stringSlice(handler["args"])
	if !ok {
		return CommandHandler{}, false
	}
	return CommandHandler{
		Command: command,
		Args:    args,
	}, true
}

func stringSlice(value any) ([]string, bool) {
	switch args := value.(type) {
	case nil:
		return nil, true
	case []string:
		return append([]string(nil), args...), true
	case []any:
		out := make([]string, 0, len(args))
		for _, arg := range args {
			text, ok := arg.(string)
			if !ok {
				return nil, false
			}
			out = append(out, text)
		}
		return out, true
	default:
		return nil, false
	}
}
