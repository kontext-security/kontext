package shellprojection

import (
	"strings"

	"github.com/kontext-security/kontext/internal/cedareval"
)

func projectCmd(command string, w walk) []cedareval.ShellProjectionV2 {
	if len(command) > maxCommandBytes {
		return scriptParseFailure("command-too-large", command)
	}
	statements, _, reason := scanScript(command, dialectCmd)
	if reason != "" {
		return scriptParseFailure(reason, command)
	}
	projections := projectStatements(statements, nil, dialectCmd, w, false)
	if len(projections) == 0 {
		projections = append(projections, projection("unknown", nil, []string{"empty-command"}, false))
	}
	return projections
}

func nestedCmd(script string, w walk) []cedareval.ShellProjectionV2 {
	if strings.TrimSpace(script) == "" {
		return single(projection("cmd", nil, []string{"missing-script"}, false))
	}
	if w.depth >= maxScriptDepth {
		return single(projection("cmd", nil, []string{"script-depth-exceeded"}, false))
	}
	inner := projectCmd(script, walk{depth: w.depth + 1})
	for i := range inner {
		inner[i].Features = sortedUnique(append(inner[i].Features, "nested-script"))
	}
	return inner
}

// classifyCmd sees through cmd /c, /k and /r. The switches are
// case-insensitive, and the script may follow without a space.
func classifyCmd(args []string, complete bool, w walk) []cedareval.ShellProjectionV2 {
	for i, arg := range args {
		lower := strings.ToLower(arg)
		if !strings.HasPrefix(lower, "/") {
			return single(projection("cmd", nil, nil, complete))
		}
		if len(lower) < 2 || !strings.ContainsRune("ckr", rune(lower[1])) {
			continue
		}
		if !complete {
			return single(projection("cmd", nil, []string{"dynamic-script"}, false))
		}
		script := strings.TrimSpace(arg[2:] + " " + strings.Join(args[i+1:], " "))
		return nestedCmd(script, w)
	}
	return single(projection("cmd", nil, nil, complete))
}

// isCmdVariable reports a %NAME% reference, with cmd's :~ substring and :=
// substitution forms.
func isCmdVariable(name string) bool {
	for i := 0; i < len(name); i++ {
		if !isNameByte(name[i]) && strings.IndexByte(":~=,-", name[i]) < 0 {
			return false
		}
	}
	return name != ""
}
