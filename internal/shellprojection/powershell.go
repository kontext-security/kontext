package shellprojection

import (
	"regexp"
	"slices"
	"strings"

	"github.com/kontext-security/kontext/internal/cedareval"
)

// FactDialectPowerShell marks a projection made by the PowerShell grammar: of
// a command run through an agent's PowerShell tool or through pwsh or
// powershell from another shell, or one of two readings of a command whose
// shell is not known (Codex on Windows). A policy can match that reading.
const FactDialectPowerShell = "shell/dialect=powershell"

// ProjectPowerShell projects a command run through an agent's PowerShell
// tool. Like Project it never executes or expands anything and never fails;
// every projection carries FactDialectPowerShell.
//
// PowerShell text is not POSIX shell text: a backslash is a path separator,
// not an escape; the backtick escapes and continues lines; & calls a program
// named by a string; and a statement that starts with a variable or a string
// is an expression, so `$GIT push` runs nothing. The tokenizer below reads
// that much. The words of each call are then classified as a POSIX shell's
// are, so git, gh, curl and the provider CLIs keep their facts. Cmdlets get
// no facts of their own.
func ProjectPowerShell(command string) []cedareval.ShellProjectionV2 {
	return withDialect(projectPowerShell(command, walk{}, true))
}

func withDialect(projections []cedareval.ShellProjectionV2) []cedareval.ShellProjectionV2 {
	for i := range projections {
		projections[i].Facts = sortedUnique(append(projections[i].Facts, FactDialectPowerShell))
	}
	return projections
}

// powerShellKeywords open a language construct, not a call; the calls in
// their blocks and conditions are projected from those.
var powerShellKeywords = words("if", "elseif", "else", "foreach", "for", "while", "do", "until", "switch", "try", "catch", "finally", "trap", "function", "filter", "workflow", "param", "begin", "process", "end", "break", "continue", "data", "dynamicparam", "class", "enum", "using")

// powerShellFlowKeywords run the pipeline that follows them before they
// return, throw or exit, so that pipeline is the statement's call.
var powerShellFlowKeywords = words("return", "throw", "exit")

// powerShellClauses continue a construct after one of its blocks, as in
// if { } else { }, try { } catch { } or do { } while ( ).
var powerShellClauses = words("else", "elseif", "catch", "finally", "while", "until")

// powerShellAssignments are the assignment operators as words.
var powerShellAssignments = words("=", "+=", "-=", "*=", "/=", "%=", "??=")

// projectPowerShell projects a whole script: one with no call still gets a
// projection, as in project.
func projectPowerShell(command string, w walk, top bool) []cedareval.ShellProjectionV2 {
	projections := powerShellCalls(command, w, top)
	if len(projections) == 0 {
		projections = append(projections, projection("unknown", nil, []string{"empty-command"}, false))
	}
	return projections
}

func powerShellCalls(command string, w walk, top bool) []cedareval.ShellProjectionV2 {
	if len(command) > maxCommandBytes {
		return scriptParseFailure("command-too-large", command)
	}
	statements, nested, reason := scanScript(command, dialectPowerShell)
	if reason != "" {
		return scriptParseFailure(reason, command)
	}
	return projectStatements(statements, nested, dialectPowerShell, w, top)
}

// endsConstruct reports a statement that is a keyword construct whose last
// word is one of its blocks or groupings, so that what follows starts a
// statement of its own.
func endsConstruct(words []scriptWord) bool {
	if len(words) < 2 || !words[0].literal || !powerShellKeywords[strings.ToLower(words[0].value)] {
		return false
	}
	last := words[len(words)-1]
	return !last.literal && !last.expression
}

// afterConstruct returns the words that follow a keyword construct: those
// from the first plain word after one of its blocks or groupings that is not
// a clause such as else or catch, or nil when the statement ends with it.
// Words before the first block, a function's name or switch's -regex, belong
// to the construct.
func afterConstruct(words []scriptWord) []scriptWord {
	block := false
	for i := 1; i < len(words); i++ {
		w := words[i]
		switch {
		case !w.literal:
			block = block || !w.expression
		case block && w.value != "," && !powerShellClauses[strings.ToLower(w.value)]:
			return words[i:]
		}
	}
	return nil
}

// isFlowKeyword reports return, throw or exit as a statement's first word.
func isFlowKeyword(word scriptWord) bool {
	return word.literal && !word.quoted && powerShellFlowKeywords[strings.ToLower(word.value)]
}

// numberLiteral is a PowerShell integer, real or hex literal with its type
// and multiplier suffixes.
var numberLiteral = regexp.MustCompile(`^(?i:[+-]?([0-9]+(\.[0-9]*)?|\.[0-9]+)(e[+-]?[0-9]+)?|0x[0-9a-f]+)(?i:[dlun]|[us][ly]?|y)?(?i:[kmgtp]b)?$`)

// isNumberExpression reports a word that PowerShell reads as a number, a
// range of numbers (1..3) or an array of them (1,2,3).
func isNumberExpression(word string) bool {
	if word == "" || strings.IndexByte("0123456789+-.", word[0]) < 0 {
		return false
	}
	numbers := 0
	for _, part := range strings.Split(strings.ReplaceAll(word, "..", ","), ",") {
		if part == "" {
			continue
		}
		if !numberLiteral.MatchString(part) {
			return false
		}
		numbers++
	}
	return numbers > 0
}

// assignmentPrefix reports words that are only the targets and operators
// of an assignment so far, as in $x = or $a, or $x = $a, — a variable that
// follows them is another target, not an expression.
func assignmentPrefix(words []scriptWord) bool {
	// The pipeline of return, throw or exit, or after foreach's in, may
	// itself be an assignment.
	if len(words) > 0 && isFlowKeyword(words[0]) {
		words = words[1:]
	} else if len(words) >= 2 && words[0].variable && words[1].literal && !words[1].quoted && strings.EqualFold(words[1].value, "in") {
		words = words[2:]
	}
	start := 0
	for i, word := range words {
		if word.assign || word.literal && !word.quoted && powerShellAssignments[word.value] {
			if !variableList(words[start:i], true) {
				return false
			}
			start = i + 1
		}
	}
	return variableList(words[start:], false)
}

// variableList reports variables separated by commas; a complete list ends
// with a variable, an open one with a comma (or is empty).
func variableList(words []scriptWord, complete bool) bool {
	for i, word := range words {
		if i%2 == 0 && !word.variable || i%2 == 1 && !(word.literal && word.value == ",") {
			return false
		}
	}
	if complete {
		return len(words)%2 == 1
	}
	return len(words)%2 == 0
}

// multipleAssignment returns the index of the assignment operator after a
// list of variables, as in $a, $b = ..., or -1 when the words do not start
// with one.
func multipleAssignment(words []scriptWord) int {
	if len(words) < 3 || !words[0].variable {
		return -1
	}
	for k := 1; k < len(words); k++ {
		switch word := words[k]; {
		case word.literal && !word.quoted && powerShellAssignments[word.value]:
			return k
		case word.variable, word.literal && !word.quoted && word.value == ",":
		default:
			return -1
		}
	}
	return -1
}

// pipedString returns the string a statement that is a single string
// outputs; complete is false for any other statement, whose output is not
// known.
func pipedString(statement scriptStatement) (_ []string, complete bool) {
	if len(statement.words) != 1 || !statement.words[0].quoted || !statement.words[0].literal || statement.invoke {
		return nil, false
	}
	return []string{statement.words[0].value}, true
}

// classifyInvokeExpression runs its argument as PowerShell, like eval. A
// cmdlet takes any unambiguous prefix of a parameter name, and no common
// parameter starts with c, so -c, -Com and -Command:'...' all name -Command;
// any other parameter before the script leaves the reading incomplete.
func classifyInvokeExpression(args []string, complete bool, w walk) []cedareval.ShellProjectionV2 {
	if len(args) > 0 && strings.HasPrefix(args[0], "-") {
		name, value, inline := strings.Cut(args[0][1:], ":")
		if name == "" || !strings.HasPrefix("command", strings.ToLower(name)) {
			return single(projection("invoke-expression", nil, []string{"unrecognized-wrapper-arguments"}, false))
		}
		args = args[1:]
		if inline {
			args = append([]string{value}, args...)
		}
	}
	if !complete {
		return single(projection("invoke-expression", nil, []string{"dynamic-script"}, false))
	}
	return nestedPowerShell("invoke-expression", strings.Join(args, " "), w)
}

func nestedPowerShell(program, script string, w walk) []cedareval.ShellProjectionV2 {
	if strings.TrimSpace(script) == "" {
		return single(projection(program, nil, []string{"dynamic-script"}, false))
	}
	if w.depth >= maxScriptDepth {
		return single(projection(program, nil, []string{"script-depth-exceeded"}, false))
	}
	inner := withDialect(projectPowerShell(script, walk{depth: w.depth + 1}, false))
	for i := range inner {
		inner[i].Features = sortedUnique(append(inner[i].Features, "nested-script"))
	}
	return inner
}

// matchesParameter reports whether name, lowercased and without its dash,
// names the parameter full: by the full name, one of its aliases, or a
// prefix of it of at least three characters.
func matchesParameter(name, full string, aliases ...string) bool {
	return name == full || len(name) >= 3 && strings.HasPrefix(full, name) || slices.Contains(aliases, name)
}

// powerShellHostParameter is a pwsh or powershell parameter other than the
// ones that name a script.
type powerShellHostParameter struct {
	name    string
	aliases []string
	value   bool
}

var powerShellHostParameters = []powerShellHostParameter{
	{name: "executionpolicy", aliases: []string{"ex", "ep"}, value: true},
	{name: "workingdirectory", aliases: []string{"wd", "wo"}, value: true},
	{name: "configurationname", aliases: []string{"config"}, value: true},
	{name: "configurationfile", value: true},
	{name: "custompipename", value: true},
	{name: "windowstyle", aliases: []string{"w"}, value: true},
	{name: "outputformat", aliases: []string{"o", "of"}, value: true},
	{name: "inputformat", aliases: []string{"in", "if"}, value: true},
	{name: "settingsfile", aliases: []string{"settings"}, value: true},
	{name: "psconsolefile", value: true},
	{name: "version", aliases: []string{"v"}, value: true},
	{name: "noprofile", aliases: []string{"nop"}},
	{name: "nologo", aliases: []string{"nol"}},
	{name: "noninteractive", aliases: []string{"noni"}},
	{name: "noexit", aliases: []string{"noe"}},
	{name: "noprofileloadtime"},
	{name: "interactive", aliases: []string{"i"}},
	{name: "login", aliases: []string{"l"}},
	{name: "sta"},
	{name: "mta"},
}

// classifyPowerShellHost sees through pwsh and powershell running a script
// given on the command line. Parameter names are case-insensitive and may be
// abbreviated, so -c, -com and -COMMAND all name -Command. The first
// argument that is not a parameter is a script file for pwsh and a command
// for Windows PowerShell. An unknown parameter leaves the call incomplete,
// since it may take a value.
func classifyPowerShellHost(program string, args []string, complete bool, w walk) []cedareval.ShellProjectionV2 {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "" {
			return single(projection(program, nil, []string{"dynamic-script"}, false))
		}
		if !strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "/") {
			if program == "powershell" {
				return powerShellHostScript(program, args[i:], complete, w)
			}
			return single(projection(program, nil, nil, complete))
		}
		name, value, inline := strings.Cut(strings.TrimLeft(arg, "-/"), ":")
		name = strings.ToLower(name)
		switch {
		case name == "c" || matchesParameter(name, "command"):
			rest := args[i+1:]
			if inline {
				rest = append([]string{value}, rest...)
			}
			return powerShellHostScript(program, rest, complete, w)
		case name == "cwa" || len(name) > len("command") && strings.HasPrefix("commandwithargs", name):
			// The script is the next argument; the ones after it are its
			// arguments.
			if i+1 >= len(args) {
				return single(projection(program, nil, []string{"missing-script"}, false))
			}
			return powerShellHostScript(program, args[i+1:i+2], complete, w)
		case name == "e" || matchesParameter(name, "encodedcommand", "ec"):
			// The script is base64 text; reading it needs policy for it first.
			return single(projection(program, nil, []string{"encoded-script"}, false))
		case name == "f" || matchesParameter(name, "file"), name == "h" || name == "?" || name == "help":
			return single(projection(program, nil, nil, complete))
		}
		index := slices.IndexFunc(powerShellHostParameters, func(parameter powerShellHostParameter) bool {
			return matchesParameter(name, parameter.name, parameter.aliases...)
		})
		if index < 0 {
			return single(projection(program, nil, []string{"unrecognized-wrapper-arguments"}, false))
		}
		if powerShellHostParameters[index].value && !inline {
			i++
		}
	}
	return single(projection(program, nil, nil, complete))
}

// powerShellHostScript joins the arguments after -Command into one script,
// as the host does; "-" reads the script from stdin.
func powerShellHostScript(program string, args []string, complete bool, w walk) []cedareval.ShellProjectionV2 {
	if len(args) == 0 {
		return single(projection(program, nil, []string{"missing-script"}, false))
	}
	if len(args) == 1 && args[0] == "-" {
		return single(projection(program, nil, []string{"stdin-script"}, false))
	}
	if !complete {
		return single(projection(program, nil, []string{"dynamic-script"}, false))
	}
	return nestedPowerShell(program, strings.Join(args, " "), w)
}

// typographicQuotes are the curly quotes PowerShell reads as straight ones,
// so git receives “--force” as --force.
var typographicQuotes = strings.NewReplacer("\u2018", "'", "\u2019", "'", "\u201a", "'", "\u201b", "'", "\u201c", `"`, "\u201d", `"`, "\u201e", `"`)

// assignmentOperator reports an assignment operator at src[i:], after
// optional blanks, and the index of its last byte.
func assignmentOperator(src string, i int) (int, bool) {
	for i < len(src) && (src[i] == ' ' || src[i] == '\t') {
		i++
	}
	for _, operator := range []string{"??=", "+=", "-=", "*=", "/=", "%=", "="} {
		if strings.HasPrefix(src[i:], operator) && !strings.HasPrefix(src[i+len(operator):], "=") {
			return i + len(operator) - 1, true
		}
	}
	return 0, false
}

// powerShellEscapes are the backtick escapes PowerShell expands in double
// quotes; any other escaped character stands for itself.
var powerShellEscapes = map[byte]byte{'0': 0, 'a': 7, 'b': 8, 'e': 27, 'f': 12, 'n': '\n', 'r': '\r', 't': '\t', 'v': 11}

// subexpressions returns the scripts of the $( ) subexpressions in the body
// of a double-quoted here-string.
func subexpressions(body string) []string {
	var scripts []string
	for i := 0; i+1 < len(body); i++ {
		switch {
		case body[i] == '`':
			i++
		case body[i] == '$' && body[i+1] == '(':
			end := matchBracket(body, i+1)
			if end < 0 {
				// Unbalanced: hand the rest over, so it fails as a script.
				return append(scripts, body[i+2:])
			}
			scripts = append(scripts, body[i+2:end])
			i = end
		}
	}
	return scripts
}

// scriptBlocks returns the scripts of the { } blocks in text that is not
// itself a script, such as an attribute's arguments, which are otherwise
// constants. Text that does not tokenize is returned whole, so it fails as a
// script.
func scriptBlocks(text string) []string {
	var scripts []string
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '`':
			i++
		case '\'', '"':
			i = closingQuote(text, i)
		case '{':
			end := matchBracket(text, i)
			if end < 0 {
				return append(scripts, text)
			}
			scripts = append(scripts, text[i+1:end])
			i = end
		}
	}
	return scripts
}

// hashtableStatements returns the statements in the body of a hashtable
// literal: entries are key = value, separated by ; or a new line, and each
// value runs as a statement while the table is built. A key is evaluated
// too, as in @{ "$(git ...)" = 1 }, so a key that can run anything comes back
// as an expression to read; a bare or single-quoted key is plain text. A body
// that does not tokenize is returned whole, so it fails as a script.
func hashtableStatements(body string) []string {
	var values []string
	start, assign := 0, -1
	entry := func(end int) {
		if assign >= 0 {
			if key := strings.TrimSpace(body[start:assign]); strings.ContainsAny(key, "$(@\"") {
				values = append(values, "$null["+key+"]")
			}
			values = append(values, body[assign+1:end])
		}
		start, assign = end+1, -1
	}
	for i := 0; i < len(body); i++ {
		switch c := body[i]; c {
		case '`':
			i++
		case '\'', '"':
			i = closingQuote(body, i)
		case '<':
			// A block comment is blank space: its = and ; separate nothing.
			if i+1 < len(body) && body[i+1] == '#' {
				end := strings.Index(body[i+2:], "#>")
				if end < 0 {
					return append(values, body)
				}
				blank := assign < 0 && strings.TrimSpace(body[start:i]) == ""
				i += end + 3
				if blank {
					start = i + 1
				}
			}
		case '#':
			if i == 0 || strings.IndexByte(" \t\n;", body[i-1]) >= 0 {
				end := strings.IndexByte(body[i:], '\n')
				if end < 0 {
					end = len(body) - i
				}
				entry(i)
				i += end
				start = i + 1
			}
		case '(', '{', '[':
			end := matchBracket(body, i)
			if end < 0 {
				return append(values, body)
			}
			i = end
		case '=':
			if assign < 0 {
				assign = i
			}
		case ';', '\n':
			entry(i)
		}
	}
	entry(len(body))
	return values
}

// assignmentTarget reports whether the member accesses and indexes from
// src[i] on end in an assignment operator, and returns the operator's last
// index. The target's indexes and arguments run before the assignment, as in
// $x[$(git ...)]=1, so they come back as an expression to read on its own.
func assignmentTarget(src string, i int) (end int, target []string, ok bool) {
	suffix := memberSuffix(src, i)
	if end, ok = assignmentOperator(src, suffix); !ok {
		return 0, nil, false
	}
	if strings.ContainsAny(src[i:suffix], "[(") {
		target = []string{"$null" + src[i:suffix]}
	}
	return end, target, true
}

// memberSuffix returns the index after the member accesses and indexes that
// follow a variable or a type ending before src[i], as in .Prop, ::Name, [0]
// or .Method(), so that an assignment to a member or an element is seen.
func memberSuffix(src string, i int) int {
	for i < len(src) {
		switch {
		case src[i] == '[':
			end := matchBracket(src, i)
			if end < 0 {
				return i
			}
			i = end + 1
		case src[i] == '.' || strings.HasPrefix(src[i:], "::"):
			start := i + 1
			if src[i] == ':' {
				start++
			}
			end := start
			for end < len(src) && isNameByte(src[end]) {
				end++
			}
			if end == start {
				return i
			}
			i = end
			if i < len(src) && src[i] == '(' {
				if end = matchBracket(src, i); end < 0 {
					return i
				}
				i = end + 1
			}
		default:
			return i
		}
	}
	return i
}
