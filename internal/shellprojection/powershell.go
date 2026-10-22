package shellprojection

import (
	"slices"
	"strings"

	"github.com/kontext-security/kontext/internal/cedareval"
)

// FactDialectPowerShell marks a projection of a command the agent ran
// through its PowerShell tool, or through pwsh or powershell from another
// shell, so a policy can tell that dialect apart from a POSIX shell's.
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

type scriptDialect int

const (
	dialectPowerShell scriptDialect = iota
	dialectCmd
)

// scriptWord is one word of a statement. value is meaningful only when the
// word is literal, that is, nothing in it expands.
type scriptWord struct {
	value    string
	literal  bool
	quoted   bool // starts with a quote or a here-string
	variable bool // starts with a variable
	// expression is set for a word that starts with a value, a string, a
	// variable or a type literal, rather than a command name.
	expression bool
	assign     bool // the assignment operator after a leading variable
}

type scriptStatement struct {
	words []scriptWord
	// invoke is set by the & call operator: the first word names the
	// program even when it is a string or a variable.
	invoke bool
	// verbatim is set by PowerShell's --% token, after which the words are
	// passed on with cmd-style expansion this tokenizer does not model.
	verbatim bool
	// piped is set for a statement that reads the previous one's output.
	piped bool
}

// powerShellKeywords open a language construct, not a call; the calls in
// their blocks and conditions are projected from those.
var powerShellKeywords = words("if", "elseif", "else", "foreach", "for", "while", "do", "until", "switch", "try", "catch", "finally", "trap", "function", "filter", "workflow", "param", "begin", "process", "end", "return", "throw", "break", "continue", "exit", "data", "dynamicparam", "class", "enum", "using")

// windowsExecutableSuffixes are the PATHEXT defaults Windows finds a
// program by without them being typed.
var windowsExecutableSuffixes = []string{".exe", ".cmd", ".bat", ".com"}

// commandName reduces a program word to its command name the same way on
// every host: either path separator, a drive letter and an executable
// suffix are dropped, so C:\Program Files\Git\cmd\git.exe is git on macOS
// and Linux too.
func commandName(word string) string {
	if i := strings.LastIndexAny(word, `/\`); i >= 0 {
		word = word[i+1:]
	} else if len(word) >= 2 && word[1] == ':' {
		word = word[2:]
	}
	lower := strings.ToLower(word)
	for _, suffix := range windowsExecutableSuffixes {
		if strings.HasSuffix(lower, suffix) && len(word) > len(suffix) {
			return word[:len(word)-len(suffix)]
		}
	}
	return word
}

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

// projectStatements classifies each statement's call, then the scripts in
// its blocks, groupings and subexpressions, which run as part of it.
func projectStatements(statements []scriptStatement, nested []string, dialect scriptDialect, w walk, top bool) []cedareval.ShellProjectionV2 {
	// As in a POSIX shell, a help call is a read only when it is the whole
	// command.
	helpAllowed := top && w.depth == 0 && len(statements) == 1 && len(nested) == 0
	projections := make([]cedareval.ShellProjectionV2, 0, len(statements)+len(nested))
	for index, statement := range statements {
		words, ok := callWords(statement, dialect)
		if !ok {
			continue
		}
		values := make([]string, len(words))
		complete := !statement.verbatim
		for i, word := range words {
			if word.literal {
				values[i] = word.value
			} else {
				complete = false
			}
		}
		if len(values) > 0 && values[0] != "" {
			values[0] = commandName(values[0])
		}
		if len(values) > 0 && dialect == dialectPowerShell {
			if program := strings.ToLower(values[0]); program == "iex" || program == "invoke-expression" {
				args := values[1:]
				if len(args) == 0 && statement.piped && index > 0 {
					// 'git push' | iex runs the string it is piped.
					args, complete = pipedString(statements[index-1])
				}
				projections = append(projections, classifyInvokeExpression(args, complete, w)...)
				continue
			}
		}
		direct := len(values) > 0 && values[0] == "gh"
		projections = append(projections, classify(values, complete, walk{depth: w.depth}, helpAllowed && direct)...)
	}
	for _, script := range nested {
		// A block runs as part of the command, not as a script handed to
		// another shell, so it keeps the depth; bracket nesting bounds it.
		projections = append(projections, powerShellCalls(script, w, false)...)
	}
	return projections
}

// callWords returns the words of the call a statement makes, without the
// call operator, a leading assignment or cmd's @ and call; ok is false for a
// statement that calls nothing.
func callWords(statement scriptStatement, dialect scriptDialect) ([]scriptWord, bool) {
	words := statement.words
	if dialect == dialectCmd {
		if len(words) > 0 && words[0].literal {
			words[0].value = strings.TrimPrefix(words[0].value, "@")
			if strings.EqualFold(words[0].value, "call") {
				words = words[1:]
			}
		}
		return words, len(words) > 0
	}
	if len(words) >= 2 && words[0].variable && words[1].assign {
		words = words[2:]
	}
	if statement.invoke {
		return words, true
	}
	if len(words) == 0 {
		return nil, false
	}
	if words[0].literal && words[0].value == "." {
		// Dot-sourcing runs a script in the current scope.
		return words[1:], len(words) > 1
	}
	if words[0].expression {
		// A string, a variable or a type without & starts an expression: it
		// is evaluated, not run as a program, and calls only in its
		// groupings and blocks, which are projected from those.
		return nil, false
	}
	if words[0].literal && powerShellKeywords[strings.ToLower(words[0].value)] {
		return nil, false
	}
	return words, true
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

// classifyInvokeExpression runs its argument as PowerShell, like eval.
func classifyInvokeExpression(args []string, complete bool, w walk) []cedareval.ShellProjectionV2 {
	if len(args) > 0 && strings.EqualFold(args[0], "-command") {
		args = args[1:]
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

// scriptParseFailure projects text that does not tokenize as PowerShell or
// cmd. It is read as POSIX shell text too, every reading incomplete, so a
// call that parser recognises keeps its facts.
func scriptParseFailure(reason, command string) []cedareval.ShellProjectionV2 {
	projections := []cedareval.ShellProjectionV2{scriptParseFailureProgram(reason, command)}
	for _, posix := range Project(command) {
		if posix.ParseComplete {
			posix = projection(posix.Program, posix.Facts, posix.Features, false)
		}
		projections = append(projections, posix)
	}
	return projections
}

func scriptParseFailureProgram(reason, command string) cedareval.ShellProjectionV2 {
	failure := parseFailure(reason, command)
	fields := strings.Fields(command[:min(len(command), 4096)])
	if len(fields) > 1 && fields[0] == "&" {
		fields = fields[1:]
	}
	if len(fields) > 0 {
		if name := commandName(strings.Trim(fields[0], `&'"`)); programName.MatchString(name) {
			failure.Program = strings.ToLower(name)
		}
	}
	return failure
}

// scanScript splits PowerShell or cmd text into statements of words, and
// collects the scripts of PowerShell blocks, groupings and subexpressions.
// It reads quoting, escapes, the call operator, comments, here-strings and
// redirections; any other expansion makes its word non-literal. reason is
// set when the text does not tokenize.
func scanScript(src string, dialect scriptDialect) (statements []scriptStatement, nested []string, reason string) {
	src = strings.ReplaceAll(src, "\r\n", "\n")
	ps := dialect == dialectPowerShell
	if ps {
		src = typographicQuotes.Replace(src)
	}
	var (
		statement scriptStatement
		word      strings.Builder
		current   scriptWord
		inWord    bool
		redirect  bool // the next word is a redirection target
		count     int
	)
	beginWord := func() {
		if !inWord {
			inWord = true
			current = scriptWord{literal: true}
		}
	}
	endWord := func() {
		if !inWord {
			return
		}
		inWord = false
		current.value = word.String()
		word.Reset()
		count++
		switch {
		case redirect:
			redirect = false
		case ps && current.literal && !current.quoted && current.value == "--%":
			statement.verbatim = true
		default:
			statement.words = append(statement.words, current)
		}
	}
	endStatement := func() {
		endWord()
		redirect = false
		if len(statement.words) > 0 || statement.invoke {
			statements = append(statements, statement)
		}
		statement = scriptStatement{}
	}
	// block finds the bracket closing the one at src[i].
	block := func(i int) (int, bool) {
		end := matchBracket(src, i)
		switch {
		case end == -2:
			reason = "syntax-too-complex"
		case end < 0:
			reason = "syntax-error"
		}
		return end, end >= 0
	}

	for i := 0; i < len(src) && reason == ""; i++ {
		if count > maxSyntaxNodes {
			return nil, nil, "syntax-too-complex"
		}
		c := src[i]
		switch {
		case c == ' ' || c == '\t':
			endWord()
		case c == '\n' || ps && c == ';' || !ps && (c == '(' || c == ')'):
			endStatement()
		case c == '|':
			endStatement()
			if i+1 < len(src) && src[i+1] == '|' {
				i++
			} else {
				statement.piped = true
			}
		case c == '&':
			switch {
			case i+1 < len(src) && src[i+1] == '&':
				endStatement()
				i++
			case ps && !inWord && !statement.invoke && (len(statement.words) == 0 || len(statement.words) == 2 && statement.words[1].assign):
				// The call operator, at the start or after an assignment.
				statement.invoke = true
			default:
				// PowerShell runs what precedes a trailing & as a job; cmd
				// separates commands with it.
				endStatement()
			}
		case ps && c == '#' && !inWord:
			if end := strings.IndexByte(src[i:], '\n'); end < 0 {
				i = len(src)
			} else {
				i += end - 1
			}
		case ps && c == '<' && !inWord && i+1 < len(src) && src[i+1] == '#':
			end := strings.Index(src[i+2:], "#>")
			if end < 0 {
				reason = "syntax-error"
				break
			}
			i += end + 3
		case c == '>' || c == '<':
			if text := word.String(); inWord && current.literal && !current.quoted && (text == "*" || len(text) == 1 && text[0] >= '1' && text[0] <= '6') {
				// The stream number of 2>&1 or *> belongs to the operator.
				inWord = false
				word.Reset()
			} else {
				endWord()
			}
			if i+1 < len(src) && src[i+1] == '>' {
				i++
			}
			if i+2 < len(src) && src[i+1] == '&' && src[i+2] >= '1' && src[i+2] <= '6' {
				i += 2
			} else {
				redirect = true
			}
		case ps && c == '\'':
			beginWord()
			current.quoted = current.quoted || word.Len() == 0 && !current.variable
			current.expression = current.expression || current.quoted
			end, ok := scanSingleQuoted(src, i, &word)
			if !ok {
				reason = "syntax-error"
				break
			}
			i = end
		case c == '"':
			beginWord()
			current.quoted = current.quoted || word.Len() == 0 && !current.variable
			current.expression = current.expression || current.quoted
			end, literal, scripts, ok := scanDoubleQuoted(src, i, dialect, &word)
			if !ok {
				reason = "syntax-error"
				break
			}
			current.literal = current.literal && literal
			nested = append(nested, scripts...)
			i = end
		case ps && c == '`' || !ps && c == '^':
			if i+1 < len(src) && src[i+1] == '\n' {
				// A line continuation.
				endWord()
				i++
				break
			}
			if i+1 < len(src) {
				beginWord()
				word.WriteByte(src[i+1])
				i++
			}
		case ps && c == '$':
			beginWord()
			if i+1 >= len(src) || strings.IndexByte(" \t\n", src[i+1]) >= 0 {
				word.WriteByte('$')
				break
			}
			leading := current.literal && word.Len() == 0
			current.literal = false
			current.variable = current.variable || leading
			current.expression = current.expression || leading
			switch next := src[i+1]; {
			case next == '(':
				end, ok := block(i + 1)
				if !ok {
					break
				}
				nested = append(nested, src[i+2:end])
				i = end
			case next == '{':
				end := strings.IndexByte(src[i:], '}')
				if end < 0 {
					reason = "syntax-error"
					break
				}
				i += end
			default:
				j := i + 1
				if strings.IndexByte("$?^", src[j]) >= 0 {
					j++
				}
				for j < len(src) && (isNameByte(src[j]) || src[j] == ':') {
					j++
				}
				i = j - 1
			}
			if leading && reason == "" && len(statement.words) == 0 && !statement.invoke {
				if end, ok := assignmentOperator(src, i+1); ok {
					endWord()
					statement.words = append(statement.words, scriptWord{value: "=", literal: true, assign: true})
					i = end
				}
			}
		case ps && c == '@' && !inWord && i+1 < len(src):
			switch next := src[i+1]; {
			case next == '(' || next == '{':
				end, ok := block(i + 1)
				if !ok {
					break
				}
				beginWord()
				current.literal = false
				// An array subexpression holds statements; a hashtable
				// holds keys and values.
				if next == '(' {
					nested = append(nested, src[i+2:end])
				}
				i = end
			case (next == '\'' || next == '"') && i+2 < len(src) && src[i+2] == '\n':
				closing := "\n" + string(next) + "@"
				end := strings.Index(src[i+3:], closing)
				if end < 0 {
					reason = "syntax-error"
					break
				}
				body := src[i+3 : i+3+end]
				beginWord()
				current.quoted = true
				current.expression = true
				current.literal = next == '\'' || !strings.ContainsAny(body, "$`")
				if next == '"' {
					nested = append(nested, subexpressions(body)...)
				}
				word.WriteString(body)
				i += 3 + end + len(closing) - 1
			case isNameByte(next):
				// Splatting passes a variable's elements as arguments.
				beginWord()
				current.literal = false
				j := i + 1
				for j < len(src) && isNameByte(src[j]) {
					j++
				}
				i = j - 1
			default:
				beginWord()
				word.WriteByte(c)
			}
		case ps && (c == '(' || c == '{'):
			end, ok := block(i)
			if !ok {
				break
			}
			beginWord()
			current.literal = false
			// A grouping or a script block holds statements, and so may a
			// method call's arguments or a cast's operand ([void](...)); an
			// argument list that is only strings and variables projects to
			// nothing.
			nested = append(nested, src[i+1:end])
			i = end
		case ps && c == '[' && !inWord:
			// A type literal, as in [IO.File]::Delete(...).
			end, ok := block(i)
			if !ok {
				break
			}
			beginWord()
			current.literal = false
			current.expression = true
			i = end
		case ps && (c == ')' || c == '}'):
			reason = "syntax-error"
		case !ps && c == '%':
			beginWord()
			if end := strings.IndexByte(src[i+1:], '%'); end > 0 && isCmdVariable(src[i+1:i+1+end]) {
				current.literal = false
				i += end + 1
				break
			}
			word.WriteByte(c)
		default:
			beginWord()
			word.WriteByte(c)
		}
	}
	if reason != "" {
		return nil, nil, reason
	}
	endStatement()
	return statements, nested, ""
}

// typographicQuotes are the curly quotes PowerShell reads as straight ones,
// so git receives “--force” as --force.
var typographicQuotes = strings.NewReplacer("\u2018", "'", "\u2019", "'", "\u201a", "'", "\u201b", "'", "\u201c", `"`, "\u201d", `"`, "\u201e", `"`)

func isNameByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
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

// scanSingleQuoted reads a PowerShell single-quoted string at src[i], in
// which a doubled quote is a quote and nothing else is special.
func scanSingleQuoted(src string, i int, word *strings.Builder) (int, bool) {
	for j := i + 1; j < len(src); j++ {
		if src[j] != '\'' {
			word.WriteByte(src[j])
			continue
		}
		if j+1 < len(src) && src[j+1] == '\'' {
			word.WriteByte('\'')
			j++
			continue
		}
		return j, true
	}
	return 0, false
}

// powerShellEscapes are the backtick escapes PowerShell expands in double
// quotes; any other escaped character stands for itself.
var powerShellEscapes = map[byte]byte{'0': 0, 'a': 7, 'b': 8, 'e': 27, 'f': 12, 'n': '\n', 'r': '\r', 't': '\t', 'v': 11}

// scanDoubleQuoted reads a double-quoted string at src[i]. In PowerShell a
// variable or a $( ) subexpression makes it non-literal, and the
// subexpressions' scripts are returned so their calls are projected. cmd
// quotes have no escapes, and %NAME% expands inside them.
func scanDoubleQuoted(src string, i int, dialect scriptDialect, word *strings.Builder) (end int, literal bool, scripts []string, ok bool) {
	literal = true
	for j := i + 1; j < len(src); j++ {
		c := src[j]
		switch {
		case c == '"':
			if dialect == dialectPowerShell && j+1 < len(src) && src[j+1] == '"' {
				word.WriteByte('"')
				j++
				continue
			}
			return j, literal, scripts, true
		case dialect == dialectCmd:
			if c == '%' {
				if close := strings.IndexByte(src[j+1:], '%'); close > 0 && isCmdVariable(src[j+1:j+1+close]) {
					literal = false
				}
			}
			word.WriteByte(c)
		case c == '`':
			if j+1 >= len(src) {
				return 0, false, nil, false
			}
			j++
			if escaped, special := powerShellEscapes[src[j]]; special {
				word.WriteByte(escaped)
			} else if src[j] != '\n' {
				word.WriteByte(src[j])
			}
		case c == '$' && j+1 < len(src) && src[j+1] == '(':
			close := matchBracket(src, j+1)
			if close < 0 {
				return 0, false, nil, false
			}
			literal = false
			scripts = append(scripts, src[j+2:close])
			j = close
		case c == '$' && j+1 < len(src) && (isNameByte(src[j+1]) || strings.IndexByte("{$?^:", src[j+1]) >= 0):
			literal = false
			word.WriteByte(c)
		default:
			word.WriteByte(c)
		}
	}
	return 0, false, nil, false
}

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

// matchBracket returns the index of the bracket that closes the one at
// src[open], skipping PowerShell strings, escapes and comments; -1 when none
// does and -2 when brackets nest too deeply.
func matchBracket(src string, open int) int {
	closers := map[byte]byte{'(': ')', '{': '}', '[': ']'}
	stack := []byte{closers[src[open]]}
	for i := open + 1; i < len(src); i++ {
		switch c := src[i]; c {
		case '`':
			i++
		case '\'', '"':
			i = closingQuote(src, i)
		case '#':
			if strings.IndexByte(" \t\n;({", src[i-1]) >= 0 {
				if end := strings.IndexByte(src[i:], '\n'); end >= 0 {
					i += end
				} else {
					i = len(src)
				}
			}
		case '<':
			if i+1 < len(src) && src[i+1] == '#' {
				if end := strings.Index(src[i+2:], "#>"); end >= 0 {
					i += end + 3
				} else {
					i = len(src)
				}
			}
		case '(', '{', '[':
			if len(stack) >= maxSyntaxDepth {
				return -2
			}
			stack = append(stack, closers[c])
		case ')', '}', ']':
			if c != stack[len(stack)-1] {
				return -1
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return i
			}
		}
	}
	return -1
}

// closingQuote returns the index of the quote that closes the string opened
// at src[i], or len(src) when none does.
func closingQuote(src string, i int) int {
	quote := src[i]
	for j := i + 1; j < len(src); j++ {
		switch {
		case quote == '"' && src[j] == '`':
			j++
		case src[j] == quote && j+1 < len(src) && src[j+1] == quote:
			j++
		case src[j] == quote:
			return j
		}
	}
	return len(src)
}
