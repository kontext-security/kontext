package shellprojection

import (
	"slices"
	"strings"

	"github.com/kontext-security/kontext/internal/cedareval"
)

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
	cast       bool // starts with a type literal, as in [string]$x
	// elided is set when the value leaves out part of the word: an
	// unquoted variable, subexpression, splat or grouping. A quoted string
	// keeps its text, $ included.
	elided bool
}

type scriptStatement struct {
	words []scriptWord
	// invoke is set by the & call operator: the word after it names the
	// program even when it is a string or a variable. invokeAt counts the
	// words before it, an assignment, return, throw, exit or foreach's in.
	invoke   bool
	invokeAt int
	// verbatim is set by PowerShell's --% token, after which the words are
	// passed on with cmd-style expansion this tokenizer does not model.
	verbatim bool
	// piped is set for a statement that reads the previous one's output.
	piped bool
}

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

// webCmdletWords returns the arguments of a web cmdlet call: a computed word
// keeps a literal parameter name before its colon (-TimeoutSec:$t), with
// computedValue for the rest, so the value stays with its parameter; any other
// computed word is empty. In a script that touches $PSDefaultParameterValues
// the call is marked, since defaults can supply what it leaves out.
func webCmdletWords(words []scriptWord, w walk) []string {
	args := make([]string, len(words), len(words)+1)
	for i, word := range words {
		switch name := powerShellDash(word.value); {
		case word.literal && word.quoted && name != "" && name[0] == '-':
			args[i] = quotedValue + word.value
		case word.literal:
			args[i] = word.value
		case !word.quoted && parameterToken(name) && strings.HasSuffix(name, ":"):
			args[i] = word.value + computedValue
		}
	}
	if w.cmdletDefaults {
		args = append(args, cmdletDefaults)
	}
	return args
}

// scriptSource returns a call's values with each computed word written as
// its source text instead of "", lined up with its words; values past the
// words (a marker webCmdletWords adds) stay as they are. A word whose value
// leaves out part of it stays "": what remains is not its source.
func scriptSource(values []string, words []scriptWord) []string {
	source := slices.Clone(values)
	for i := 1; i < len(source) && i < len(words); i++ {
		if source[i] == "" && !words[i].literal && !words[i].elided {
			source[i] = words[i].value
		}
	}
	return source
}

// webCmdletAlias returns the arguments of curl or wget, named bare, as
// Invoke-WebRequest's when Windows PowerShell 5.1, where both are its
// aliases, would bind them; PowerShell 7 runs the program. A path or an .exe
// suffix always names the program.
func webCmdletAlias(command string, args []string) ([]string, bool) {
	switch strings.ToLower(command) {
	case "curl", "wget":
		return windowsPowerShellWebArgs(args)
	}
	return nil, false
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
		// PowerShell binds each word of a cmdlet call as one argument, and
		// the web cmdlets take input from the pipeline as the request body.
		// The check reads the word as written: .\irm.cmd is a file.
		cmdlet := dialect == dialectPowerShell && len(values) > 0 && webCmdletCall(words[0].value)
		cw := walk{depth: w.depth, oneArgumentEach: cmdlet, stdin: cmdlet && statement.piped && index > 0, cmdlet: cmdlet}
		if cmdlet {
			values = append(values[:1], webCmdletWords(words[1:], w)...)
		}
		cw.source = scriptSource(values, words)
		projections = append(projections, classify(values, complete, cw, helpAllowed && direct)...)
		if dialect != dialectPowerShell || len(values) == 0 {
			continue
		}
		if args, ok := webCmdletAlias(words[0].value, webCmdletWords(words[1:], walk{})); ok {
			// Which runs depends on the PowerShell version, so a policy
			// sees both: the program above and the cmdlet here.
			if w.cmdletDefaults {
				args = append(args, cmdletDefaults)
			}
			aw := walk{depth: w.depth, oneArgumentEach: true, stdin: statement.piped && index > 0, cmdlet: true}
			if source, ok := webCmdletAlias(words[0].value, scriptSource(webCmdletWords(words, walk{}), words)[1:]); ok {
				if w.cmdletDefaults {
					source = append(source, cmdletDefaults)
				}
				aw.source = append([]string{"invoke-webrequest"}, source...)
			}
			projections = append(projections, classify(append([]string{"invoke-webrequest"}, args...), complete, aw, false)...)
		}
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
	if statement.invoke {
		return words[statement.invokeAt:], true
	}
	for {
		// The pipeline after return, throw or exit, after foreach's in
		// ($x in git ...), and after $x = git ..., $a, $b = git ... and chains
		// of them is the call.
		if len(words) > 0 && isFlowKeyword(words[0]) {
			words = words[1:]
		} else if len(words) >= 2 && words[0].variable && words[1].literal && !words[1].quoted && strings.EqualFold(words[1].value, "in") {
			words = words[2:]
		} else if len(words) >= 2 && words[0].variable && words[1].assign {
			words = words[2:]
		} else if k := multipleAssignment(words); k > 0 {
			words = words[k+1:]
		} else {
			break
		}
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
	if words[0].literal && !words[0].quoted && isNumberExpression(words[0].value) {
		// A number, a range or an array of numbers is a value, as in
		// exit 1 or @{ Count = 2 }; 7z is still a command.
		return nil, false
	}
	if words[0].literal && powerShellKeywords[strings.ToLower(words[0].value)] {
		// A construct that ends in a block needs no ; before the next
		// statement, as in if ($x) { } git push, so the first plain word
		// after one of its blocks starts a statement of its own.
		if rest := afterConstruct(words); len(rest) > 0 {
			return callWords(scriptStatement{words: rest}, dialect)
		}
		return nil, false
	}
	return words, true
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
			case ps && !inWord && !statement.invoke && assignmentPrefix(statement.words):
				// The call operator, at the start of a pipeline: of the
				// statement, after an assignment, after return, throw or exit,
				// or after foreach's in.
				statement.invoke = true
				statement.invokeAt = len(statement.words)
			default:
				endWord()
				if ps && !statement.invoke && endsConstruct(statement.words) {
					// A construct that ends in a block needs no ; before the
					// next statement, so an & after it is that statement's call
					// operator, as in if ($x) { } & 'C:\...\git.exe' push.
					endStatement()
					statement.invoke = true
					break
				}
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
			leading := (current.literal || current.cast) && word.Len() == 0
			current.literal = false
			current.elided = true
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
			if leading && reason == "" && !statement.invoke && assignmentPrefix(statement.words) {
				// The target may be a member or an element, as in
				// $x.Prop=git ... or $x[0]=git ....
				if end, target, ok := assignmentTarget(src, i+1); ok {
					nested = append(nested, target...)
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
				current.literal, current.elided = false, true
				// An array subexpression holds statements; a hashtable
				// holds keys and values, and each value is a statement.
				if next == '(' {
					nested = append(nested, src[i+2:end])
				} else {
					nested = append(nested, hashtableStatements(src[i+2:end])...)
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
				current.literal, current.elided = false, true
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
			current.literal, current.elided = false, true
			// A grouping or a script block holds statements, and so may a
			// method call's arguments or a cast's operand ([void](...)); an
			// argument list that is only strings and variables projects to
			// nothing.
			nested = append(nested, src[i+1:end])
			i = end
		case ps && c == '[' && !inWord:
			// A type literal, as in [IO.File]::Delete(...), or an attribute,
			// whose arguments may hold a script block, as in
			// [ValidateScript({...})].
			end, ok := block(i)
			if !ok {
				break
			}
			if open := strings.IndexByte(src[i:end], '('); open > 0 {
				nested = append(nested, scriptBlocks(src[i+open:end])...)
			}
			beginWord()
			current.literal = false
			current.expression = true
			current.cast = true
			i = end
			if strings.HasPrefix(src[i+1:], "::") && !statement.invoke && assignmentPrefix(statement.words) {
				// A static member is a target too, as in [Console]::Title=git ....
				if end, target, ok := assignmentTarget(src, i+1); ok {
					nested = append(nested, target...)
					current.variable = true
					endWord()
					statement.words = append(statement.words, scriptWord{value: "=", literal: true, assign: true})
					i = end
				}
			} else if i+2 < len(src) && src[i+1] == '@' && src[i+2] == '{' {
				// A cast hashtable, as in [ordered]@{...} or
				// [pscustomobject]@{...}.
				end, ok := block(i + 2)
				if !ok {
					break
				}
				nested = append(nested, hashtableStatements(src[i+3:end])...)
				current.cast = false
				i = end
			}
		case ps && (c == ')' || c == '}'):
			reason = "syntax-error"
		case ps && c == ',' && inWord && current.variable:
			// A comma after a variable continues a list, as in $a,$b = ...
			endWord()
			statement.words = append(statement.words, scriptWord{value: ",", literal: true})
		case !ps && (c == '%' || c == '!'):
			// !NAME! expands under delayed expansion, which /v:on or the
			// DelayedExpansion registry value turn on, so it is read as a
			// variable either way.
			beginWord()
			if end := strings.IndexByte(src[i+1:], c); end > 0 && isCmdVariable(src[i+1:i+1+end]) {
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

func isNameByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
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

// scanDoubleQuoted reads a double-quoted string at src[i]. In PowerShell a
// variable or a $( ) subexpression makes it non-literal, and the
// subexpressions' scripts are returned so their calls are projected. cmd
// quotes have no escapes, and %NAME% and !NAME! expand inside them.
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
			if c == '%' || c == '!' {
				if close := strings.IndexByte(src[j+1:], c); close > 0 && isCmdVariable(src[j+1:j+1+close]) {
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
