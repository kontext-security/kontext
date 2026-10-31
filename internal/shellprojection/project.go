package shellprojection

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/kontext-security/kontext/internal/cedareval"
	"mvdan.cc/sh/v3/syntax"
)

const (
	maxCommandBytes = 64 * 1024
	maxSyntaxNodes  = 10_000
	maxSyntaxDepth  = 128
	// maxScriptDepth bounds recursion into `bash -c` and `eval` scripts so a
	// nested script chain cannot make projection unbounded.
	maxScriptDepth = 4

	// FactRouteUnrecognized marks a git, gh or curl invocation whose GitHub
	// effect could not be classified: an alias definition, an unknown git
	// global, an unknown gh command, or non-literal arguments. It is only
	// emitted once the program is known to be one of those three, so a typo
	// in an unrelated command or a dynamic program never trips a GitHub
	// preset; those carry shell/parse-complete=false alone.
	FactRouteUnrecognized = "github/route=unrecognized"
	// FactParseIncomplete mirrors ParseComplete=false as a fact so policies
	// can match it alongside the other facts.
	FactParseIncomplete = "shell/parse-complete=false"
	// FeatureParseError marks a command the parser could not turn into calls.
	FeatureParseError = "shell/parse-error"
)

var shortFlagCluster = regexp.MustCompile(`^-[A-Za-z0-9]{2,}$`)

// Project parses shell syntax without expanding or executing it. It never
// fails: a command that cannot be parsed becomes an incomplete projection
// carrying the shell/parse-error feature so policy decides what to do with
// it, instead of a projection error denying every hook under enforce.
func Project(command string) []cedareval.ShellProjectionV2 {
	return project(command, walk{})
}

// walk carries what a nested script inherits from the command around it.
type walk struct {
	depth         int
	stdin         bool
	argumentFacts []string
	stdinFacts    []string
	// stateful is set inside a script whose caller may have changed how
	// words expand (see project), so no word there is provably one argument.
	stateful bool
	// oneArgumentEach is set while classifying a call whose every word
	// expands to exactly one argument: a computed word is then quoted, so
	// it cannot split into extra options (see classifyCurl).
	oneArgumentEach bool
	// cmdlet is set while classifying a PowerShell call that runs a web
	// cmdlet (see webCmdletCall); elsewhere irm or iwr is any program.
	cmdlet bool
	// cmdletDefaults is set in a PowerShell script that touches
	// $PSDefaultParameterValues, which can change any cmdlet's parameters.
	cmdletDefaults bool
	// source is the call's words as classify receives them, with each word
	// the shell computes written as its source text instead of "": the
	// literal host of a URL with a computed part still names the provider.
	source []string
}

func project(command string, w walk) []cedareval.ShellProjectionV2 {
	if len(command) > maxCommandBytes {
		return []cedareval.ShellProjectionV2{parseFailure("command-too-large", command)}
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "command")
	if err != nil {
		return []cedareval.ShellProjectionV2{parseFailure("syntax-error", command)}
	}

	calls := make([]*syntax.CallExpr, 0, 4)
	callText := map[*syntax.CallExpr]string{}
	stdinCalls := map[*syntax.CallExpr]bool{}
	stdinOverrides := map[*syntax.CallExpr]bool{}
	stdinFacts := map[*syntax.CallExpr][]string{}
	stdinHistory := map[*syntax.CallExpr][]string{}
	nodes, nesting := 0, 0
	tooComplex := false
	// A statement that can change how a later word expands (a nameref from
	// declare -n makes a quoted "$H" several arguments; eval, source, trap
	// and builtin/command dispatch can make one) is recorded by offset. A
	// call that one starts before the end of is stateful, and with a loop
	// or function every call is, since a later statement can run first on
	// another pass.
	var stateChanges []int
	loops := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if node == nil {
			nesting--
			return true
		}
		nodes++
		nesting++
		if nodes > maxSyntaxNodes || nesting > maxSyntaxDepth {
			tooComplex = true
			return false
		}
		switch node := node.(type) {
		case *syntax.BinaryCmd:
			if node.Op == syntax.Pipe || node.Op == syntax.PipeAll {
				pipeFacts := literalEmitterFactsAtDepth(node.X, command, 0, w.argumentFacts)
				replacesInput := literalOutputOnly(node.X)
				syntax.Walk(node.Y, func(child syntax.Node) bool {
					if call, ok := child.(*syntax.CallExpr); ok {
						stdinCalls[call] = true
						if replacesInput {
							stdinFacts[call] = slices.Clone(pipeFacts)
							stdinOverrides[call] = true // This producer does not forward inherited stdin.
						} else {
							stdinFacts[call] = append(stdinFacts[call], pipeFacts...)
						}
					}
					return true
				})
			}
		case *syntax.Stmt:
			if call, ok := node.Cmd.(*syntax.CallExpr); ok {
				callText[call] = command[call.Pos().Offset():call.End().Offset()]
			}
			for _, redir := range node.Redirs {
				if node.Cmd == nil {
					continue
				}
				if redir.N != nil && redir.N.Value != "0" {
					continue
				}
				switch redir.Op {
				case syntax.RdrIn, syntax.RdrInOut, syntax.DplIn, syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
					unknownDescriptor := false
					if redir.Op == syntax.DplIn {
						source, literal := literalWord(redir.Word)
						if literal && source == "0" {
							continue // Duplicating stdin leaves its current source intact.
						}
						unknownDescriptor = !literal || source != "-"
					}
					var heredocFacts []string
					if redir.Hdoc != nil {
						heredocFacts = providerHostFacts(command[redir.Hdoc.Pos().Offset():redir.Hdoc.End().Offset()])
					} else if redir.Op == syntax.WordHdoc && redir.Word != nil {
						text, _ := literalWord(redir.Word)
						heredocFacts = providerHostFacts(text + " " + command[redir.Word.Pos().Offset():redir.Word.End().Offset()])
					}
					if redir.Word != nil {
						syntax.Walk(redir.Word, func(child syntax.Node) bool {
							if input, ok := child.(*syntax.ProcSubst); ok {
								if input.Op == syntax.CmdIn {
									heredocFacts = append(heredocFacts, literalEmitterFactsAtDepth(input, command, 0, w.argumentFacts)...)
								}
								return false
							}
							return true
						})
					}
					syntax.Walk(node.Cmd, func(child syntax.Node) bool {
						if call, ok := child.(*syntax.CallExpr); ok {
							stdinCalls[call] = true
							if unknownDescriptor {
								// A saved descriptor may restore an earlier source. Without a
								// descriptor graph, retain its possible local and inherited facts.
								stdinFacts[call] = sortedUnique(append(stdinFacts[call], stdinHistory[call]...))
								stdinOverrides[call] = false
							} else {
								stdinHistory[call] = sortedUnique(append(stdinHistory[call], stdinFacts[call]...))
								stdinOverrides[call] = true
								stdinFacts[call] = slices.Clone(heredocFacts)
							}
						}
						return true
					})
				}
			}
		case *syntax.Assign:
			// BASH_ENV and ENV name a startup file a nested shell runs first.
			if node.Name != nil && (node.Name.Value == "BASH_ENV" || node.Name.Value == "ENV") {
				stateChanges = append(stateChanges, int(node.Pos().Offset()))
			}
		case *syntax.CallExpr:
			for _, arg := range node.Args {
				if word, _ := literalWord(arg); strings.HasPrefix(word, "BASH_ENV=") || strings.HasPrefix(word, "ENV=") {
					stateChanges = append(stateChanges, int(node.Pos().Offset()))
				}
			}
			if len(node.Args) > 0 {
				calls = append(calls, node)
				if first, ok := literalWord(node.Args[0]); !ok || stateChangingCommands[first] {
					stateChanges = append(stateChanges, int(node.Pos().Offset()))
				}
			}
		case *syntax.DeclClause:
			// export and readonly cannot make a nameref.
			if node.Variant == nil || node.Variant.Value != "export" && node.Variant.Value != "readonly" {
				stateChanges = append(stateChanges, int(node.Pos().Offset()))
			}
		case *syntax.WhileClause, *syntax.ForClause, *syntax.FuncDecl:
			loops = true
		}
		return true
	})
	if tooComplex {
		return []cedareval.ShellProjectionV2{parseFailure("syntax-too-complex", command)}
	}
	sort.SliceStable(calls, func(i, j int) bool { return calls[i].Pos().Offset() < calls[j].Pos().Offset() })

	// A help call counts as a read only when it is the whole command:
	// anything else could define an alias that changes what gh receives
	// (`alias gh='gh -dn'`), however it is spelled.
	helpAllowed := w.depth == 0 && len(calls) == 1 && singlePlainCall(file)
	projections := make([]cedareval.ShellProjectionV2, 0, len(calls))
	for _, call := range calls {
		words, complete := literalWords(call.Args)
		unwrapped, wrapperComplete, _, _ := unwrap(words, true)
		httpie, newHTTPClient := false, false
		if len(unwrapped) > 0 {
			program := strings.TrimSuffix(strings.ToLower(filepath.Base(unwrapped[0])), ".exe")
			httpie = program == "http" || program == "https"
			newHTTPClient = httpie || program == "wget"
		}
		// An authorization value cannot add argv when quoted. Keep its
		// literal option/header name even when the token is computed.
		for i, word := range call.Args {
			if !newHTTPClient || words[i] != "" || !oneArgument(word) {
				continue
			}
			var prefix strings.Builder
			var appendPrefix func([]syntax.WordPart) bool
			appendPrefix = func(parts []syntax.WordPart) bool {
				for _, part := range parts {
					switch part := part.(type) {
					case *syntax.Lit:
						prefix.WriteString(part.Value)
					case *syntax.SglQuoted:
						prefix.WriteString(part.Value)
					case *syntax.DblQuoted:
						if !appendPrefix(part.Parts) {
							return false
						}
					default:
						return false
					}
				}
				return true
			}
			appendPrefix(word.Parts)
			text := prefix.String()
			if !httpie {
				for _, option := range []string{"-qO", "-O", "-o", "-T", "-t", "-U"} {
					if strings.HasPrefix(text, option) {
						words[i] = text + "computed-value"
						break
					}
				}
			}
			if strings.HasPrefix(text, "--") {
				if option, _, attached := strings.Cut(text, "="); attached {
					words[i] = option + "=computed-value"
				}
			}
			for _, option := range []string{"--body-data=", "--post-data="} {
				if strings.HasPrefix(text, option) {
					words[i] = option + "@computed-body"
				}
			}
			for _, option := range []string{"--body-file=", "--post-file=", "--user=", "--password=", "--http-user=", "--http-password="} {
				if strings.HasPrefix(text, option) {
					words[i] = option + "computed-value"
				}
			}
			if strings.HasPrefix(strings.ToLower(text), "--header=") && strings.Contains(text, ":") || strings.HasPrefix(strings.ToLower(text), "authorization:") {
				words[i] = text
			}
			if httpie {
				if item := httpieItem.FindStringSubmatch(text); item != nil {
					switch item[2] {
					case "=", ":=":
						words[i] = item[1] + item[2] + "@computed-field"
					case ":":
						words[i] = item[1] + ":computed-header"
					case "==":
						words[i] = item[1] + "==computed-field"
					}
				}
			}
		}
		// No wrapper either: env, sudo and launchers can rewrite argv.
		direct := len(words) > 0 && words[0] == "gh"
		cw := w
		cw.stdin = w.stdin || stdinCalls[call]
		cw.stdinFacts = append(slices.Clone(w.stdinFacts), stdinFacts[call]...)
		if stdinOverrides[call] {
			cw.stdinFacts = slices.Clone(stdinFacts[call])
		}
		// The earliest change by offset (Walk visits redirections after the
		// command), up to the call's end: a ${ cmd; } inside its own words
		// runs before they expand.
		cw.stateful = w.stateful || len(stateChanges) > 0 && (loops || slices.Min(stateChanges) < int(call.End().Offset()))
		cw.oneArgumentEach = !cw.stateful && !slices.ContainsFunc(call.Args, func(word *syntax.Word) bool { return !oneArgument(word) })
		// Retain visible host fragments in positional shell arguments even
		// when expansion prevents literalWords from resolving the whole word.
		if len(unwrapped) > 0 {
			switch strings.TrimSuffix(strings.ToLower(filepath.Base(unwrapped[0])), ".exe") {
			case "bash", "sh", "zsh", "dash", "ksh":
				rawWords := rawCallWords(call, command)
				if len(rawWords) > 0 {
					if i, commandFlag := shellCommandIndex(rawWords[1:]); commandFlag && i+2 < len(rawWords) {
						cw.argumentFacts = append(slices.Clone(cw.argumentFacts), providerHostFacts(strings.Join(rawWords[i+2:], " "))...)
					}
				}
			}
		}
		cw.source = sourceWords(call, command)
		classified := classify(words, complete, cw, helpAllowed && direct)
		// A computed URL may still name a provider literally. Retain that
		// hint for the new clients when no route could be established.
		rawProgram, clientProgram := "", ""
		if len(unwrapped) > 0 {
			rawProgram = unwrapped[0]
			clientProgram = strings.TrimSuffix(strings.ToLower(filepath.Base(rawProgram)), ".exe")
		}
		for i := range classified {
			if (clientProgram == "wget" || clientProgram == "http" || clientProgram == "https") && !classified[i].ParseComplete && !slices.Contains(classified[i].Facts, "github/route=catalogued") && !slices.Contains(classified[i].Facts, FactDatabricksRouteCatalogued) {
				rawWords := rawCallWords(call, command)
				if len(rawWords) > 0 {
					var converted []string
					if clientProgram == "wget" {
						converted = wgetArgs(rawWords[1:])
					} else {
						converted, _ = httpieArgs(clientProgram, rawWords[1:], cw.stdin)
					}
					facts, targetsResolved := httpClientTargetFacts(converted)
					classified[i].Facts = sortedUnique(append(classified[i].Facts, facts...))
					if !wrapperComplete || !cw.oneArgumentEach || !targetsResolved {
						classified[i].Facts = sortedUnique(append(classified[i].Facts, cw.argumentFacts...))
					}
				}
			}
			if slices.Contains(classified[i].Features, "nested-script") {
				continue
			}
			// Other interpreter forms deliberately remain unrecognized.
			jsonFormatter := false
			if len(unwrapped) > 0 && standardUtilityPath(rawProgram) && strings.HasPrefix(clientProgram, "python") {
				jsonFormatter = len(unwrapped) >= 3 && unwrapped[1] == "-m" && unwrapped[2] == "json.tool"
			}
			if !jsonFormatter && !localUtility(rawProgram) && (opaqueProgram(classified[i].Program) || slices.Contains(classified[i].Features, "opaque-script")) {
				text := callText[call] + " " + strings.Join(words, " ")
				if !slices.Contains(classified[i].Facts, "github/route=catalogued") && !slices.Contains(classified[i].Facts, FactDatabricksRouteCatalogued) {
					facts := append(providerHostFacts(text), cw.argumentFacts...)
					facts = append(facts, cw.stdinFacts...)
					if len(facts) > 0 {
						classified[i] = projection(classified[i].Program, append(classified[i].Facts, facts...), classified[i].Features, false)
					}
				}
			}
		}
		projections = append(projections, classified...)
	}
	if len(projections) == 0 {
		projections = append(projections, projection("unknown", nil, []string{"empty-command"}, false))
	}
	return projections
}

// rawCallWords preserves visible syntax where expansion hides a whole word.
func rawCallWords(call *syntax.CallExpr, command string) []string {
	words, _, _, _ := unwrap(sourceWords(call, command), true)
	return words
}

// sourceWords returns a call's words as literalWords does, with each word
// the shell computes written as its source text instead of "".
func sourceWords(call *syntax.CallExpr, command string) []string {
	words, _ := literalWords(call.Args)
	for i, arg := range call.Args {
		if _, literal := literalWord(arg); !literal {
			words[i] = command[arg.Pos().Offset():arg.End().Offset()]
		}
	}
	return words
}

// alignedSource returns the source words that line up with words, which
// unwrapping may have shortened from the front, or nil when they do not:
// every literal word must be the same in both.
func alignedSource(source, words []string) []string {
	offset := len(source) - len(words)
	if source == nil || offset < 0 {
		return nil
	}
	source = source[offset:]
	for i, word := range words {
		if word != "" && word != source[i] {
			return nil
		}
	}
	return source
}

// Direct printf/echo output is independent of stdin. Compound commands
// and unknown descriptors remain conservative because they can restore pipes.
func literalOutputOnly(node syntax.Node) bool {
	stmt, ok := node.(*syntax.Stmt)
	if !ok {
		return false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok {
		return false
	}
	argv, _ := literalWords(call.Args)
	argv, complete, _, ok := unwrap(argv, true)
	if !ok || !complete || len(argv) == 0 {
		return false
	}
	program := strings.TrimSuffix(strings.ToLower(filepath.Base(argv[0])), ".exe")
	return program == "printf" || program == "echo"
}

func stdoutRedirectedAway(redirs []*syntax.Redirect) bool {
	away := false
	for _, redir := range redirs {
		both := redir.Op == syntax.RdrAll || redir.Op == syntax.AppAll
		if redir.N != nil && redir.N.Value != "1" && !both || redir.Word == nil {
			continue
		}
		target, literal := literalWord(redir.Word)
		switch redir.Op {
		case syntax.DplOut:
			if literal && target == "1" {
				continue
			}
			if literal && target == "-" {
				away = true
				continue
			}
			if _, err := strconv.Atoi(strings.TrimSuffix(target, "-")); err == nil {
				away = false // A saved descriptor may restore the pipe.
				continue
			}
			fallthrough
		case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll:
			away = literal && target != "" && (target == "/dev/null" || !strings.HasPrefix(target, "/dev/") && !strings.HasPrefix(target, "/proc/"))
		}
	}
	return away
}

// Literal code emitters pass source into an interpreter. A provider response
// piped into a formatter carries data, not the request URL as executable source.
func literalEmitterFactsAtDepth(node syntax.Node, command string, depth int, argumentFacts []string) []string {
	if depth >= maxScriptDepth {
		return providerHostFacts(command)
	}
	var facts []string
	syntax.Walk(node, func(child syntax.Node) bool {
		if stmt, ok := child.(*syntax.Stmt); ok && literalOutputOnly(stmt) && stdoutRedirectedAway(stmt.Redirs) {
			return false
		}
		if call, ok := child.(*syntax.CallExpr); ok {
			words, complete := literalWords(call.Args)
			words, _, _, _ = unwrap(words, true)
			program := ""
			if len(words) > 0 {
				program = strings.TrimSuffix(strings.ToLower(filepath.Base(words[0])), ".exe")
			}
			if program == "printf" || program == "echo" {
				facts = append(facts, providerHostFacts(command[call.Pos().Offset():call.End().Offset()]+" "+strings.Join(words[1:], " "))...)
				if !complete {
					facts = append(facts, argumentFacts...)
				}
			}
			if program == "bash" || program == "sh" || program == "zsh" || program == "dash" || program == "ksh" {
				args := words[1:]
				i, commandFlag := shellCommandIndex(args)
				if commandFlag && i < len(args) {
					script := args[i]
					if len(script) > maxCommandBytes {
						facts = append(facts, providerHostFacts(script)...)
					} else if nested, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(script), "emitter"); err == nil {
						positionalFacts := slices.Clone(argumentFacts)
						// Raw syntax retains literal hosts inside computed arguments.
						rawWords := rawCallWords(call, command)
						if len(rawWords) > i+2 {
							positionalFacts = append(positionalFacts, providerHostFacts(strings.Join(rawWords[i+2:], " "))...)
						}
						facts = append(facts, literalEmitterFactsAtDepth(nested, script, depth+1, positionalFacts)...)
					}
				}
			}
		}
		return true
	})
	return facts
}

// singlePlainCall reports a script that is one simple command with no
// variable assignments (`BASH_ALIASES[gh]=…` defines an alias too).
// stateChangingCommands can change how a later word expands: declare and
// its kin make namerefs, eval and source run code that can, trap runs it
// before later commands, and builtin, command and enable can reach them.
var stateChangingCommands = words("declare", "typeset", "local", "eval", "source", ".", "trap", "builtin", "command", "enable")

// oneArgument reports a word the shell provably expands to exactly one
// argument: outside quotes a literal with no brace expansion ({a,-X,DELETE})
// and no glob, except the ? of a URL query; inside double quotes anything
// quotedOneArgument accepts.
func oneArgument(word *syntax.Word) bool {
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.SglQuoted:
		case *syntax.Lit:
			text := part.Value
			if scheme := strings.Index(text, "://"); scheme >= 0 {
				// Only the ? of a URL query is exempt; the rest of the word
				// is checked whole.
				text = text[:scheme] + strings.ReplaceAll(text[scheme:], "?", "")
			}
			if strings.ContainsAny(text, "{}*?[") {
				return false
			}
		case *syntax.DblQuoted:
			if !quotedOneArgument(part.Parts) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// quotedOneArgument reports double-quoted parts that stay one argument: only
// an @ list ("$@", "${A[@]}", also inside a default such as
// "${A:-"$@"}"), indirection ("${!ref}") or a name list ("${!prefix@}")
// splits. "$*", "${A[0]}", "${TOKEN:-}" and "${TOKEN:?missing}" do not.
func quotedOneArgument(parts []syntax.WordPart) bool {
	for _, part := range parts {
		switch part := part.(type) {
		// Inside double quotes a single quote is not a quote: in
		// "${A:-'$@'}" the $@ still splits, so a SglQuoted part is not
		// accepted.
		case *syntax.Lit, *syntax.CmdSubst, *syntax.ArithmExp:
		case *syntax.DblQuoted:
			if !quotedOneArgument(part.Parts) {
				return false
			}
		case *syntax.ParamExp:
			index, _ := part.Index.(*syntax.Word)
			if part.Param == nil || part.Param.Value == "@" || index != nil && index.Lit() == "@" ||
				part.Excl || part.Names != 0 || part.NestedParam != nil {
				return false
			}
			var operands []*syntax.Word
			if part.Exp != nil {
				operands = append(operands, part.Exp.Word)
			}
			if part.Repl != nil {
				operands = append(operands, part.Repl.Orig, part.Repl.With)
			}
			for _, operand := range operands {
				if operand != nil && !quotedOneArgument(operand.Parts) {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

func singlePlainCall(file *syntax.File) bool {
	if len(file.Stmts) != 1 {
		return false
	}
	stmt := file.Stmts[0]
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	return ok && len(call.Assigns) == 0 && !stmt.Negated && !stmt.Background && !stmt.Coprocess
}

// programName matches a first word that names a program (a path or a name),
// not shell syntax or padding.
var programName = regexp.MustCompile(`^[A-Za-z0-9_./-]{1,128}$`)

// parseFailure is the projection of a command that cannot be parsed. It keeps
// the program its first word names. A command that mentions Databricks gets
// the strictest Databricks facts: it is known to be Databricks and cannot be
// read, so a padded or broken DROP is not let through (the base tier rule).
func parseFailure(reason, command string) cedareval.ShellProjectionV2 {
	program := "unknown"
	if fields := strings.Fields(command[:min(len(command), 4096)]); len(fields) > 0 && programName.MatchString(fields[0]) {
		program = strings.TrimSuffix(strings.ToLower(filepath.Base(fields[0])), ".exe")
	}
	var facts []string
	facts = append(facts, providerHostFacts(command)...)
	if mentionsDatabricks.MatchString(command) {
		facts = append(facts, databricksWorstFacts()...)
	}
	return projection(program, facts, []string{FeatureParseError, reason}, false)
}

func literalWords(words []*syntax.Word) ([]string, bool) {
	values := make([]string, len(words))
	complete := true
	for i, word := range words {
		value, ok := literalWord(word)
		values[i] = value
		complete = complete && ok
	}
	return values, complete
}

// literalWord returns the value a literal word expands to. Non-literal words
// (expansions, substitutions, ANSI-C quoting) yield "" and false.
func literalWord(word *syntax.Word) (string, bool) {
	var value strings.Builder
	var appendParts func([]syntax.WordPart, bool) bool
	appendParts = func(parts []syntax.WordPart, quoted bool) bool {
		for _, part := range parts {
			switch part := part.(type) {
			case *syntax.Lit:
				value.WriteString(unescape(part.Value, quoted))
			case *syntax.SglQuoted:
				if part.Dollar {
					return false
				}
				value.WriteString(part.Value)
			case *syntax.DblQuoted:
				if part.Dollar || !appendParts(part.Parts, true) {
					return false
				}
			default:
				return false
			}
		}
		return true
	}
	if !appendParts(word.Parts, false) {
		return "", false
	}
	return value.String(), true
}

// unescape removes the backslashes the shell would remove: every escape in an
// unquoted literal, and only the four escapable characters inside double
// quotes. The parser keeps them verbatim, so `\git` would otherwise become a
// program named `\git` and never match.
func unescape(value string, quoted bool) string {
	if !strings.Contains(value, `\`) {
		return value
	}
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch != '\\' || i+1 >= len(value) {
			out.WriteByte(ch)
			continue
		}
		next := value[i+1]
		if next == '\n' {
			i++
			continue
		}
		if quoted && !strings.ContainsRune("$`\"\\", rune(next)) {
			out.WriteByte(ch)
			continue
		}
		out.WriteByte(next)
		i++
	}
	return out.String()
}

func classify(words []string, complete bool, w walk, helpAllowed bool) []cedareval.ShellProjectionV2 {
	// The words' own completeness and the wrappers' are kept apart: curl
	// reads a computed header as opaque, but not stdin arguments from xargs.
	wordsComplete := complete
	words, wrapperComplete, wrapper, ok := unwrap(words, true)
	complete = wordsComplete && wrapperComplete
	if !ok {
		return single(projection(wrapper, nil, []string{"unrecognized-wrapper-arguments"}, false))
	}
	if len(words) == 0 || words[0] == "" {
		return single(projection("dynamic", nil, []string{"dynamic-program"}, false))
	}
	if launched, launchedComplete, ok := unwrapPackageLauncher(words, complete); ok {
		words, complete = launched, launchedComplete
	}
	// Case-insensitive file systems (macOS, Windows) run ACLI as acli.
	program := strings.TrimSuffix(strings.ToLower(filepath.Base(words[0])), ".exe")
	args := words[1:]
	var sourceArgs []string
	if source := alignedSource(w.source, words); source != nil {
		sourceArgs = source[1:]
	}
	if w.cmdlet && webCmdlet(program) {
		return single(classifyHTTPClient(program, args, sourceArgs, complete && w.oneArgumentEach, !wordsComplete && wrapperComplete && w.oneArgumentEach, w.stdin))
	}
	switch program {
	case "git":
		return single(classifyGit(args, complete))
	case "gh":
		return single(classifyGH(args, complete, helpAllowed))
	case "curl":
		return single(classifyCurl(args, sourceArgs, complete, !wordsComplete && wrapperComplete && w.oneArgumentEach, true))
	case "wget", "http", "https":
		return single(classifyHTTPClient(program, args, sourceArgs, complete && w.oneArgumentEach, !wordsComplete && wrapperComplete && w.oneArgumentEach, w.stdin))
	case "acli":
		return single(acliCLI.classify(args, complete))
	case "jira":
		return single(jiraCLI.classify(args, complete))
	case "hs":
		return single(hsCLI.classify(args, complete))
	case "forge":
		return single(forgeCLI.classify(args, complete))
	case "databricks":
		return single(classifyDatabricks(args, complete, wrapperComplete && w.oneArgumentEach))
	case "bash", "sh", "zsh", "dash", "ksh":
		return classifyShell(program, args, complete, w)
	case "pwsh", "powershell":
		return classifyPowerShellHost(program, args, complete, w)
	case "cmd":
		return classifyCmd(args, complete, w)
	case "eval":
		return classifyEval(args, complete, w)
	default:
		var features []string
		if strings.ContainsRune(words[0], '/') {
			features = []string{"opaque-script"}
		}
		return single(projection(program, nil, features, complete))
	}
}

// launchedCLIs maps the npm packages and binaries a package launcher can run
// to the provider CLI they are.
var launchedCLIs = map[string]string{
	"@hubspot/cli": "hs",
	"hs":           "hs",
	"@forge/cli":   "forge",
	"forge":        "forge",
}

// unwrapPackageLauncher sees through npx, bunx, pnpm dlx, yarn dlx and npm
// exec when they run a provider CLI, so `npx @hubspot/cli project deploy` is
// judged as `hs project deploy`. Launcher options it does not know leave the
// command incomplete. ok is false when the words do not launch a provider CLI.
func unwrapPackageLauncher(words []string, complete bool) ([]string, bool, bool) {
	program := strings.ToLower(filepath.Base(words[0]))
	rest := words[1:]
	switch program {
	case "npx", "bunx", "pnpx":
	case "pnpm", "yarn", "bun", "npm":
		if len(rest) == 0 {
			return nil, false, false
		}
		sub := rest[0]
		if !(sub == "dlx" && (program == "pnpm" || program == "yarn") || sub == "x" && program == "bun" || (sub == "exec" || sub == "x") && program == "npm") {
			return nil, false, false
		}
		rest = rest[1:]
	default:
		return nil, false, false
	}
	// A provider package named with --package, even when the command that
	// runs cannot be read, still makes this that provider's CLI.
	packaged := ""
	for i := 0; i < len(rest); i++ {
		arg := rest[i]
		switch {
		case arg == "--":
			if i+1 < len(rest) {
				if cli, ok := launchedCLIs[packageName(rest[i+1])]; ok {
					return append([]string{cli}, rest[i+2:]...), complete, true
				}
			}
			return launchedPackage(packaged)
		case arg == "-p" || arg == "--package":
			// The package is installed; the command named after it runs.
			if i+1 < len(rest) {
				packaged = strictestPackage(packaged, rest[i+1])
			}
			i++
		case strings.HasPrefix(arg, "--package="):
			packaged = strictestPackage(packaged, strings.TrimPrefix(arg, "--package="))
		case arg == "-c" || arg == "--call":
			// npx --call 'hs project deploy': the command is one quoted
			// argument. Its words are judged, but never as a complete parse.
			if i+1 < len(rest) {
				words := strings.Fields(rest[i+1])
				if len(words) > 0 {
					if cli, ok := launchedCLIs[packageName(words[0])]; ok {
						return append([]string{cli}, words[1:]...), false, true
					}
				}
			}
			return launchedPackage(packaged)
		case strings.HasPrefix(arg, "--call="):
			words := strings.Fields(strings.TrimPrefix(arg, "--call="))
			if len(words) > 0 {
				if cli, ok := launchedCLIs[packageName(words[0])]; ok {
					return append([]string{cli}, words[1:]...), false, true
				}
			}
			return launchedPackage(packaged)
		case arg == "-y" || arg == "--yes" || arg == "-q" || arg == "--quiet" || arg == "--silent":
		case strings.HasPrefix(arg, "-"):
			complete = false
		default:
			if cli, ok := launchedCLIs[packageName(arg)]; ok {
				return append([]string{cli}, rest[i+1:]...), complete, true
			}
			if complete {
				return launchedPackage(packaged)
			}
			// After an unknown option this may be its value; keep looking
			// for the package.
		}
	}
	return launchedPackage(packaged)
}

// strictestPackage keeps the first provider package a launcher installs.
func strictestPackage(current, spec string) string {
	if current != "" {
		return current
	}
	if _, ok := launchedCLIs[packageName(spec)]; ok {
		return packageName(spec)
	}
	return ""
}

// launchedPackage is the fallback when a launcher's command cannot be read:
// a provider package it installs makes it that provider's CLI, unrecognized.
func launchedPackage(packaged string) ([]string, bool, bool) {
	if cli, ok := launchedCLIs[packaged]; ok {
		return []string{cli}, false, true
	}
	return nil, false, false
}

// packageName drops a version from an npm package spec: @hubspot/cli@7 is
// @hubspot/cli.
func packageName(spec string) string {
	spec = strings.ToLower(spec)
	if at := strings.LastIndex(spec, "@"); at > 0 {
		return spec[:at]
	}
	return spec
}

func single(projection cedareval.ShellProjectionV2) []cedareval.ShellProjectionV2 {
	return []cedareval.ShellProjectionV2{projection}
}

// unwrap strips the process wrappers an agent can put in front of a command
// without changing what runs. It returns ok=false, naming the wrapper, when
// the wrapper's own arguments cannot be understood and the real program is
// therefore unknown.
func unwrap(words []string, complete bool) (_ []string, _ bool, wrapper string, ok bool) {
	for range 8 {
		if len(words) == 0 || words[0] == "" {
			return words, complete, "", true
		}
		wrapper = filepath.Base(words[0])
		rest := words[1:]
		switch wrapper {
		case "command":
			rest = skipFlags(rest, "-p")
			if len(rest) > 0 && (rest[0] == "-v" || rest[0] == "-V") {
				// Lookups print where a command lives; nothing runs.
				return words, complete, "", true
			}
			if len(rest) > 0 && rest[0] == "--" {
				rest = rest[1:]
			}
			if len(rest) > 0 && strings.HasPrefix(rest[0], "-") {
				return nil, false, wrapper, false
			}
		case "env":
			rest, complete, ok = unwrapEnv(rest, complete)
		case "sudo":
			rest, complete, ok = unwrapSudo(rest, complete)
		case "exec":
			rest, ok = unwrapOptions(rest, map[string]bool{"-a": true}, map[string]bool{"-c": true, "-l": true}, nil)
		case "nohup":
			ok = true
		case "nice":
			rest, ok = unwrapNice(rest)
		case "timeout":
			rest, ok = unwrapTimeout(rest)
		case "time":
			rest, ok = unwrapOptions(rest, nil, map[string]bool{"-p": true}, nil)
		case "xargs":
			rest, ok = unwrapXargs(rest)
			// Arguments read from stdin are appended to the command; the
			// literal words are real but never the whole story.
			complete = false
		default:
			return words, complete, "", true
		}
		if wrapper != "command" && !ok {
			return nil, false, wrapper, false
		}
		if len(rest) == 0 {
			// The wrapper ran alone (`env`, `nice`): it is the program.
			return []string{wrapper}, complete, "", true
		}
		words = rest
	}
	return nil, false, wrapper, false
}

func skipFlags(words []string, flags ...string) []string {
	for len(words) > 0 && hasArg(flags, words[0]) {
		words = words[1:]
	}
	return words
}

// unwrapOptions consumes a wrapper's options: valueOptions take the next
// word, flags stand alone, valuePrefixes are `--option=value` forms. Any other
// option is unknown and makes the wrapper unclassifiable.
func unwrapOptions(words []string, valueOptions, flags map[string]bool, valuePrefixes []string) ([]string, bool) {
	for len(words) > 0 {
		word := words[0]
		switch {
		case word == "--":
			return words[1:], true
		case valueOptions[word]:
			if len(words) < 2 {
				return nil, false
			}
			words = words[2:]
		case flags[word] || hasPrefix(word, valuePrefixes...):
			words = words[1:]
		case strings.HasPrefix(word, "-") && word != "-":
			return nil, false
		default:
			return words, true
		}
	}
	return nil, true
}

func unwrapEnv(words []string, complete bool) ([]string, bool, bool) {
	for len(words) > 0 {
		word := words[0]
		switch {
		case word == "--":
			return words[1:], complete, true
		case word == "-u" || word == "--unset" || word == "-C" || word == "--chdir":
			if len(words) < 2 {
				return nil, false, false
			}
			words = words[2:]
		case hasPrefix(word, "--unset=", "--chdir=") || word == "-i" || word == "--ignore-environment" || word == "-0" || word == "--null":
			words = words[1:]
		case strings.Contains(word, "=") && !strings.HasPrefix(word, "="):
			words = words[1:]
		case strings.HasPrefix(word, "-"):
			return nil, false, false
		default:
			return words, complete, true
		}
	}
	return nil, complete, true
}

func unwrapSudo(words []string, complete bool) ([]string, bool, bool) {
	valueOptions := map[string]bool{"-u": true, "--user": true, "-g": true, "--group": true, "-h": true, "--host": true, "-C": true, "--close-from": true, "-D": true, "--chdir": true, "-R": true, "--chroot": true, "-T": true, "--command-timeout": true, "-p": true, "--prompt": true}
	valuePrefixes := []string{"--user=", "--group=", "--host=", "--close-from=", "--chdir=", "--chroot=", "--command-timeout=", "--preserve-env=", "--prompt="}
	flags := map[string]bool{"-E": true, "--preserve-env": true, "-n": true, "--non-interactive": true, "-S": true, "--stdin": true, "-k": true, "--reset-timestamp": true, "-b": true, "--background": true, "-H": true, "--set-home": true, "-i": true, "--login": true, "-s": true, "--shell": true, "-A": true, "--askpass": true}
	rest, ok := unwrapOptions(words, valueOptions, flags, valuePrefixes)
	return rest, complete, ok
}

func unwrapNice(words []string) ([]string, bool) {
	for len(words) > 0 {
		word := words[0]
		switch {
		case word == "--":
			return words[1:], true
		case word == "-n" || word == "--adjustment":
			if len(words) < 2 {
				return nil, false
			}
			words = words[2:]
		case strings.HasPrefix(word, "--adjustment=") || strings.HasPrefix(word, "-n") && len(word) > 2 || isSignedNumber(word):
			words = words[1:]
		case strings.HasPrefix(word, "-"):
			return nil, false
		default:
			return words, true
		}
	}
	return nil, true
}

func isSignedNumber(word string) bool {
	trimmed := strings.TrimLeft(word, "-+")
	if trimmed == "" || len(word)-len(trimmed) > 2 {
		return false
	}
	return strings.Trim(trimmed, "0123456789") == ""
}

func unwrapTimeout(words []string) ([]string, bool) {
	valueOptions := map[string]bool{"-s": true, "--signal": true, "-k": true, "--kill-after": true}
	flags := map[string]bool{"--preserve-status": true, "--foreground": true, "-v": true, "--verbose": true}
	rest, ok := unwrapOptions(words, valueOptions, flags, []string{"--signal=", "--kill-after="})
	if !ok || len(rest) == 0 {
		return nil, ok
	}
	// The first non-option word is the duration; the command follows it.
	return rest[1:], true
}

func unwrapXargs(words []string) ([]string, bool) {
	valueOptions := map[string]bool{"-a": true, "--arg-file": true, "-d": true, "--delimiter": true, "-E": true, "--eof": true, "-I": true, "--replace": true, "-L": true, "--max-lines": true, "-l": true, "-n": true, "--max-args": true, "-P": true, "--max-procs": true, "-s": true, "--max-chars": true, "-S": true, "-J": true, "-R": true, "--process-slot-var": true}
	flags := map[string]bool{"-0": true, "--null": true, "-r": true, "--no-run-if-empty": true, "-t": true, "--verbose": true, "-p": true, "--interactive": true, "-x": true, "--exit": true, "-o": true, "--open-tty": true, "-i": true}
	for len(words) > 0 {
		word := words[0]
		switch {
		case word == "--":
			return words[1:], true
		case valueOptions[word]:
			if len(words) < 2 {
				return nil, false
			}
			words = words[2:]
		case flags[word]:
			words = words[1:]
		case len(word) > 2 && !strings.HasPrefix(word, "--") && (valueOptions[word[:2]] || word[:2] == "-i"):
			// Attached value: -n1, -I{}, -P4.
			words = words[1:]
		case strings.HasPrefix(word, "--") && strings.Contains(word, "="):
			words = words[1:]
		case strings.HasPrefix(word, "-"):
			return nil, false
		default:
			return words, true
		}
	}
	return nil, true
}

// classifyShell recurses into `sh -c <script>` so the inner command is
// classified like a top-level one. A script that is not a literal cannot be
// seen through; it stays incomplete without a GitHub route fact because the
// program inside is unknown.
func shellCommandIndex(args []string) (int, bool) {
	commandFlag := false
	i := 0
	for ; i < len(args); i++ {
		arg := args[i]
		if arg == "--" || arg == "-" {
			i++
			break
		}
		if !strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "+") {
			break
		}
		if arg == "-o" || arg == "+o" || arg == "-O" || arg == "+O" || arg == "--rcfile" || arg == "--init-file" {
			i++
			continue
		}
		if strings.HasPrefix(arg, "--") {
			continue
		}
		if strings.Contains(arg, "c") {
			commandFlag = true
		}
	}
	return i, commandFlag
}

func classifyShell(program string, args []string, complete bool, w walk) []cedareval.ShellProjectionV2 {
	i, commandFlag := shellCommandIndex(args)
	if !commandFlag {
		return single(projection(program, nil, nil, complete))
	}
	if i >= len(args) {
		return single(projection(program, nil, []string{"missing-script"}, false))
	}
	w.argumentFacts = append(w.argumentFacts, providerHostFacts(strings.Join(args[i+1:], " "))...)
	return nestedScript(program, args[i], w)
}

// classifyEval joins eval's arguments the way the shell does and classifies
// the resulting script.
func classifyEval(args []string, complete bool, w walk) []cedareval.ShellProjectionV2 {
	if len(args) == 0 {
		return single(projection("eval", nil, []string{"empty-command"}, complete))
	}
	if !complete {
		return single(projection("eval", nil, []string{"dynamic-script"}, false))
	}
	return nestedScript("eval", strings.Join(args, " "), w)
}

func nestedScript(program, script string, w walk) []cedareval.ShellProjectionV2 {
	if script == "" {
		return single(projection(program, nil, []string{"dynamic-script"}, false))
	}
	if w.depth >= maxScriptDepth {
		return single(projection(program, nil, []string{"script-depth-exceeded"}, false))
	}
	inner := project(script, walk{depth: w.depth + 1, stateful: w.stateful, stdin: w.stdin, argumentFacts: w.argumentFacts, stdinFacts: w.stdinFacts})
	for i := range inner {
		inner[i].Features = sortedUnique(append(inner[i].Features, "nested-script"))
	}
	return inner
}

func classifyGit(args []string, complete bool) cedareval.ShellProjectionV2 {
	args, globals := stripGitGlobals(args)
	if globals == gitGlobalsUnknown {
		return projection("git", []string{FactRouteUnrecognized}, []string{"unknown-git-global"}, false)
	}
	if len(args) == 0 {
		return projection("git", nil, []string{"missing-subcommand"}, false)
	}
	if args[0] == "" {
		return projection("git", []string{FactRouteUnrecognized}, []string{"dynamic-subcommand"}, false)
	}
	subcommand := args[0]
	rest := args[1:]
	facts := []string{"git/subcommand=" + subcommand}
	var features []string
	if globals == gitGlobalsAlias {
		// An alias defined on the command line can turn any subcommand into
		// anything; git only ignores aliases that shadow builtins.
		facts = append(facts, FactRouteUnrecognized)
		features = append(features, "git-alias-definition")
		complete = false
	}

	if subcommand == "lfs" {
		if len(rest) == 0 || rest[0] == "" {
			return projection("git", facts, append(features, "missing-lfs-subcommand"), false)
		}
		facts = append(facts, "git/lfs-subcommand="+rest[0])
		if rest[0] == "push" {
			facts = append(facts, gitRoute(complete))
			if !hasArg(rest[1:], "-n", "--dry-run") {
				facts = append(facts, "github/write=true")
			}
		}
		return projection("git", facts, features, complete)
	}

	if subcommand != "push" && subcommand != "send-pack" {
		return projection("git", facts, features, complete)
	}
	if !complete {
		features = append(features, "dynamic-push-arguments")
	}
	facts = append(facts, gitRoute(complete))
	options, refspecs := pushArguments(rest)
	dryRun := hasArg(options, "-n", "--dry-run")
	if dryRun {
		facts = append(facts, "github/dry-run=true")
	} else {
		facts = append(facts, "github/write=true")
	}
	if !dryRun {
		force := hasArg(options, "-f", "--force", "--mirror") || hasForceRefspec(refspecs)
		if force {
			facts = append(facts, "github/force-push=true", "git/force=true", OperationFact(OperationForcePush))
		}
		// Lease pushes are a separate operation: block-github-force-push
		// promises to allow them, protect-git-history forbids them.
		if hasForceWithLease(options) {
			facts = append(facts, OperationFact(OperationForcePushWithLease))
		}
		if hasArg(options, "-d", "--delete", "--prune", "--mirror") || hasDeleteRefspec(refspecs) {
			facts = append(facts, OperationFact(OperationDeleteRef))
		}
	}
	return projection("git", facts, features, complete)
}

func gitRoute(complete bool) string {
	if complete {
		return "github/route=catalogued"
	}
	return FactRouteUnrecognized
}

// pushArguments separates options from refspecs, expanding clustered short
// flags (`-fu` is `-f -u`) and honouring `--` and value-taking options.
func pushArguments(args []string) (options, refspecs []string) {
	valueOptions := map[string]bool{"-o": true, "--push-option": true, "--receive-pack": true, "--exec": true, "--repo": true}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			refspecs = append(refspecs, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			refspecs = append(refspecs, arg)
			continue
		}
		if valueOptions[arg] {
			options = append(options, arg)
			i++
			continue
		}
		if shortFlagCluster.MatchString(arg) {
			for _, flag := range arg[1:] {
				options = append(options, "-"+string(flag))
				if flag == 'o' {
					// -o takes a value; the rest of the cluster is it.
					break
				}
			}
			continue
		}
		options = append(options, arg)
	}
	return options, refspecs
}

type gitGlobals int

const (
	gitGlobalsOK gitGlobals = iota
	gitGlobalsAlias
	gitGlobalsUnknown
)

var gitGlobalValueOptions = map[string]bool{"-C": true, "-c": true, "--git-dir": true, "--work-tree": true, "--namespace": true, "--exec-path": true, "--super-prefix": true, "--config-env": true, "--attr-source": true, "--list-cmds": true}

var gitGlobalValuePrefixes = []string{"--git-dir=", "--work-tree=", "--namespace=", "--exec-path=", "--super-prefix=", "--attr-source=", "--list-cmds="}

var gitGlobalFlags = map[string]bool{"-p": true, "--paginate": true, "-P": true, "--no-pager": true, "--bare": true, "--no-replace-objects": true, "--no-lazy-fetch": true, "--no-optional-locks": true, "--no-advice": true, "--literal-pathspecs": true, "--glob-pathspecs": true, "--noglob-pathspecs": true, "--icase-pathspecs": true, "--html-path": true, "--man-path": true, "--info-path": true, "--version": true, "--help": true, "-h": true}

// stripGitGlobals consumes git's own options. Every global git accepts is
// listed; anything else is unknown and cannot be skipped safely because it
// might take the next word as its value.
func stripGitGlobals(args []string) ([]string, gitGlobals) {
	status := gitGlobalsOK
	for len(args) > 0 {
		word := args[0]
		switch {
		case gitGlobalValueOptions[word]:
			if len(args) < 2 {
				return nil, gitGlobalsUnknown
			}
			if (word == "-c" || word == "--config-env") && strings.HasPrefix(strings.ToLower(args[1]), "alias.") {
				status = gitGlobalsAlias
			}
			args = args[2:]
		case strings.HasPrefix(word, "--config-env="):
			if strings.HasPrefix(strings.ToLower(strings.TrimPrefix(word, "--config-env=")), "alias.") {
				status = gitGlobalsAlias
			}
			args = args[1:]
		case hasPrefix(word, gitGlobalValuePrefixes...) || gitGlobalFlags[word]:
			args = args[1:]
		case strings.HasPrefix(word, "-") && word != "-":
			return args, gitGlobalsUnknown
		default:
			return args, status
		}
	}
	return nil, status
}

func classifyGH(args []string, complete, helpAllowed bool) cedareval.ShellProjectionV2 {
	plain := plainGHWords(args)
	args, globalsComplete := stripGHGlobals(args)
	complete = complete && globalsComplete
	if len(args) == 0 || args[0] == "" {
		return projection("gh", []string{FactRouteUnrecognized}, []string{"missing-command"}, false)
	}
	if args[0] == "api" {
		return classifyGHAPI(args[1:], complete)
	}
	key := args[0]
	rest := args[1:]
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		key += "/" + rest[0]
		rest = rest[1:]
		// `repo deploy-key add` and `repo autolink create` carry their verb
		// in a third word.
		if ghNestedCommands[key] && len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			key += "/" + rest[0]
			rest = rest[1:]
		}
	}
	if ghWriteCommands[key] && !(helpAllowed && complete && plain && ghAsksForHelp(rest)) {
		facts := []string{"gh/command=" + key, "github/route=catalogued", "github/write=true"}
		facts = append(facts, operationFacts(ghOperations(key, rest))...)
		return projection("gh", facts, nil, complete)
	}
	if ghWriteCommands[key] || ghReadCommands[key] || ghReadCommands[args[0]] {
		return projection("gh", []string{"gh/command=" + key, "github/route=catalogued"}, nil, complete)
	}
	return projection("gh", []string{"gh/command=" + key, FactRouteUnrecognized}, nil, false)
}

// ghAsksForHelp reports a --help flag still on at the end of the command,
// which makes gh print the command's usage and exit without running it. The
// last setting wins, so a later --help=false turns it back off. Only --help
// counts: some commands give -h another meaning (`gh repo create -h URL`),
// so a short cluster with a value that could reach -h makes the answer no.
// A word right after an option word may be that option's value
// (`gh release create v1 --notes --help`); when such a word is --help,
// --help=… or --, which way gh reads it is unclear and the answer is no.
var plainGHWord = regexp.MustCompile(`^[A-Za-z0-9_./:=,@%+-]*$`)

// plainGHWords reports that no word, global flags included, uses characters
// the shell may still expand (`--{help,help}=false`, `-R{acme/api,-dn}`), so
// the help check sees the words gh will.
func plainGHWords(args []string) bool {
	for _, arg := range args {
		if !plainGHWord.MatchString(arg) {
			return false
		}
	}
	return true
}

func ghAsksForHelp(args []string) bool {
	help := false
	for i, arg := range args {
		helpWord := arg == "--" || arg == "--help" || strings.HasPrefix(arg, "--help=")
		if helpWord && i > 0 {
			previous := args[i-1]
			if strings.HasPrefix(previous, "-") && previous != "--" && !strings.Contains(previous, "=") {
				return false
			}
		}
		switch {
		case arg == "--":
			return help
		case arg == "--help":
			help = true
		case strings.HasPrefix(arg, "--help="):
			value, err := strconv.ParseBool(strings.TrimPrefix(arg, "--help="))
			help = err == nil && value
		case !strings.HasPrefix(arg, "--") && strings.HasPrefix(arg, "-") && strings.Contains(arg, "h") && strings.Contains(arg, "="):
			return false
		}
	}
	return help
}

func stripGHGlobals(args []string) ([]string, bool) {
	for len(args) > 0 {
		word := args[0]
		if word == "--" {
			return args[1:], true
		}
		if word == "-R" || word == "--repo" || word == "--hostname" {
			if len(args) < 2 {
				return nil, false
			}
			args = args[2:]
			continue
		}
		if strings.HasPrefix(word, "--repo=") || strings.HasPrefix(word, "--hostname=") {
			args = args[1:]
			continue
		}
		return args, true
	}
	return nil, false
}

func classifyGHAPI(args []string, complete bool) cedareval.ShellProjectionV2 {
	method := "GET"
	path := ""
	fields := make([]string, 0, 2)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-X" || arg == "--method":
			if i+1 >= len(args) {
				complete = false
				continue
			}
			i++
			method = strings.ToUpper(args[i])
		case strings.HasPrefix(arg, "--method="):
			method = strings.ToUpper(strings.TrimPrefix(arg, "--method="))
		case arg == "-f" || arg == "-F" || arg == "--raw-field" || arg == "--field":
			if i+1 >= len(args) {
				complete = false
				continue
			}
			i++
			fields = append(fields, args[i])
			if method == "GET" {
				method = "POST"
			}
		case strings.HasPrefix(arg, "-f") && len(arg) > 2:
			fields = append(fields, arg[2:])
			if method == "GET" {
				method = "POST"
			}
		case strings.HasPrefix(arg, "--raw-field=") || strings.HasPrefix(arg, "--field="):
			fields = append(fields, strings.SplitN(arg, "=", 2)[1])
			if method == "GET" {
				method = "POST"
			}
		case arg == "--input" || strings.HasPrefix(arg, "--input="):
			// A request body file makes gh default to POST; its contents are
			// invisible here, so the request stays unrecognized.
			if arg == "--input" {
				i++
			}
			if method == "GET" {
				method = "POST"
			}
			complete = false
		case ghAPINeutralFlags[arg] || hasPrefix(arg, ghAPINeutralValuePrefixes...):
			// Output and transport flags shape the response, not the request.
		case ghAPINeutralValueOptions[arg]:
			if i+1 >= len(args) {
				complete = false
				continue
			}
			i++
		case strings.HasPrefix(arg, "-"):
			// A flag this projection does not know could change the request.
			complete = false
		case !strings.HasPrefix(arg, "-") && path == "":
			path = arg
		}
	}
	facts := []string{"gh/command=api", "github/route=catalogued", "http/method=" + method}
	if path != "" {
		facts = append(facts, "http/path="+path)
	} else {
		complete = false
	}
	if isWriteMethod(method) {
		facts = append(facts, "github/write=true")
	}
	force := method == "PATCH" && strings.Contains(path, "/git/refs") && containsForceField(fields)
	if force {
		facts = append(facts, "github/force-push=true")
	}
	operations, features, literal := githubOperations(path, method, fields, force)
	facts = append(facts, operationFacts(operations)...)
	complete = complete && literal
	if !complete {
		facts = replaceFact(facts, "github/route=catalogued", FactRouteUnrecognized)
	}
	return projection("gh", facts, features, complete)
}

// githubOperations derives operation facts for a literal REST or GraphQL
// call from its route (see githubRouteOperations) or its literal mutation
// text. Route matching runs even for an incomplete call: the path is known
// even when the body is not. literal is false when the call is GraphQL and
// its query text cannot be read, which makes the route unrecognized.
func githubOperations(path, method string, bodies []string, force bool) (operations, features []string, literal bool) {
	literal = true
	if path == "" {
		return nil, nil, literal
	}
	host, segments, ok := githubAPISegments(path)
	if !ok {
		return nil, nil, literal
	}
	if host == hostGitHubAPI && len(segments) == 1 && segments[0] == "graphql" {
		query, found := graphqlQueryText(bodies)
		if !found {
			return nil, []string{FeatureGraphQLNotLiteral}, false
		}
		operations = graphqlOperations(query)
		if len(operations) > 0 {
			features = append(features, FeatureOperationFromGraphQL)
		}
		return operations, features, literal
	}
	operations = githubRouteOperations(host, method, segments, force, bodyHasField(bodies, "event", "APPROVE"))
	if len(operations) > 0 {
		features = append(features, FeatureOperationFromRoute)
	}
	return operations, features, literal
}

// gh api flags that only affect output or transport; they never change what
// the request does to GitHub, so they must not make a read unrecognized.
var ghAPINeutralFlags = map[string]bool{"--paginate": true, "--slurp": true, "--verbose": true, "-i": true, "--include": true, "--silent": true}

var ghAPINeutralValueOptions = map[string]bool{"-q": true, "--jq": true, "-t": true, "--template": true, "--cache": true, "--hostname": true, "-H": true, "--header": true, "-p": true, "--preview": true}

var ghAPINeutralValuePrefixes = []string{"--jq=", "--template=", "--cache=", "--hostname=", "--header=", "--preview="}

// curlOperation is one request of a curl command: --next starts the next one
// with fresh options.
type curlOperation struct {
	// custom is the -X method, which replaces the method string whatever
	// else is set; otherwise -I, -G, -T and a body imply one.
	custom                  string
	head, get, upload, data bool
	// uploads are the -T files in order, one per URL; an empty one is a
	// slot without an upload.
	uploads       []string
	requestTarget string
	protoDefault  string
	urls, bodies  []string
	bodyFile      bool
}

func (op curlOperation) method() string {
	switch {
	case op.custom != "":
		return op.custom
	case op.head:
		return "HEAD"
	case op.get:
		return "GET"
	case op.upload:
		return "PUT"
	case op.data:
		return "POST"
	}
	return "GET"
}

// withUpload returns the operation and URL as curl sends its index-th URL:
// each -T applies to one URL in turn, and a URL ending in / gets the upload
// file's name appended, unless --request-target sets the path. readable is
// false when that name is a glob or holds a backslash, which the projection
// does not model.
func (op curlOperation) withUpload(index int, urlText string) (_ curlOperation, _ string, readable bool) {
	file := ""
	if index < len(op.uploads) {
		file = op.uploads[index]
	}
	op.upload = file != ""
	parsed, err := url.Parse(urlText)
	if !op.upload || op.requestTarget != "" || file == "-" || file == "." || err != nil || !strings.HasSuffix("/"+parsed.Path, "/") {
		return op, urlText, true
	}
	if strings.ContainsAny(file, "{}[]\\") {
		return op, urlText, false
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/") + "/" + path.Base(file)
	parsed.RawPath = ""
	return op, parsed.String(), true
}

// classifyCurl classifies a curl command. opaqueValues is set when the
// command is incomplete only because the shell computes some of its words (a
// computed word is ""), each quoted into exactly one argument, and no wrapper
// adds any. For a Databricks request a computed header, body or other option
// value is then opaque text that does not change the route ("Authorization:
// Bearer $TOKEN"), while one in a URL, method or target still leaves it
// unclear. Other providers keep main's reading: any computed word leaves
// their request incomplete. urlGlobs is false for clients without curl globbing.
func classifyCurl(args, source []string, complete, opaqueValues, urlGlobs bool) cedareval.ShellProjectionV2 {
	result, hints := readCurl(args, source, complete, opaqueValues, urlGlobs)
	// A hint comes only from a computed URL, which leaves the request
	// unreadable, so it never joins a catalogued route.
	if len(hints) > 0 {
		result.Facts = sortedUnique(append(result.Facts, hints...))
	}
	return result
}

// readCurl classifies a curl command's requests and returns, as hints, the
// provider facts that the source text of its computed URL operands still
// names (see computedTargetHints); source lines up with args, or is nil.
func readCurl(args, source []string, complete, opaqueValues, urlGlobs bool) (cedareval.ShellProjectionV2, []string) {
	// unclear is set when the request cannot be read exactly: a word the
	// shell computes where an option, URL or method goes, a config file
	// (-K), which can set any option, or an option the parser does not know
	// followed by one that it may have taken as its value. By decision, a
	// Databricks request that cannot be read exactly is unrecognized with no
	// tier: it fails open. A computed body or header value does not change
	// the route, so the route's tier holds.
	unclear := false
	computed := !complete
	if opaqueValues {
		complete = true
	}
	isComputed := func(word string) bool { return computed && word == "" }
	args = slices.Clone(args)
	if len(source) != len(args) {
		source = nil
	}
	source = slices.Clone(source)
	var hints []string
	hint := func(j int) {
		if source != nil && isComputed(args[j]) {
			hints = append(hints, computedTargetHints(source[j])...)
		}
	}
	var operations []curlOperation
	var op curlOperation
	safeFlags := map[string]bool{"-s": true, "-S": true, "--silent": true, "--show-error": true, "--fail": true, "--fail-with-body": true, "--compressed": true}
	unknownBefore := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if expanded, ok := expandCurlShortCluster(arg); ok {
			// -sX DELETE is -s -X DELETE; -sd@f is -s -d @f.
			args = slices.Concat(args[:i], expanded, args[i+1:])
			if source != nil {
				source = slices.Concat(source[:i], expanded, source[i+1:])
			}
			i--
			continue
		}
		if unknownBefore && strings.HasPrefix(arg, "-") {
			unclear = true
		}
		if isComputed(arg) && !strings.HasPrefix(arg, "-") {
			// A computed URL or other positional word.
			unclear, complete = true, false
		}
		if arg == "--" && !unknownBefore {
			// Everything after the option terminator is a URL.
			op.urls = append(op.urls, args[i+1:]...)
			for j := i + 1; j < len(args); j++ {
				hint(j)
			}
			break
		}
		unknown := false
		// value returns the option's value: attached after = or the next word.
		// Every option that reads it shapes the method, target or URL, so a
		// computed value leaves the request unclear.
		value := func(name string) (string, bool) {
			if attached, ok := strings.CutPrefix(arg, name+"="); ok {
				if isComputed(attached) {
					unclear, complete = true, false
				}
				return attached, true
			}
			if i+1 >= len(args) {
				complete = false
				return "", false
			}
			i++
			if isComputed(args[i]) {
				unclear, complete = true, false
			}
			return args[i], true
		}
		body, isBody := curlDataOption(arg)
		switch {
		case arg == "-X" || arg == "--request" || strings.HasPrefix(arg, "--request="):
			if method, ok := value("--request"); ok {
				op.custom = strings.ToUpper(method)
			}
		case arg == "--request-target" || strings.HasPrefix(arg, "--request-target="):
			op.requestTarget, _ = value("--request-target")
		case arg == "--proto-default" || strings.HasPrefix(arg, "--proto-default="):
			op.protoDefault, _ = value("--proto-default")
		case arg == "-I" || arg == "--head":
			op.head = true
		case arg == "--no-head":
			op.head = false
		case arg == "-G" || arg == "--get":
			op.get = true
		case arg == "--no-get":
			op.get = false
		case arg == "--url" || strings.HasPrefix(arg, "--url="):
			if urlText, ok := value("--url"); ok {
				op.urls = append(op.urls, urlText)
				hint(i)
			}
		case isCurlDataFlag(arg):
			if i+1 >= len(args) {
				complete = false
				continue
			}
			i++
			body, isBody = curlBody(arg, args[i]), true
		case isBody:
		case arg == "-T" || arg == "--upload-file" || strings.HasPrefix(arg, "--upload-file="):
			// An empty file name holds its URL's slot without an upload.
			if file, ok := value("--upload-file"); ok {
				op.uploads = append(op.uploads, file)
				op.upload = op.upload || file != ""
			}
		case arg == "-K" || arg == "--config" || strings.HasPrefix(arg, "--config="):
			unclear = true
			complete = false
			value("--config")
		case curlValueOption(arg):
			if i+1 >= len(args) {
				complete = false
				continue
			}
			i++
			if (arg == "-H" || arg == "--header") && isMethodOverrideHeader(args[i]) {
				// The server would act on the header's method, not the one we see.
				complete = false
			}
		case strings.HasPrefix(arg, "--header=") && isMethodOverrideHeader(strings.TrimPrefix(arg, "--header=")):
			complete = false
		case safeFlags[arg]:
		case arg == "--next" || arg == "-:":
			unclear = unclear || unknownBefore
			complete = false
			operations = append(operations, op)
			op = curlOperation{}
		case strings.HasPrefix(arg, "-"):
			// Unknown curl flags can change request behavior. A known switch
			// takes no value, so it cannot hide the next word.
			complete = false
			unknown = !curlSwitches[arg]
		default:
			op.urls = append(op.urls, arg)
			if !unknownBefore {
				// Else it may be the value of an option the parser does
				// not know (--noproxy).
				hint(i)
			}
		}
		if isBody {
			op.bodies = append(op.bodies, body)
			op.bodyFile = op.bodyFile || strings.HasPrefix(body, "@")
			op.data = true
		}
		unknownBefore = unknown
	}
	operations = append(operations, op)

	// Each URL of each operation is judged with that operation's method and
	// body. A URL glob ({a,b}, [x-y]) is not expanded, so the request cannot
	// be read exactly: a Databricks URL with one is unrecognized with no
	// tier, and any other is read as written but never as a catalogued
	// route (a GitHub force push through a globbed path is not seen).
	type request struct {
		urlText, method string
		bodies          []string
		bodyFile        bool
	}
	var requests []request
	var unrecognized []string
	for _, op := range operations {
		for index, urlText := range op.urls {
			normalized := normalizeCurlURL(urlText, cmp.Or(op.protoDefault, "http"))
			// Only a target in origin form (/path) replaces the path the
			// projection can read; any other form (*, a relative or absolute
			// URL) leaves the request unreadable.
			targetReadable := op.requestTarget == "" || strings.HasPrefix(op.requestTarget, "/")
			complete = complete && targetReadable
			if op.requestTarget != "" && targetReadable {
				normalized = withRequestTarget(normalized, op.requestTarget)
			}
			sent, sentURL, readable := op.withUpload(index, normalized)
			readable = readable && targetReadable
			// The fragment is not sent, so a glob in it changes nothing.
			beforeFragment, _, _ := strings.Cut(urlText, "#")
			globbed := urlGlobs && strings.ContainsAny(beforeFragment, "{}[]")
			complete = complete && !globbed
			if unclear || !readable || globbed {
				if databricksURL(urlText) {
					unrecognized = append(unrecognized, FactDatabricksRouteUnrecognized)
					continue
				}
			}
			requests = append(requests, request{sentURL, sent.method(), op.bodies, op.bodyFile})
		}
	}
	if len(requests) <= 1 && len(operations) == 1 && len(unrecognized) == 0 {
		if len(requests) == 0 {
			return classifyCurlURL("", op.method(), op.bodies, complete && !opaqueValues, op.bodyFile), hints
		}
		// The opaque reading is for Databricks requests only.
		requestComplete := complete && (!opaqueValues || databricksURL(requests[0].urlText))
		return classifyCurlURL(requests[0].urlText, requests[0].method, requests[0].bodies, requestComplete, requests[0].bodyFile), hints
	}
	// Several requests, or one that is unrecognized: each is judged, and the
	// whole is never a catalogued route.
	facts := unrecognized
	var features []string
	otherWrite := false
	for _, each := range requests {
		projection := classifyCurlURL(each.urlText, each.method, each.bodies, false, each.bodyFile)
		facts = append(facts, projection.Facts...)
		features = append(features, projection.Features...)
		otherWrite = otherWrite || databricksWritesOutsideSQL(projection.Facts)
	}
	if otherWrite {
		// One request must not lend the SQL exemption to another's write.
		facts = slices.DeleteFunc(facts, func(fact string) bool { return fact == databricksProductFact(databricksSQLProduct) })
	}
	return projection("curl", facts, features, false), hints
}

// curlSwitches are common curl options that take no value.
var curlSwitches = words("-L", "--location", "--location-trusted", "-k", "--insecure", "-v", "--verbose", "-i",
	"--include", "--show-headers", "-f", "-#", "--progress-bar", "--no-progress-meter", "-N", "--no-buffer", "-O",
	"--remote-name", "--remote-name-all", "-J", "--remote-header-name", "-g", "--globoff", "-q", "--disable",
	"-0", "--http1.0", "--http1.1", "--http2", "--http2-prior-knowledge", "--http3", "--http3-only", "-4", "--ipv4",
	"-6", "--ipv6", "--raw", "-n", "--netrc", "--netrc-optional", "--tcp-nodelay", "-Z", "--parallel",
	"--parallel-immediate", "--fail-early", "--create-dirs", "--path-as-is", "--retry-all-errors",
	"--retry-connrefused", "--anyauth", "--basic", "--digest", "--negotiate", "--ntlm", "-l", "--list-only", "-B",
	"--use-ascii", "-j", "--junk-session-cookies", "-R", "--remote-time", "-p", "--proxytunnel", "-V", "--version",
	"--styled-output", "--no-keepalive", "--no-sessionid", "--tr-encoding", "--xattr", "--ssl", "--ssl-reqd",
	"--ssl-no-revoke", "--ssl-allow-beast", "--ssl-revoke-best-effort", "--no-alpn", "--no-npn", "--compressed-ssh",
	"--suppress-connect-headers", "--disallow-username-in-url", "--ignore-content-length", "--crlf", "--append",
	"-a", "--proxy-insecure", "--proxy-anyauth", "--proxy-basic", "--proxy-digest", "--proxy-negotiate",
	"--proxy-ntlm", "--doh-insecure", "--cert-status", "--false-start", "--sasl-ir", "--metalink", "-M", "--manual")

var curlScheme = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9+.-]*):/+`)

// normalizeCurlURL reads a URL the way curl does: without a scheme it uses
// --proto-default (http unless set), any number of slashes may follow the
// scheme (https:/host and https:///host are https://host), percent escapes
// in the host are decoded, and the fragment, which curl does not send, is
// dropped.
func normalizeCurlURL(urlText, protoDefault string) string {
	urlText, _, _ = strings.Cut(urlText, "#")
	if urlText == "" {
		return ""
	}
	scheme, rest := protoDefault, urlText
	if match := curlScheme.FindStringSubmatch(urlText); match != nil {
		scheme, rest = match[1], urlText[len(match[0]):]
	}
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	if authority, err := url.PathUnescape(rest[:end]); err == nil {
		rest = authority + rest[end:]
	}
	return scheme + "://" + rest
}

// curlLongValueOptions are curl's long options that take a value.
var curlLongValueOptions = words("--abstract-unix-socket", "--alt-svc", "--aws-sigv4", "--cacert", "--capath", "--cert",
	"--cert-type", "--ciphers", "--config", "--connect-timeout", "--connect-to", "--continue-at", "--cookie", "--cookie-jar",
	"--create-file-mode", "--crlfile", "--curves", "--data", "--data-ascii", "--data-binary", "--data-raw",
	"--data-urlencode", "--delegation", "--dns-interface", "--dns-ipv4-addr", "--dns-ipv6-addr", "--dns-servers",
	"--doh-url", "--dump-header", "--ech", "--egd-file", "--engine", "--etag-compare", "--etag-save",
	"--expect100-timeout", "--form", "--form-string", "--ftp-account", "--ftp-alternative-to-user", "--ftp-method",
	"--ftp-port", "--ftp-ssl-ccc-mode", "--happy-eyeballs-timeout-ms", "--header", "--hostpubmd5", "--hostpubsha256",
	"--hsts", "--interface", "--ip-tos", "--ipfs-gateway", "--json", "--keepalive-cnt", "--keepalive-time", "--key",
	"--key-type", "--krb", "--libcurl", "--limit-rate", "--local-port", "--login-options", "--mail-auth", "--mail-from",
	"--mail-rcpt", "--max-filesize", "--max-redirs", "--max-time", "--netrc-file", "--oauth2-bearer", "--output",
	"--output-dir", "--parallel-max", "--pass", "--pinnedpubkey", "--preproxy", "--proto", "--proto-default",
	"--proto-redir", "--proxy", "--proxy-cacert", "--proxy-capath", "--proxy-cert", "--proxy-cert-type",
	"--proxy-ciphers", "--proxy-crlfile", "--proxy-header", "--proxy-key", "--proxy-key-type", "--proxy-pass",
	"--proxy-pinnedpubkey", "--proxy-service-name", "--proxy-tls13-ciphers", "--proxy-tlsauthtype",
	"--proxy-tlspassword", "--proxy-tlsuser", "--proxy-user", "--proxy1.0", "--pubkey", "--quote", "--random-file",
	"--range", "--rate", "--referer", "--request", "--request-target", "--resolve", "--retry", "--retry-delay",
	"--retry-max-time", "--sasl-authzid", "--service-name", "--socks4", "--socks4a", "--socks5",
	"--socks5-gssapi-service", "--socks5-hostname", "--speed-limit", "--speed-time", "--ssl-sessions", "--stderr",
	"--telnet-option", "--tftp-blksize", "--time-cond", "--tls-max", "--tls13-ciphers", "--tlsauthtype",
	"--tlspassword", "--tlsuser", "--trace", "--trace-ascii", "--trace-config", "--unix-socket", "--upload-file",
	"--upload-flags", "--url", "--url-query", "--user", "--user-agent", "--variable", "--write-out")

// curlValueOption reports a curl option that takes the next word as its
// value.
func curlValueOption(arg string) bool {
	if len(arg) == 2 && arg[0] == '-' && arg[1] != '-' {
		return strings.IndexByte(curlShortValueOptions, arg[1]) >= 0
	}
	return curlLongValueOptions[arg]
}

// curlShortValueOptions are curl's one-letter options that take a value.
const curlShortValueOptions = "AbcCdDeEFHKmoPQrtTuUwxXyYz"

// expandCurlShortCluster splits a short-option cluster the way curl reads
// it: each letter is an option, and the first one that takes a value takes
// the rest of the word (-XPOST, -sd@f) or, at the end, the next word.
func expandCurlShortCluster(arg string) ([]string, bool) {
	if len(arg) <= 2 || arg[0] != '-' || arg[1] == '-' {
		return nil, false
	}
	var out []string
	for j := 1; j < len(arg); j++ {
		out = append(out, "-"+arg[j:j+1])
		if strings.IndexByte(curlShortValueOptions, arg[j]) >= 0 {
			if j+1 < len(arg) {
				out = append(out, arg[j+1:])
			}
			break
		}
	}
	return out, true
}

// withRequestTarget replaces a URL's path and query with the target curl
// sends instead (--request-target).
func withRequestTarget(urlText, target string) string {
	parsed, err := url.Parse(urlText)
	if err != nil || parsed.Host == "" {
		return urlText
	}
	return parsed.Scheme + "://" + parsed.Host + target
}

// classifyCurlURL classifies one request of a curl command.
func classifyCurlURL(urlText, method string, bodies []string, complete, bodyFile bool) cedareval.ShellProjectionV2 {
	parsed, err := url.Parse(urlText)
	if err == nil && parsed.Scheme == "http" && parsed.Host != "" {
		// Plain HTTP to a provider is still that provider's request; it is
		// judged like HTTPS but never as a catalogued route.
		host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
		if isAtlassianHost(host) || isHubSpotHost(host) || databricksHost(host) || isJiraServerPath(parsed.Path) {
			parsed.Scheme = "https"
			complete = false
		}
	}
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		var facts []string
		if databricksURL(urlText) {
			// A readable Databricks host with a request the parser cannot
			// read (an invalid escape in the path).
			facts = []string{FactDatabricksRouteUnrecognized}
		}
		return projection("curl", facts, []string{"dynamic-or-invalid-url"}, false)
	}
	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	switch {
	case isAtlassianHost(host):
		return classifyAtlassianCurl(host, parsed, method, complete, bodyFile)
	case isHubSpotHost(host):
		return classifyHubSpotCurl(host, parsed, method, complete, bodyFile)
	case databricksHost(host):
		return classifyDatabricksCurl(host, parsed, method, bodies, complete)
	case isJiraServerPath(parsed.Path):
		return classifyAtlassianCurl(host, parsed, method, complete, bodyFile)
	}
	complete = complete && !bodyFile
	if host != "api.github.com" && host != "uploads.github.com" {
		return projection("curl", nil, nil, complete)
	}
	facts := []string{"curl/host=" + host, "http/method=" + method, "http/path=" + parsed.EscapedPath()}
	if complete {
		facts = append(facts, "github/route=catalogued")
	} else {
		facts = append(facts, FactRouteUnrecognized)
	}
	if isWriteMethod(method) {
		facts = append(facts, "github/write=true")
	}
	force := method == "PATCH" && strings.Contains(parsed.Path, "/git/refs") && containsForceBody(bodies)
	if force {
		facts = append(facts, "github/force-push=true")
	}
	operations, features, literal := githubOperations("https://"+host+parsed.EscapedPath(), method, bodies, force)
	facts = append(facts, operationFacts(operations)...)
	if !literal && complete {
		complete = false
		facts = replaceFact(facts, "github/route=catalogued", FactRouteUnrecognized)
	}
	return projection("curl", facts, features, complete)
}

var curlDataFlags = map[string]bool{"-d": true, "--data": true, "--data-raw": true, "--data-binary": true, "--data-urlencode": true, "--data-ascii": true, "--json": true, "-F": true, "--form": true, "--form-string": true}

func isCurlDataFlag(arg string) bool {
	return curlDataFlags[arg]
}

// curlDataOption returns the body of a data option with its value attached
// (--json=…, -d…); an empty attached value is still a body.
func curlDataOption(arg string) (string, bool) {
	for _, prefix := range []string{"--data=", "--data-raw=", "--data-binary=", "--data-urlencode=", "--data-ascii=", "--json=", "--form=", "--form-string="} {
		if value, ok := strings.CutPrefix(arg, prefix); ok {
			return curlBody(strings.TrimSuffix(prefix, "="), value), true
		}
	}
	if strings.HasPrefix(arg, "-d") && len(arg) > 2 || strings.HasPrefix(arg, "-F") && len(arg) > 2 {
		return arg[2:], true
	}
	return "", false
}

// curlBody returns the body piece curl sends for a data option's value:
// --data-urlencode percent-encodes the content (all of it, after a leading =,
// or after name=); a piece read from a file stays @name.
func curlBody(flag, value string) string {
	if flag != "--data-urlencode" {
		return value
	}
	name, content, hasName := strings.Cut(value, "=")
	if !hasName {
		if before, file, ok := strings.Cut(value, "@"); ok && !strings.ContainsAny(before, "=") {
			return "@" + file
		}
		return curlEscape(value)
	}
	if name == "" {
		return curlEscape(content)
	}
	return name + "=" + curlEscape(content)
}

// curlEscape percent-encodes every byte but letters, digits and -._~, as
// curl_easy_escape does.
func curlEscape(value string) string {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("-._~", c) >= 0 {
			out.WriteByte(c)
		} else {
			fmt.Fprintf(&out, "%%%02X", c)
		}
	}
	return out.String()
}

func containsForceBody(bodies []string) bool {
	for _, body := range bodies {
		var value map[string]any
		if json.Unmarshal([]byte(body), &value) == nil {
			if force, ok := value["force"].(bool); ok && force {
				return true
			}
		}
		if body == "force=true" {
			return true
		}
	}
	return false
}

func containsForceField(fields []string) bool {
	for _, field := range fields {
		if field == "force=true" {
			return true
		}
	}
	return false
}

func hasArg(args []string, values ...string) bool {
	for _, arg := range args {
		for _, value := range values {
			if arg == value {
				return true
			}
		}
	}
	return false
}

func hasPrefix(value string, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

// hasForceRefspec reports a `+<refspec>` argument. The plus forces the
// update whether or not a destination is spelled out after a colon.
func hasForceRefspec(refspecs []string) bool {
	for _, refspec := range refspecs {
		if strings.HasPrefix(refspec, "+") {
			return true
		}
	}
	return false
}

func isWriteMethod(method string) bool {
	switch method {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

func replaceFact(facts []string, old, replacement string) []string {
	for i := range facts {
		if facts[i] == old {
			facts[i] = replacement
		}
	}
	return facts
}

func projection(program string, facts, features []string, complete bool) cedareval.ShellProjectionV2 {
	if !complete {
		facts = append(append([]string{}, facts...), FactParseIncomplete)
	}
	return cedareval.ShellProjectionV2{
		Version:       1,
		Program:       program,
		Facts:         sortedUnique(facts),
		Features:      sortedUnique(features),
		ParseComplete: complete,
	}
}

func sortedUnique(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if value != "" && (len(result) == 0 || result[len(result)-1] != value) {
			result = append(result, value)
		}
	}
	return result
}

var ghWriteCommands = map[string]bool{
	"ssh-key/add": true, "ssh-key/delete": true, "gpg-key/add": true, "gpg-key/delete": true,
	"codespace/create": true, "codespace/delete": true, "codespace/rebuild": true, "codespace/stop": true,
	"gist/create": true, "gist/delete": true, "gist/edit": true,
	"issue/close": true, "issue/create": true, "issue/delete": true, "issue/develop": true, "issue/edit": true, "issue/reopen": true, "issue/transfer": true,
	"label/clone": true, "label/create": true, "label/delete": true, "label/edit": true,
	"pr/close": true, "pr/comment": true, "pr/create": true, "pr/edit": true, "pr/merge": true, "pr/ready": true, "pr/reopen": true, "pr/review": true,
	"release/create": true, "release/delete": true, "release/delete-asset": true, "release/edit": true, "release/upload": true,
	"repo/archive": true, "repo/create": true, "repo/delete": true, "repo/edit": true, "repo/fork": true, "repo/rename": true, "repo/sync": true, "repo/unarchive": true,
	"repo/autolink/create": true, "repo/autolink/delete": true, "repo/deploy-key/add": true, "repo/deploy-key/delete": true,
	"run/cancel": true, "run/delete": true, "run/rerun": true,
	"secret/delete": true, "secret/set": true, "variable/delete": true, "variable/set": true,
	"workflow/disable": true, "workflow/enable": true, "workflow/run": true,
}

var ghReadCommands = map[string]bool{
	"ssh-key/list": true, "gpg-key/list": true,
	"auth/status": true, "codespace/list": true, "gist/clone": true, "gist/list": true, "gist/view": true,
	"issue/list": true, "issue/status": true, "issue/view": true, "label/list": true,
	"pr/checks": true, "pr/diff": true, "pr/list": true, "pr/status": true, "pr/view": true,
	"release/download": true, "release/list": true, "release/view": true,
	"repo/clone": true, "repo/list": true, "repo/view": true,
	"repo/autolink/list": true, "repo/autolink/view": true, "repo/deploy-key/list": true,
	"run/list": true, "run/view": true, "run/watch": true, "search": true,
	"secret/list": true, "status": true, "variable/list": true, "workflow/list": true, "workflow/view": true,
}

// ghNestedCommands take their verb as a third word (`repo deploy-key add`).
var ghNestedCommands = map[string]bool{"repo/autolink": true, "repo/deploy-key": true}

// isMethodOverrideHeader reports whether a curl header asks the server to
// treat the request as a different HTTP method.
func isMethodOverrideHeader(header string) bool {
	name, _, _ := strings.Cut(header, ":")
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "x-http-method-override", "x-http-method", "x-method-override":
		return true
	}
	return false
}
