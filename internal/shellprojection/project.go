package shellprojection

import (
	"encoding/json"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
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
	return project(command, 0)
}

func project(command string, depth int) []cedareval.ShellProjectionV2 {
	if len(command) > maxCommandBytes {
		return []cedareval.ShellProjectionV2{parseFailure("command-too-large")}
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "command")
	if err != nil {
		return []cedareval.ShellProjectionV2{parseFailure("syntax-error")}
	}

	calls := make([]*syntax.CallExpr, 0, 4)
	nodes, nesting := 0, 0
	tooComplex := false
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
		if call, ok := node.(*syntax.CallExpr); ok && len(call.Args) > 0 {
			calls = append(calls, call)
		}
		return true
	})
	if tooComplex {
		return []cedareval.ShellProjectionV2{parseFailure("syntax-too-complex")}
	}
	sort.SliceStable(calls, func(i, j int) bool { return calls[i].Pos().Offset() < calls[j].Pos().Offset() })

	projections := make([]cedareval.ShellProjectionV2, 0, len(calls))
	for _, call := range calls {
		words, complete := literalWords(call.Args)
		projections = append(projections, classify(words, complete, depth)...)
	}
	if len(projections) == 0 {
		projections = append(projections, projection("unknown", nil, []string{"empty-command"}, false))
	}
	return projections
}

func parseFailure(reason string) cedareval.ShellProjectionV2 {
	return projection("unknown", nil, []string{FeatureParseError, reason}, false)
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

func classify(words []string, complete bool, depth int) []cedareval.ShellProjectionV2 {
	words, complete, wrapper, ok := unwrap(words, complete)
	if !ok {
		return single(projection(wrapper, nil, []string{"unrecognized-wrapper-arguments"}, false))
	}
	if len(words) == 0 || words[0] == "" {
		return single(projection("dynamic", nil, []string{"dynamic-program"}, false))
	}
	program := filepath.Base(words[0])
	args := words[1:]
	switch program {
	case "git":
		return single(classifyGit(args, complete))
	case "gh":
		return single(classifyGH(args, complete))
	case "curl":
		return single(classifyCurl(args, complete))
	case "bash", "sh", "zsh", "dash", "ksh":
		return classifyShell(program, args, complete, depth)
	case "eval":
		return classifyEval(args, complete, depth)
	default:
		return single(projection(program, nil, nil, complete))
	}
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
func classifyShell(program string, args []string, complete bool, depth int) []cedareval.ShellProjectionV2 {
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
	if !commandFlag {
		return single(projection(program, nil, nil, complete))
	}
	if i >= len(args) {
		return single(projection(program, nil, []string{"missing-script"}, false))
	}
	return nestedScript(program, args[i], depth)
}

// classifyEval joins eval's arguments the way the shell does and classifies
// the resulting script.
func classifyEval(args []string, complete bool, depth int) []cedareval.ShellProjectionV2 {
	if len(args) == 0 {
		return single(projection("eval", nil, []string{"empty-command"}, complete))
	}
	if !complete {
		return single(projection("eval", nil, []string{"dynamic-script"}, false))
	}
	return nestedScript("eval", strings.Join(args, " "), depth)
}

func nestedScript(program, script string, depth int) []cedareval.ShellProjectionV2 {
	if script == "" {
		return single(projection(program, nil, []string{"dynamic-script"}, false))
	}
	if depth >= maxScriptDepth {
		return single(projection(program, nil, []string{"script-depth-exceeded"}, false))
	}
	inner := project(script, depth+1)
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

func classifyGH(args []string, complete bool) cedareval.ShellProjectionV2 {
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
	if ghWriteCommands[key] {
		facts := []string{"gh/command=" + key, "github/route=catalogued", "github/write=true"}
		facts = append(facts, operationFacts(ghOperations(key, rest))...)
		return projection("gh", facts, nil, complete)
	}
	if ghReadCommands[key] || ghReadCommands[args[0]] {
		return projection("gh", []string{"gh/command=" + key, "github/route=catalogued"}, nil, complete)
	}
	return projection("gh", []string{"gh/command=" + key, FactRouteUnrecognized}, nil, false)
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

func classifyCurl(args []string, complete bool) cedareval.ShellProjectionV2 {
	method := "GET"
	explicitMethod := false
	urlText := ""
	bodies := make([]string, 0, 2)
	valueOptions := map[string]bool{"-H": true, "--header": true, "-A": true, "--user-agent": true, "-u": true, "--user": true, "-o": true, "--output": true, "--connect-timeout": true, "--max-time": true, "--retry": true}
	safeFlags := map[string]bool{"-s": true, "-S": true, "-sS": true, "--silent": true, "--show-error": true, "--fail": true, "--fail-with-body": true, "--compressed": true}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-X" || arg == "--request":
			if i+1 >= len(args) {
				complete = false
				continue
			}
			i++
			method, explicitMethod = strings.ToUpper(args[i]), true
		case strings.HasPrefix(arg, "-X") && len(arg) > 2:
			method, explicitMethod = strings.ToUpper(arg[2:]), true
		case strings.HasPrefix(arg, "--request="):
			method, explicitMethod = strings.ToUpper(strings.TrimPrefix(arg, "--request=")), true
		case arg == "-I" || arg == "--head":
			method, explicitMethod = "HEAD", true
		case arg == "-G" || arg == "--get":
			method, explicitMethod = "GET", true
		case arg == "--url":
			if i+1 >= len(args) {
				complete = false
				continue
			}
			i++
			urlText = args[i]
		case strings.HasPrefix(arg, "--url="):
			urlText = strings.TrimPrefix(arg, "--url=")
		case isCurlDataFlag(arg):
			if i+1 >= len(args) {
				complete = false
				continue
			}
			i++
			bodies = append(bodies, args[i])
			if strings.HasPrefix(args[i], "@") {
				complete = false
			}
			if !explicitMethod {
				method = "POST"
			}
		case curlDataValue(arg) != "":
			body := curlDataValue(arg)
			bodies = append(bodies, body)
			if strings.HasPrefix(body, "@") {
				complete = false
			}
			if !explicitMethod {
				method = "POST"
			}
		case arg == "-T" || arg == "--upload-file":
			if i+1 >= len(args) {
				complete = false
				continue
			}
			i++
			if !explicitMethod {
				method = "PUT"
			}
		case strings.HasPrefix(arg, "--upload-file="):
			if !explicitMethod {
				method = "PUT"
			}
		case valueOptions[arg]:
			if i+1 >= len(args) {
				complete = false
				continue
			}
			i++
		case safeFlags[arg]:
		case strings.HasPrefix(arg, "-"):
			// Unknown curl flags can change request behavior.
			complete = false
		case urlText == "":
			urlText = arg
		}
	}
	parsed, err := url.Parse(urlText)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return projection("curl", nil, []string{"dynamic-or-invalid-url"}, false)
	}
	host := strings.ToLower(parsed.Hostname())
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

func curlDataValue(arg string) string {
	for _, prefix := range []string{"--data=", "--data-raw=", "--data-binary=", "--data-urlencode=", "--data-ascii=", "--json=", "--form=", "--form-string="} {
		if strings.HasPrefix(arg, prefix) {
			return strings.TrimPrefix(arg, prefix)
		}
	}
	if strings.HasPrefix(arg, "-d") && len(arg) > 2 || strings.HasPrefix(arg, "-F") && len(arg) > 2 {
		return arg[2:]
	}
	return ""
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
