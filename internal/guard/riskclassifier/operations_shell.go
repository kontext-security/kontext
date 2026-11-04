package riskclassifier

import (
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Limits are explicit abstentions, never truncation followed by a clean label.
const operationMaxBytes = 1024 * 1024
const operationMaxNodes = 100000
const operationMaxDepth = 128
const operationMaxCalls = 1024
const operationMaxRecursion = 128

type awsOperation struct {
	service, operation string
	flags              []string
}
type awsArgumentTypes = map[string]map[string]map[string]string

type operationWalk struct {
	types            awsArgumentTypes
	ops              []awsOperation
	functions        map[string]*syntax.Stmt
	visiting         map[string]bool
	steps, recursion int
	status           string
}

func extractAWSOperations(command string, types awsArgumentTypes) ([]awsOperation, string) {
	if len(command) > operationMaxBytes {
		return nil, "limit_exceeded"
	}
	w := &operationWalk{types: types, functions: map[string]*syntax.Stmt{}, visiting: map[string]bool{}}
	w.parse(command)
	if w.status != "" {
		return w.ops, w.status
	}
	if len(w.ops) == 0 {
		return nil, "unsupported"
	}
	return w.ops, "evaluated"
}

func (w *operationWalk) parse(command string) {
	if w.recursion >= operationMaxRecursion {
		w.status = "limit_exceeded"
		return
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil {
		w.status = "parse_error"
		return
	}
	depth := 0
	syntax.Walk(file, func(node syntax.Node) bool {
		if node == nil {
			depth--
			return true
		}
		depth++
		w.steps++
		if depth > operationMaxDepth || w.steps > operationMaxNodes {
			w.status = "limit_exceeded"
			depth--
			return false
		}
		return true
	})
	if w.status == "limit_exceeded" {
		return
	}
	w.recursion++
	w.list(file.Stmts)
	w.recursion--
}

// list follows known constant guards, but never runs a shell. Unknown branches
// are possible executions rather than assertions about what already happened.
func (w *operationWalk) list(stmts []*syntax.Stmt) int {
	result := -1
	for _, stmt := range stmts {
		if w.status == "limit_exceeded" {
			break
		}
		result = w.stmt(stmt)
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && !stmt.Negated && !stmt.Background && len(call.Args) > 0 {
			name, _ := operationLiteral(call.Args[0])
			if name == "exit" || name == "return" {
				break
			}
		}
	}
	return result
}

func (w *operationWalk) stmt(stmt *syntax.Stmt) int {
	if stmt == nil {
		return -1
	}
	w.steps++
	if w.steps > operationMaxNodes || w.recursion >= operationMaxRecursion || len(w.ops) >= operationMaxCalls {
		w.status = "limit_exceeded"
		return -1
	}
	w.recursion++
	defer func() { w.recursion-- }()
	if fn, ok := stmt.Cmd.(*syntax.FuncDecl); ok {
		if fn.Name != nil {
			body := *fn.Body
			body.Redirs = append(append([]*syntax.Redirect{}, body.Redirs...), stmt.Redirs...)
			w.functions[fn.Name.Value] = &body
		}
		return 0
	}
	for _, redir := range stmt.Redirs {
		w.word(redir.Word)
		w.word(redir.Hdoc)
	}
	result := -1
	switch c := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		for _, a := range c.Assigns {
			w.word(a.Value)
			w.expansions(a.Array)
			w.expansions(a.Index)
		}
		for _, a := range c.Args {
			w.word(a)
		}
		result = w.call(c)
	case *syntax.Block:
		result = w.list(c.Stmts)
	case *syntax.Subshell:
		// Definitions in a subshell must not leak into the enclosing shell.
		functions := w.functions
		w.functions = cloneOperationFunctions(functions)
		result = w.list(c.Stmts)
		w.functions = functions
	case *syntax.BinaryCmd:
		left := w.stmt(c.X)
		if c.Op == syntax.AndStmt && left == 1 || c.Op == syntax.OrStmt && left == 0 {
			result = left
		} else {
			result = w.stmt(c.Y)
			if left < 0 && (c.Op == syntax.AndStmt || c.Op == syntax.OrStmt) {
				result = -1
			}
		}
	case *syntax.IfClause:
		result = w.ifClause(c)
	case *syntax.WhileClause:
		cond := w.list(c.Cond)
		if !(cond == 1 && !c.Until || cond == 0 && c.Until) {
			w.list(c.Do)
		}
	case *syntax.ForClause:
		if loop, ok := c.Loop.(*syntax.WordIter); ok {
			for _, item := range loop.Items {
				w.word(item)
			}
			if loop.InPos.IsValid() && len(loop.Items) == 0 {
				break
			}
		} else {
			w.expansions(c.Loop)
		}
		w.list(c.Do)
	case *syntax.CaseClause:
		w.word(c.Word)
		for _, item := range c.Items {
			for _, pattern := range item.Patterns {
				w.word(pattern)
			}
			w.list(item.Stmts)
		}
	case *syntax.DeclClause:
		for _, a := range c.Args {
			w.word(a.Value)
			w.expansions(a.Array)
			w.expansions(a.Index)
		}
	case *syntax.TimeClause:
		result = w.stmt(c.Stmt)
	case *syntax.CoprocClause:
		result = w.stmt(c.Stmt)
	default:
		w.expansions(c)
	}
	if stmt.Negated && result >= 0 {
		result = 1 - result
	}
	return result
}

func (w *operationWalk) ifClause(c *syntax.IfClause) int {
	if len(c.Cond) == 0 {
		return w.list(c.Then)
	}
	condition := w.list(c.Cond)
	if condition == 0 {
		return w.list(c.Then)
	}
	if condition < 0 {
		w.list(c.Then)
		if c.Else != nil {
			w.ifClause(c.Else)
		}
		return -1
	}
	if c.Else != nil {
		return w.ifClause(c.Else)
	}
	return -1
}

func cloneOperationFunctions(src map[string]*syntax.Stmt) map[string]*syntax.Stmt {
	dst := make(map[string]*syntax.Stmt, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func (w *operationWalk) word(word *syntax.Word) {
	if word != nil {
		w.expansions(word)
	}
}

func (w *operationWalk) expansions(node syntax.Node) {
	if node == nil {
		return
	}
	// An interface can contain a typed nil (Assign.Array, for example).
	switch n := node.(type) {
	case *syntax.ArrayExpr:
		if n == nil {
			return
		}
	case *syntax.Word:
		if n == nil {
			return
		}
	}
	syntax.Walk(node, func(n syntax.Node) bool {
		switch n := n.(type) {
		case *syntax.CmdSubst:
			functions := w.functions
			w.functions = cloneOperationFunctions(functions)
			w.list(n.Stmts)
			w.functions = functions
			return false
		case *syntax.ProcSubst:
			functions := w.functions
			w.functions = cloneOperationFunctions(functions)
			w.list(n.Stmts)
			w.functions = functions
			return false
		}
		return w.status != "limit_exceeded"
	})
}

func (w *operationWalk) call(c *syntax.CallExpr) int {
	if len(c.Args) == 0 {
		return -1
	}
	argv := make([]string, len(c.Args))
	for i, arg := range c.Args {
		value, ok := operationLiteral(arg)
		if !ok {
			value = "\x00"
		}
		argv[i] = value
	}
	// Wrappers describe invocation syntax; none assigns a risk label.
	for len(argv) > 0 {
		name := path.Base(argv[0])
		switch name {
		case "env":
			argv = argv[1:]
			for len(argv) > 0 {
				a := argv[0]
				if a == "--" {
					argv = argv[1:]
					break
				}
				if a == "-u" || a == "--unset" || a == "-C" || a == "--chdir" {
					if len(argv) < 2 {
						return -1
					}
					argv = argv[2:]
					continue
				}
				if strings.HasPrefix(a, "-") || strings.Contains(a, "=") {
					argv = argv[1:]
					continue
				}
				break
			}
		case "command", "exec", "nohup":
			argv = argv[1:]
			for len(argv) > 0 && (argv[0] == "--" || argv[0] == "-p") {
				argv = argv[1:]
			}
		case "sudo":
			argv = argv[1:]
			for len(argv) > 0 && strings.HasPrefix(argv[0], "-") {
				flag := argv[0]
				argv = argv[1:]
				if flag == "--" {
					break
				}
				if flag == "-u" || flag == "-g" || flag == "-h" || flag == "-p" || flag == "-C" || flag == "-T" || flag == "--user" || flag == "--group" {
					if len(argv) == 0 {
						return -1
					}
					argv = argv[1:]
				}
			}
		default:
			if fn := w.functions[argv[0]]; fn != nil {
				if w.visiting[argv[0]] {
					w.status = "limit_exceeded"
					return -1
				}
				w.visiting[argv[0]] = true
				w.stmt(fn)
				delete(w.visiting, argv[0])
				return -1
			}
			if name == "bash" || name == "sh" || name == "dash" {
				for i := 1; i < len(argv); i++ {
					flag := argv[i]
					if flag == "--" || !strings.HasPrefix(flag, "-") {
						break
					}
					if flag == "-o" || flag == "-O" || flag == "--rcfile" || flag == "--init-file" {
						i++
						continue
					}
					if !strings.HasPrefix(flag, "--") && strings.Contains(flag, "c") && i+1 < len(argv) && argv[i+1] != "\x00" {
						w.parse(argv[i+1])
						break
					}
				}
				return -1
			}
			if name == "aws" {
				if op, ok := parseAWSOperation(argv, w.types); ok {
					w.ops = append(w.ops, op)
				}
				return -1
			}
			if len(argv) == 1 && len(c.Assigns) == 0 {
				if name == "true" || name == ":" {
					return 0
				}
				if name == "false" {
					return 1
				}
			}
			return -1
		}
	}
	return -1
}

var operationGlobalValues = map[string]bool{"--profile": true, "--region": true, "--endpoint-url": true, "--query": true, "--output": true, "--color": true, "--ca-bundle": true, "--cli-read-timeout": true, "--cli-connect-timeout": true, "--cli-binary-format": true, "--cli-input-json": true, "--cli-input-yaml": true}
var operationGlobalBools = map[string]bool{"--debug": true, "--no-verify-ssl": true, "--no-paginate": true, "--no-sign-request": true, "--no-cli-pager": true, "--cli-auto-prompt": true, "--no-cli-auto-prompt": true}

func parseAWSOperation(argv []string, types awsArgumentTypes) (awsOperation, bool) {
	i := 1
	var op awsOperation
	for i < len(argv) && (op.service == "" || op.operation == "") {
		arg := argv[i]
		flag, _, eq := strings.Cut(arg, "=")
		if operationGlobalValues[flag] {
			i++
			if !eq {
				i++
			}
			continue
		}
		if operationGlobalBools[flag] {
			i++
			continue
		}
		if strings.HasPrefix(arg, "-") || arg == "\x00" {
			return op, false
		}
		if op.service == "" {
			op.service = arg
		} else {
			op.operation = arg
		}
		i++
	}
	params, known := types[op.service][op.operation]
	if !known {
		return op, false
	}
	for i < len(argv) {
		arg := argv[i]
		flag, _, eq := strings.Cut(arg, "=")
		if arg == "help" || flag == "--generate-cli-skeleton" || op.service == "s3" && flag == "--dryrun" || op.service == "ec2" && flag == "--dry-run" {
			return op, false
		}
		if !strings.HasPrefix(arg, "--") {
			i++
			continue
		}
		op.flags = append(op.flags, flag)
		kind := params[flag]
		if kind == "" && strings.HasPrefix(flag, "--no-") {
			kind = params["--"+flag[5:]]
		}
		if operationGlobalBools[flag] {
			kind = "boolean"
		}
		i++
		if eq || kind == "boolean" {
			continue
		}
		if i < len(argv) {
			i++
		}
		if kind == "list" {
			for i < len(argv) && !strings.HasPrefix(argv[i], "--") && argv[i] != "help" {
				i++
			}
		}
	}
	return op, true
}

// operationLiteral accepts static shell words only. It deliberately does not
// expand variables, glob patterns, ANSI-C quotes or computed command names.
func operationLiteral(word *syntax.Word) (string, bool) {
	var out strings.Builder
	var parts func([]syntax.WordPart, bool) bool
	parts = func(items []syntax.WordPart, quoted bool) bool {
		for _, item := range items {
			switch item := item.(type) {
			case *syntax.Lit:
				for i := 0; i < len(item.Value); i++ {
					ch := item.Value[i]
					if ch == '\\' && i+1 < len(item.Value) {
						next := item.Value[i+1]
						if next == '\n' {
							i++
							continue
						}
						if !quoted || strings.ContainsRune("$`\"\\", rune(next)) {
							out.WriteByte(next)
							i++
							continue
						}
					}
					if !quoted && strings.ContainsRune("*?[]{}~", rune(ch)) {
						return false
					}
					out.WriteByte(ch)
				}
			case *syntax.SglQuoted:
				if item.Dollar {
					return false
				}
				out.WriteString(item.Value)
			case *syntax.DblQuoted:
				if item.Dollar || !parts(item.Parts, true) {
					return false
				}
			default:
				return false
			}
		}
		return true
	}
	if word == nil || !parts(word.Parts, false) {
		return "", false
	}
	return out.String(), true
}
