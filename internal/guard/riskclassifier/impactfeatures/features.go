// Package impactfeatures provides shared inert features for training and native scoring.
// It parses syntax only: never expands variables, reads paths, or runs commands.
package impactfeatures

import (
	"math"
	"path"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"mvdan.cc/sh/v3/syntax"
)

// TrainingVersion pins the unchanged frozen artifact. Version identifies the
// serving semantics, including the asynchronous-list correction in 2.1.
const TrainingVersion = "kontext-command-risk-features/2"
const Version = "kontext-command-risk-features/2.1"
const MaxCommandBytes = 64 * 1024
const maxNodes = 10000
const maxDepth = 128
const maxScriptDepth = 4

type Features struct {
	Version    string             `json:"version"`
	Status     string             `json:"status"`
	Characters map[string]float64 `json:"characters"`
	Tokens     map[string]float64 `json:"tokens"`
	Structure  map[string]float64 `json:"structure"`
}
type extractor struct {
	out                Features
	nodes, scriptDepth int
}

func Extract(command string) Features {
	e := &extractor{out: Features{Version: Version, Status: "parsed", Characters: map[string]float64{}, Tokens: map[string]float64{}, Structure: map[string]float64{}}}
	if len(command) > MaxCommandBytes {
		e.out.Status = "limit_exceeded"
		return e.out
	}
	e.out.Structure["length_log"] = math.Log1p(float64(utf8.RuneCountInString(command)))
	e.out.Structure["lines_log"] = math.Log1p(float64(strings.Count(command, "\n")))
	e.out.Structure["single_quotes_log"] = math.Log1p(float64(strings.Count(command, "'")))
	e.out.Structure["double_quotes_log"] = math.Log1p(float64(strings.Count(command, "\"")))
	e.parse(command, false, nil)
	if e.out.Status != "limit_exceeded" {
		e.augmentProcesses(command)
	}
	if e.out.Status == "limit_exceeded" {
		e.out.Characters = nil
		e.out.Tokens = nil
		e.out.Structure = nil
		return e.out
	}
	textCounts(command, e.out.Characters, e.out.Tokens)
	for k, v := range e.out.Structure {
		if v > 64 {
			e.out.Structure[k] = 64
		}
	}
	return e.out
}

func textCounts(s string, chars, tokens map[string]float64) {
	lower := strings.ToLower(s)
	// Like the prior char analyzer, collapse whitespace runs of length>=2.
	r := []rune(lower)
	norm := make([]rune, 0, len(r))
	for i := 0; i < len(r); {
		j := i + 1
		if unicode.IsSpace(r[i]) {
			for j < len(r) && unicode.IsSpace(r[j]) {
				j++
			}
			if j-i >= 2 {
				norm = append(norm, ' ')
			} else {
				norm = append(norm, r[i])
			}
		} else {
			norm = append(norm, r[i])
		}
		i = j
	}
	for n := 3; n <= 5; n++ {
		for i := 0; i+n <= len(norm); i++ {
			chars[string(norm[i:i+n])]++
		}
	}
	words := strings.Fields(lower)
	for n := 1; n <= 3; n++ {
		for i := 0; i+n <= len(words); i++ {
			tokens[strings.Join(words[i:i+n], " ")]++
		}
	}
}
func (e *extractor) add(k string)             { e.out.Structure[k]++ }
func (e *extractor) addv(k string, v float64) { e.out.Structure[k] += v }
func nodeKind(n syntax.Node) string           { return reflect.TypeOf(n).Elem().Name() }

func (e *extractor) parse(source string, nested bool, inherited []string) {
	if e.scriptDepth > maxScriptDepth {
		e.out.Status = "limit_exceeded"
		return
	}
	tree, err := syntax.NewParser(syntax.Variant(syntax.LangBash), syntax.KeepComments(true)).Parse(strings.NewReader(source), "")
	if err != nil {
		if !nested {
			e.out.Status = "syntax_error_text_only"
			e.out.Structure["parse_success"] = 0
			e.add("parse_error")
		} else {
			e.add("nested_parse_error")
		}
		return
	}
	if !nested {
		e.out.Structure["parse_success"] = 1
	}
	e.add("parsed_script")
	stack := []syntax.Node{}
	syntax.Walk(tree, func(n syntax.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		e.nodes++
		if e.nodes > maxNodes || len(stack) >= maxDepth {
			e.out.Status = "limit_exceeded"
			return false
		}
		if e.out.Status == "limit_exceeded" {
			return false
		}
		kind := nodeKind(n)
		parent := "root"
		if len(stack) > 0 {
			parent = nodeKind(stack[len(stack)-1])
		}
		e.add("node=" + kind)
		e.add("edge=" + parent + ">" + kind)
		if float64(len(stack)) > e.out.Structure["maximum_depth"] {
			e.out.Structure["maximum_depth"] = float64(len(stack))
		}
		contexts := append([]string{}, inherited...)
		if nested {
			contexts = append(contexts, "literal_script")
		}
		for _, a := range stack {
			switch a := a.(type) {
			case *syntax.FuncDecl:
				contexts = append(contexts, "definition")
			case *syntax.CmdSubst, *syntax.ProcSubst:
				contexts = append(contexts, "substitution")
			case *syntax.DblQuoted:
				contexts = append(contexts, "double_quoted")
			case *syntax.IfClause:
				contexts = append(contexts, "if")
			case *syntax.WhileClause, *syntax.ForClause:
				contexts = append(contexts, "loop")
			case *syntax.BinaryCmd:
				side := "lhs"
				if n.Pos().Offset() >= a.Y.Pos().Offset() {
					side = "rhs"
				}
				op := a.Op.String()
				if op == "&&" {
					op = "and"
				} else if op == "||" {
					op = "or"
				} else {
					op = "pipe"
				}
				contexts = append(contexts, op+"_"+side)
			}
		}
		switch x := n.(type) {
		case *syntax.Comment:
			e.add("comment")
			e.addv("comment_length_log", math.Log1p(float64(len(x.Text))))
		case *syntax.Stmt:
			if x.Negated {
				e.add("negated")
			}
			if x.Background {
				e.add("background")
			}
		case *syntax.BinaryCmd:
			e.add("binary_op=" + x.Op.String())
			if c, ok := x.X.Cmd.(*syntax.CallExpr); ok && len(c.Args) > 0 {
				if s, ok := literal(c.Args[0]); ok {
					e.add("binary_left_program=" + x.Op.String() + "|" + short(path.Base(s), 80))
				}
			}
		case *syntax.Redirect:
			e.add("redir_op=" + x.Op.String())
			if x.Hdoc != nil {
				e.add("heredoc")
			}
			if x.Word != nil {
				s, ok := literal(x.Word)
				if !ok {
					s = slice(source, x.Word)
				}
				e.add("redir_target_shape=" + shape(s))
				e.lexical("<redirection>", s, 1)
			}
		case *syntax.ParamExp:
			e.add("parameter_expansion")
		case *syntax.SglQuoted:
			e.add("single_quoted_literal")
		case *syntax.DblQuoted:
			if _, ok := literalParts(x.Parts); ok {
				e.add("double_quoted_literal")
			}
		case *syntax.CallExpr:
			e.call(source, x, contexts, len(stack))
		}
		stack = append(stack, n)
		return true
	})
}
func short(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}
func slice(source string, n syntax.Node) string {
	a, b := int(n.Pos().Offset()), int(n.End().Offset())
	if a < 0 || b < a || b > len(source) {
		return "<unresolved>"
	}
	return source[a:b]
}
func literal(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", false
	}
	return literalParts(w.Parts)
}
func literalParts(parts []syntax.WordPart) (string, bool) {
	var b strings.Builder
	for _, p := range parts {
		switch p := p.(type) {
		case *syntax.Lit:
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			if p.Dollar {
				return "", false
			}
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			s, ok := literalParts(p.Parts)
			if !ok {
				return "", false
			}
			b.WriteString(s)
		default:
			return "", false
		}
	}
	return b.String(), true
}

var number = regexp.MustCompile(`^[-+]?\d+(?:\.\d+)?$`)
var assignment = regexp.MustCompile(`^[A-Za-z_][\w-]*=`)
var digits = regexp.MustCompile(`\d+`)
var extension = regexp.MustCompile(`^[A-Za-z0-9_-]{1,12}$`)

func shape(s string) string {
	switch {
	case s == "":
		return "empty"
	case number.MatchString(s):
		return "number"
	case strings.ContainsAny(s, "$`"):
		return "expansion"
	case strings.Contains(s, "://"):
		return "url"
	case strings.HasPrefix(s, "/"):
		return "absolute_path"
	case strings.HasPrefix(s, "~/") || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../"):
		return "relative_path"
	case strings.Contains(s, "/"):
		return "slash_word"
	case strings.HasPrefix(s, "--"):
		return "long_option"
	case strings.HasPrefix(s, "-") && s != "-":
		return "short_option"
	case assignment.MatchString(s):
		return "assignment"
	default:
		return "plain"
	}
}
func (e *extractor) lexical(cmd, s string, index int) {
	role := shape(s)
	e.add("arg_shape=" + role)
	e.add("cmd_shape=" + cmd + "|" + role)
	e.add("position_shape=" + strconv.Itoa(min(index, 6)) + "|" + role)
	if role == "short_option" || role == "long_option" {
		opt := short(strings.SplitN(s, "=", 2)[0], 80)
		e.add("option=" + opt)
		e.add("cmd_option=" + cmd + "|" + opt)
	}
	if role == "absolute_path" || role == "relative_path" || role == "slash_word" {
		parts := strings.FieldsFunc(s, func(r rune) bool { return r == '/' })
		e.add("path_depth=" + strconv.Itoa(min(len(parts), 8)))
		if len(parts) > 0 {
			prefix := short(digits.ReplaceAllString(parts[0], "#"), 48)
			e.add("path_prefix=" + prefix)
			e.add("cmd_path_prefix=" + cmd + "|" + prefix)
			last := parts[len(parts)-1]
			if i := strings.LastIndexByte(last, '.'); i >= 0 && extension.MatchString(last[i+1:]) {
				e.add("extension=" + strings.ToLower(last[i+1:]))
			}
		}
		if strings.ContainsAny(s, "*?[") {
			e.add("path_wildcard")
		}
		for _, p := range parts {
			if p == ".." {
				e.add("path_parent_segment")
				break
			}
		}
	}
	if role == "number" {
		if v, err := strconv.ParseFloat(s, 64); err == nil && !math.IsInf(v, 0) {
			if v == 0 {
				e.add("numeric_zero")
			}
			if v < 0 {
				e.add("numeric_negative")
			}
			e.addv("numeric_log_magnitude", min(16, math.Log1p(math.Abs(v))))
		}
	}
}
func (e *extractor) call(source string, c *syntax.CallExpr, contexts []string, depth int) {
	if len(c.Args) == 0 {
		e.add("assignment_only")
		return
	}
	words := make([]string, len(c.Args))
	known := make([]bool, len(c.Args))
	for i, w := range c.Args {
		words[i], known[i] = literal(w)
		if !known[i] {
			words[i] = slice(source, w)
		}
	}
	cmd := "<dynamic>"
	if known[0] {
		cmd = short(path.Base(words[0]), 80)
	}
	e.add("command=" + cmd)
	e.add("command_depth=" + strconv.Itoa(min(depth, 8)) + "|" + cmd)
	e.add("arity=" + strconv.Itoa(min(len(words)-1, 12)))
	seen := map[string]bool{}
	for _, cx := range contexts {
		if !seen[cx] {
			e.add("context=" + cx)
			e.add("context_command=" + cx + "|" + cmd)
			seen[cx] = true
		}
	}
	for i, s := range words[1:] {
		e.lexical(cmd, s, i+1)
	}
	for i := 1; i+1 < len(words); i++ {
		if strings.HasPrefix(words[i], "-") {
			e.add("cmd_option_next_shape=" + cmd + "|" + short(strings.SplitN(words[i], "=", 2)[0], 40) + "|" + shape(words[i+1]))
		}
	}
	// Literal shell command strings add syntax evidence, never execution or a safety verdict.
	if cmd == "bash" || cmd == "sh" || cmd == "dash" || cmd == "ksh" || cmd == "zsh" {
		for i := 1; i < len(words); i++ {
			if !known[i] {
				e.add("dynamic_script")
				break
			}
			if !strings.HasPrefix(words[i], "-") {
				break
			}
			if !strings.HasPrefix(words[i], "--") && strings.Contains(words[i], "c") {
				if i+1 < len(words) && known[i+1] {
					e.add("literal_script")
					e.scriptDepth++
					e.parse(words[i+1], true, contexts)
					e.scriptDepth--
				} else {
					e.add("dynamic_script")
				}
				break
			}
		}
	}
	if cmd == "eval" {
		all := true
		for _, ok := range known[1:] {
			all = all && ok
		}
		if all && len(words) > 1 {
			e.add("literal_eval")
			e.scriptDepth++
			e.parse(strings.Join(words[1:], " "), true, contexts)
			e.scriptDepth--
		} else {
			e.add("dynamic_script")
		}
	}
}
