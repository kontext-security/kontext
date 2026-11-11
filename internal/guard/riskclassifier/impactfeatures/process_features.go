package impactfeatures

// Process facts encode documented argv and shell context, never an alert verdict.
import (
	"mvdan.cc/sh/v3/syntax"
	"path"
	"regexp"
	"strconv"
	"strings"
)

type processPass struct {
	e     *extractor
	nodes int
}

var intText = regexp.MustCompile(`^[+-]?(0|[1-9][0-9]*)$`)
var compareText = regexp.MustCompile(`^([+-]?(?:0|[1-9][0-9]*))\s*(==|!=|<=|>=|<|>|-eq|-ne|-lt|-le|-gt|-ge)\s*([+-]?(?:0|[1-9][0-9]*))$`)
var testCompareText = regexp.MustCompile(`^([+-]?(?:0|[1-9][0-9]*))\s+(==|!=|<=|>=|<|>|-eq|-ne|-lt|-le|-gt|-ge)\s+([+-]?(?:0|[1-9][0-9]*))$`)
var commLiteral = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func constantText(s string) int {
	s = strings.TrimSpace(s)
	testForm := strings.HasPrefix(s, "[[") || strings.HasPrefix(s, "[")
	for _, pair := range [][2]string{{"((", "))"}, {"[[", "]]"}, {"[", "]"}} {
		if strings.HasPrefix(s, pair[0]) && strings.HasSuffix(s, pair[1]) {
			s = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(s, pair[0]), pair[1]))
			break
		}
	}
	if intText.MatchString(s) && !testForm {
		n, err := strconv.ParseInt(s, 10, 64)
		if err == nil {
			if n == 0 {
				return -1
			}
			return 1
		}
	}
	m := compareText.FindStringSubmatch(s)
	if testForm {
		m = testCompareText.FindStringSubmatch(s)
	}
	if m == nil {
		return 0
	}
	a, ea := strconv.ParseInt(m[1], 10, 64)
	b, eb := strconv.ParseInt(m[3], 10, 64)
	if ea != nil || eb != nil {
		return 0
	}
	v := false
	if testForm && (m[2] == "==" || m[2] == "!=" || m[2] == "<" || m[2] == ">") {
		switch m[2] {
		case "==":
			v = m[1] == m[3]
		case "!=":
			v = m[1] != m[3]
		case "<":
			v = m[1] < m[3]
		case ">":
			v = m[1] > m[3]
		}
		if v {
			return 1
		}
		return -1
	}
	switch m[2] {
	case "==", "-eq":
		v = a == b
	case "!=", "-ne":
		v = a != b
	case "<", "-lt":
		v = a < b
	case "<=", "-le":
		v = a <= b
	case ">", "-gt":
		v = a > b
	case ">=", "-ge":
		v = a >= b
	}
	if v {
		return 1
	}
	return -1
}
func constantStmt(source string, s *syntax.Stmt, blocked bool) int {
	if s == nil {
		return 0
	}
	// Bash returns success for the asynchronous list, not the background
	// command's eventual status. This also applies when that job is negated.
	if s.Background {
		return 1
	}
	if len(s.Redirs) > 0 {
		return 0
	}
	v := 0
	switch c := s.Cmd.(type) {
	case *syntax.CallExpr:
		if blocked || len(c.Assigns) > 0 {
			return 0
		}
		if len(c.Args) > 0 {
			name, ok := literal(c.Args[0])
			if ok {
				switch name {
				case "false":
					if len(c.Args) == 1 {
						v = -1
					}
				case "true", ":":
					v = 1
				case "[", "test":
					ws := []string{}
					for _, w := range c.Args[1:] {
						z, k := literal(w)
						if !k {
							return 0
						}
						ws = append(ws, z)
					}
					if name == "[" {
						if len(ws) == 0 || ws[len(ws)-1] != "]" {
							return 0
						}
						ws = ws[:len(ws)-1]
					}
					if len(ws) == 3 {
						v = constantText("[ " + strings.Join(ws, " ") + " ]")
					}
				}
			}
		}
	case *syntax.ArithmCmd, *syntax.TestClause:
		v = constantText(slice(source, c))
	}
	if s.Negated {
		v = -v
	}
	return v
}
func inStatements(n syntax.Node, ss []*syntax.Stmt) bool {
	return len(ss) > 0 && n.Pos().Offset() >= ss[0].Pos().Offset() && n.Pos().Offset() < ss[len(ss)-1].End().Offset()
}
func contextMode(source, base string, n syntax.Node, stack []syntax.Node, blocked bool) string {
	if base != "executed" {
		return base
	}
	for _, ancestor := range stack {
		switch a := ancestor.(type) {
		case *syntax.FuncDecl:
			return "definition"
		case *syntax.BinaryCmd:
			if n.Pos().Offset() >= a.Y.Pos().Offset() {
				v := constantStmt(source, a.X, blocked)
				if a.Op.String() == "&&" && v == -1 || a.Op.String() == "||" && v == 1 {
					return "unreachable"
				}
			}
		case *syntax.IfClause:
			if len(a.Cond) > 0 {
				v := constantStmt(source, a.Cond[len(a.Cond)-1], blocked)
				if v == -1 && inStatements(n, a.Then) || v == 1 && a.Else != nil && n.Pos().Offset() >= a.Else.Pos().Offset() {
					return "unreachable"
				}
			}
		case *syntax.WhileClause:
			if len(a.Cond) > 0 {
				v := constantStmt(source, a.Cond[len(a.Cond)-1], blocked)
				if a.Until {
					v = -v
				}
				if v == -1 && inStatements(n, a.Do) {
					return "unreachable"
				}
			}
		}
	}
	return base
}
func (e *extractor) augmentProcesses(source string) {
	p := processPass{e: e}
	p.walk(source, "executed", 0)
}
func (p *processPass) walk(source, base string, depth int) {
	if depth > maxScriptDepth {
		p.e.out.Status = "limit_exceeded"
		return
	}
	tree, err := syntax.NewParser(syntax.Variant(syntax.LangBash), syntax.KeepComments(true)).Parse(strings.NewReader(source), "")
	if err != nil {
		return
	}
	blocked := false
	syntax.Walk(tree, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.FuncDecl:
			if x.Name.Value == "true" || x.Name.Value == "false" || x.Name.Value == "test" || x.Name.Value == ":" || x.Name.Value == "[" {
				blocked = true
			}
		case *syntax.CallExpr:
			if len(x.Args) > 0 {
				name, k := literal(x.Args[0])
				if k && (name == "alias" || name == "source" || name == "." || name == "eval" || name == "enable") {
					blocked = true
				}
			}
		}
		return true
	})
	stack := []syntax.Node{}
	syntax.Walk(tree, func(n syntax.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		p.nodes++
		if p.nodes > maxNodes || len(stack) >= maxDepth {
			p.e.out.Status = "limit_exceeded"
			return false
		}
		if p.e.out.Status == "limit_exceeded" {
			return false
		}
		if c, ok := n.(*syntax.CallExpr); ok {
			mode := contextMode(source, base, n, stack, blocked)
			words := []string{}
			known := []bool{}
			for _, w := range c.Args {
				v, k := literal(w)
				if !k {
					v = slice(source, w)
				}
				words = append(words, v)
				known = append(known, k)
			}
			wi, ok := effectiveCommand(words, known)
			if ok && wi < len(words) {
				name := path.Base(words[wi])
				ws, ks := words[wi:], known[wi:]
				switch name {
				case "pkill", "pgrep", "pidwait", "killall", "kill":
					p.facts(mode, name, ws, ks)
				}
				switch name {
				case "bash", "sh", "dash", "ksh", "zsh":
					index, hasC, noexec, uncertain, stdin := shellMode(ws, ks)
					childMode := mode
					if childMode == "executed" {
						if uncertain {
							childMode = "unresolved_shell"
						} else if noexec {
							childMode = "syntax_only"
						}
					}
					if hasC && index >= 0 && index < len(ws) && ks[index] {
						p.walk(ws[index], childMode, depth+1)
					}
					if stdin && !hasC {
						for i := len(stack) - 1; i >= 0; i-- {
							if stmt, yes := stack[i].(*syntax.Stmt); yes {
								for _, r := range stmt.Redirs {
									if r.Hdoc != nil {
										if body, k := literal(r.Hdoc); k {
											p.walk(body, childMode, depth+1)
										}
									}
								}
								break
							}
						}
					}
				case "eval":
					all := len(ws) > 1
					for _, k := range ks[1:] {
						all = all && k
					}
					if all {
						p.walk(strings.Join(ws[1:], " "), mode, depth+1)
					}
				}
			}
		}
		stack = append(stack, n)
		return true
	})
}

// Static wrapper boundaries only. Unknown syntax remains unresolved.
func effectiveCommand(ws []string, ks []bool) (int, bool) {
	i := 0
	for count := 0; count < 8 && i < len(ws); count++ {
		if !ks[i] {
			return i, false
		}
		cmd := path.Base(ws[i])
		i++
		switch cmd {
		case "sudo":
			for i < len(ws) && strings.HasPrefix(ws[i], "-") {
				o := ws[i]
				i++
				if o == "--" {
					break
				}
				if !ks[i-1] {
					return i, false
				}
				switch o {
				case "-u", "-g", "-h", "-p", "-C", "-T", "--user", "--group", "--host", "--prompt":
					if i >= len(ws) || !ks[i] {
						return i, false
					}
					i++
				case "-n", "-E", "-H", "-S", "-b", "-k", "--non-interactive", "--preserve-env":
				case "-l", "--list", "-v", "--validate", "-V", "--version", "--help":
					return i, false
				default:
					if !strings.HasPrefix(o, "--user=") && !strings.HasPrefix(o, "--group=") {
						return i, false
					}
				}
			}
		case "env":
			for i < len(ws) {
				o := ws[i]
				if !ks[i] {
					return i, false
				}
				if o == "--" {
					i++
					break
				}
				if assignment.MatchString(o) {
					i++
					continue
				}
				if o == "-i" || o == "--ignore-environment" {
					i++
					continue
				}
				if o == "-u" || o == "--unset" || o == "-C" || o == "--chdir" {
					i += 2
					if i > len(ws) {
						return i, false
					}
					continue
				}
				if strings.HasPrefix(o, "--unset=") || strings.HasPrefix(o, "--chdir=") {
					i++
					continue
				}
				if strings.HasPrefix(o, "-") {
					return i, false
				}
				break
			}
		case "command":
			if i < len(ws) && (ws[i] == "-v" || ws[i] == "-V") {
				return i, false
			}
			if i < len(ws) && (ws[i] == "-p" || ws[i] == "--") {
				i++
			}
		case "builtin", "exec", "nohup":
			if i < len(ws) && ws[i] == "--" {
				i++
			}
		case "nice":
			if i < len(ws) && (ws[i] == "-n" || ws[i] == "--adjustment") {
				i += 2
			} else if i < len(ws) && strings.HasPrefix(ws[i], "-") && intText.MatchString(ws[i]) {
				i++
			}
			if i > len(ws) {
				return i, false
			}
		default:
			return i - 1, true
		}
	}
	return i, false
}
func shellMode(ws []string, ks []bool) (index int, hasC, noexec, uncertain, stdin bool) {
	index = -1
	stdin = true
	interactive := false
	i := 1
	for i < len(ws) {
		if !ks[i] {
			uncertain = true
			return
		}
		s := ws[i]
		if s == "--" {
			i++
			break
		}
		if s == "-" {
			i++
			break
		}
		if !strings.HasPrefix(s, "-") && !strings.HasPrefix(s, "+") {
			break
		}
		on := s[0] == '-'
		if strings.HasPrefix(s, "--") {
			switch s {
			case "--noprofile", "--norc", "--posix", "--restricted", "--verbose", "--login":
			case "--rcfile", "--init-file":
				i++
				if i >= len(ws) {
					uncertain = true
					return
				}
			default:
				uncertain = true
			}
			i++
			continue
		}
		for _, f := range s[1:] {
			switch f {
			case 'n':
				noexec = on
			case 'i':
				interactive = on
			case 'c':
				hasC = on
			case 'o', 'O':
				i++
				if i >= len(ws) || !ks[i] {
					uncertain = true
					return
				}
				if ws[i] == "noexec" {
					noexec = on
				}
			case 'a', 'b', 'e', 'f', 'h', 'k', 'm', 'p', 's', 't', 'u', 'v', 'x', 'B', 'C', 'E', 'H', 'P', 'T', 'l':
			default:
				uncertain = true
			}
		}
		i++
	}
	if interactive {
		noexec = false
	}
	if hasC {
		if i < len(ws) {
			index = i
		} else {
			uncertain = true
		}
		stdin = false
	} else if i < len(ws) {
		stdin = false
	}
	return
}
func signalKind(s string) string {
	s = strings.TrimPrefix(s, "SIG")
	switch s {
	case "0":
		return "probe"
	case "TERM", "KILL", "INT", "QUIT", "HUP", "ABRT", "15", "9", "2", "3", "6":
		return "termination_or_reload"
	case "STOP", "TSTP", "TTIN", "TTOU":
		return "stop"
	case "CONT":
		return "continue"
	case "USR1", "USR2", "CHLD", "CLD", "ALRM", "PIPE", "WINCH", "URG", "TRAP", "FPE", "ILL", "SEGV", "BUS", "XCPU", "XFSZ", "VTALRM", "PROF", "SYS", "RTMIN", "RTMAX":
		return "other_signal"
	default:
		return "other_or_unverified"
	}
}
func (p *processPass) facts(mode, utility string, ws []string, ks []bool) {
	prefix := "process/" + mode + "/"
	add := func(k string) { p.e.add(prefix + k) }
	add("utility=" + utility)
	purpose := "signal"
	if utility == "pgrep" {
		purpose = "inspect"
	}
	if utility == "pidwait" {
		purpose = "wait"
	}
	signal := "TERM"
	sigSet := false
	exact, full, regex := false, false, false
	selectors := 0
	operands := []int{}
	unknown := false
	ended := false
	selector := func(kind, value string, known bool) {
		selectors++
		add("selector=" + kind)
		if known {
			add("selector_value=fixed")
			if value == "0" {
				add("selector_zero=" + kind)
			}
			if strings.Contains(value, ",") {
				add("selector_union=" + kind)
			}
		} else {
			add("selector_value=dynamic")
		}
	}
	for i := 1; i < len(ws); i++ {
		s := ws[i]
		if !ks[i] {
			operands = append(operands, i)
			continue
		}
		if s == "--" {
			ended = true
			continue
		}
		if !ended && strings.HasPrefix(s, "-") && s != "-" {
			if s == "--help" || s == "--version" || s == "-V" {
				purpose = "query"
				continue
			}
			if utility == "kill" && (s == "-l" || s == "-L") {
				purpose = "query"
				continue
			}
			if utility == "killall" && s == "-l" {
				purpose = "query"
				continue
			}
			if utility == "pkill" || utility == "pgrep" || utility == "pidwait" {
				long := strings.SplitN(s, "=", 2)
				o := long[0]
				value := ""
				hasValue := false
				kinds := map[string]string{"--euid": "user", "--uid": "real_user", "--pgroup": "group", "--parent": "parent", "--session": "session", "--terminal": "terminal", "--pidfile": "pidfile", "--ns": "namespace", "--nslist": "namespace_list", "--cgroup": "cgroup", "--env": "environment", "--older": "age"}
				if kind, ok := kinds[o]; ok {
					if len(long) == 2 {
						value = long[1]
						hasValue = true
					} else if i+1 < len(ws) {
						i++
						value = ws[i]
						hasValue = ks[i]
					}
					selector(kind, value, hasValue)
					continue
				}
				switch o {
				case "--full":
					full = true
					continue
				case "--exact":
					exact = true
					continue
				case "--newest", "--oldest":
					add("narrowing=" + o)
					continue
				case "--list-name", "--list-full":
					if utility == "pgrep" {
						continue
					}
					unknown = true
					continue
				case "--signal":
					if len(long) == 2 {
						signal = long[1]
						sigSet = true
					} else if i+1 < len(ws) {
						i++
						signal = ws[i]
						sigSet = ks[i]
					}
					continue
				case "--queue", "--delimiter":
					if len(long) == 1 {
						i++
					}
					continue
				}
				if !strings.HasPrefix(s, "--") {
					tail := s[1:]
					if signalKind(tail) != "other_or_unverified" || intText.MatchString(tail) {
						signal = tail
						sigSet = true
						continue
					}
					consumed := false
					for j, f := range tail {
						kind := ""
						switch f {
						case 'u':
							kind = "user"
						case 'U':
							kind = "real_user"
						case 'g':
							kind = "group"
						case 'P':
							kind = "parent"
						case 's':
							kind = "session"
						case 't':
							kind = "terminal"
						case 'F':
							kind = "pidfile"
						case 'O':
							kind = "age"
						}
						if kind != "" {
							value = ""
							known := false
							if j+1 < len(tail) {
								value = tail[j+1:]
								known = true
							} else if i+1 < len(ws) {
								i++
								value = ws[i]
								known = ks[i]
							}
							selector(kind, value, known)
							consumed = true
							break
						}
						switch f {
						case 'f':
							full = true
						case 'x':
							exact = true
						case 'n', 'o':
							add("narrowing=" + string(f))
						case 'l', 'a', 'c':
							if utility != "pgrep" {
								unknown = true
							}
						case 'e', 'A', 'L', 'w':
						case 'v':
							if utility == "pkill" {
								unknown = true
							}
						case 'q', 'd':
							if j+1 == len(tail) {
								i++
							}
							consumed = true
						default:
							unknown = true
						}
						if consumed {
							break
						}
					}
					continue
				}
			} else {
				if strings.HasPrefix(s, "--signal=") {
					signal = strings.TrimPrefix(s, "--signal=")
					sigSet = true
					continue
				}
				if utility == "killall" && strings.HasPrefix(s, "--user=") {
					selector("user", strings.TrimPrefix(s, "--user="), true)
					continue
				}
				if (s == "-s" || s == "--signal" || utility == "kill" && s == "-n") && i+1 < len(ws) {
					if utility == "killall" && s == "-s" {
						add("platform_ambiguous_s")
					}
					i++
					signal = ws[i]
					sigSet = ks[i]
					continue
				}
				if utility == "killall" && (s == "-u" || s == "--user") && i+1 < len(ws) {
					i++
					selector("user", ws[i], ks[i])
					continue
				}
				if utility == "killall" && (s == "-r" || s == "--regexp" || s == "-m") {
					regex = true
					continue
				}
				if utility == "killall" && s == "-d" {
					add("platform_debug_d")
					continue
				}
				if utility == "kill" && sigSet && intText.MatchString(s) {
					operands = append(operands, i)
					continue
				}
				tail := s[1:]
				if !sigSet && (signalKind(tail) != "other_or_unverified" || intText.MatchString(tail)) {
					signal = tail
					sigSet = true
					continue
				}
				if s == "-q" || s == "-v" || s == "-w" || s == "-I" || s == "-i" || s == "-e" {
					add("option=" + s)
					continue
				}
			}
			unknown = true
			continue
		}
		operands = append(operands, i)
	}
	if purpose == "signal" && signalKind(signal) == "probe" {
		purpose = "probe"
	}
	add("purpose=" + purpose)
	add("signal=" + signalKind(signal))
	if unknown {
		add("unverified_option")
	}
	if full {
		add("match=full_command")
	}
	if exact {
		add("match=exact")
	}
	if regex {
		add("match=regex")
	}
	add("operand_count=" + strconv.Itoa(min(len(operands), 4)))
	for _, i := range operands {
		kind := "name"
		if full {
			kind = "full_command"
		}
		if utility == "kill" {
			kind = "pid"
		}
		selector(kind, ws[i], ks[i])
		if !ks[i] {
			continue
		}
		v := ws[i]
		plain := strings.TrimSuffix(strings.TrimPrefix(v, "^"), "$")
		if !full && (utility == "pkill" || utility == "pgrep" || utility == "pidwait") && commLiteral.MatchString(plain) && len(plain) > 15 {
			add("pattern=linux_comm_literal_over15")
		}
		if utility == "kill" {
			if v == "0" || strings.HasPrefix(v, "-") {
				add("pid_scope=cohort")
			} else if strings.HasPrefix(v, "%") {
				add("pid_scope=job")
			} else {
				add("pid_scope=single_or_unverified")
			}
		}
		if full || regex || utility == "pkill" || utility == "pgrep" {
			if strings.HasPrefix(v, "^") {
				add("pattern=start_anchor")
			}
			if strings.HasSuffix(v, "$") {
				add("pattern=end_anchor")
			}
			if strings.Contains(v, ".*") {
				add("pattern=any_span")
			}
			if strings.Contains(v, "|") {
				add("pattern=union")
			}
			if strings.ContainsAny(v, "[]") {
				add("pattern=character_class")
			}
			if strings.Contains(v, "/") {
				add("pattern=path")
			}
			if v == "" {
				add("pattern=empty")
			}
		}
	}
	add("selector_count=" + strconv.Itoa(min(selectors, 4)))
}
