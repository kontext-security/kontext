package payloadcapture

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"mvdan.cc/sh/v3/syntax"
)

type commandVectorFile struct {
	Vectors []struct {
		Name           string   `json:"name"`
		Program        string   `json:"program"`
		Input          string   `json:"input"`
		Spans          [][2]int `json:"spans"`
		MustNotSurvive []string `json:"mustNotSurvive"`
		Expected       string   `json:"expected"`
	} `json:"vectors"`
	Prose       []string `json:"prose"`
	ArgvVectors []struct {
		Name     string `json:"name"`
		Value    any    `json:"value"`
		Expected any    `json:"expected"`
	} `json:"argvVectors"`
}

func loadCommandVectors(t testing.TB) commandVectorFile {
	t.Helper()
	var vectors commandVectorFile
	loadTestdata(t, "command-redaction-vectors.json", &vectors)
	if len(vectors.Vectors) == 0 || len(vectors.Prose) == 0 {
		t.Fatal("no command vectors loaded")
	}
	return vectors
}

// TestCommandVectors pins the command rules byte span for byte span; the
// same file pins kontext-cloud's command-redaction.ts.
func TestCommandVectors(t *testing.T) {
	t.Parallel()

	vectors := loadCommandVectors(t)
	covered := map[string]bool{}
	for _, vector := range vectors.Vectors {
		covered[vector.Program] = true
	}
	for _, program := range commandRules.Programs {
		if !covered[program.ID] {
			t.Errorf("command program %q has no vector", program.ID)
		}
	}
	for _, vector := range vectors.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			t.Parallel()

			var got [][2]int
			for _, span := range commandSpans(vector.Input) {
				got = append(got, [2]int{span.Start, span.End})
			}
			if !slices.Equal(got, vector.Spans) {
				t.Fatalf("commandSpans(%q) = %v, want %v", vector.Input, got, vector.Spans)
			}
			redacted, _ := RedactText(vector.Input)
			for _, secret := range vector.MustNotSurvive {
				if strings.Contains(redacted, secret) {
					t.Fatalf("secret %q survived: %q", secret, redacted)
				}
			}
			if redacted != vector.Expected {
				t.Fatalf("RedactText(%q) = %q, want %q", vector.Input, redacted, vector.Expected)
			}
			if again, _ := RedactText(redacted); again != redacted {
				t.Fatalf("redacting %q again gives %q", redacted, again)
			}
		})
	}
	for _, input := range vectors.Prose {
		if spans := commandSpans(input); len(spans) > 0 {
			t.Errorf("prose %q masked at %v", input, spans)
		}
		if redacted, changed := RedactText(input); changed {
			t.Errorf("prose %q redacted to %q", input, redacted)
		}
	}
}

// lexedWords is the source range of every argument word the lexer reads in
// src, sorted.
func lexedWords(src string) []Span {
	var words []Span
	l := &lexer{src: src, limit: len(src), words: &words}
	l.commands(0)
	slices.SortFunc(words, func(a, b Span) int { return a.Start - b.Start })
	return words
}

// shellWords is the source range of every assignment and argument word
// mvdan.cc/sh parses in src, sorted, or false when src holds anything the
// lexer reads differently by design: a compound command, a keyword, a
// comment, a heredoc, arithmetic, a process substitution, an array, a
// backslash inside backticks.
func shellWords(src string) ([]Span, bool) {
	if strings.ContainsAny(src, "#\r\x00") || strings.Contains(src, "<<") {
		return nil, false
	}
	// Inside backticks the shell reads backslashes once more before it
	// parses the command; the lexer reads them as written, which only
	// moves a mask by a byte.
	if strings.Contains(src, "`") && strings.Contains(src, "\\") {
		return nil, false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(src), "")
	if err != nil {
		return nil, false
	}
	var words []Span
	ok := true
	// mvdan counts a line continuation after a word into it in some
	// spellings and not in others; the lexer never does.
	span := func(node syntax.Node) Span {
		start, end := int(node.Pos().Offset()), int(node.End().Offset())
		for {
			if end-start >= 2 && src[end-2:end] == "\\\n" {
				end -= 2
			} else if end-start >= 1 && end < len(src) && src[end-1:end+1] == "\\\n" &&
				(end-start-len(strings.TrimRight(src[start:end], "\\")))%2 == 1 {
				// Or only its backslash ($0\<newline>), when that one is not
				// escaped itself (0\\<newline>).
				end--
			} else {
				break
			}
		}
		return Span{start, end}
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case nil, *syntax.File, *syntax.Word, *syntax.Lit, *syntax.SglQuoted, *syntax.DblQuoted,
			*syntax.ParamExp, *syntax.Redirect, *syntax.BinaryCmd:
		case *syntax.CmdSubst:
			// ${ cmd; } and ${| cmd; } run in the shell; the lexer reads
			// any ${…} as one opaque part.
			if n.TempFile || n.ReplyVar {
				ok = false
			}
		case *syntax.Stmt:
			if n.Negated || n.Coprocess {
				ok = false
			}
		case *syntax.CallExpr:
			for _, assign := range n.Assigns {
				if assign.Array != nil || assign.Index != nil || assign.Naked || assign.Append {
					ok = false
				}
				// mvdan ends an empty assignment at its name when a line
				// continuation comes before the = (A\<newline>=).
				if assign.Name != nil && assign.Value == nil &&
					!strings.HasPrefix(src[assign.Name.End().Offset():], "=") {
					ok = false
				}
				words = append(words, span(assign))
			}
			for _, arg := range n.Args {
				words = append(words, span(arg))
			}
		case *syntax.Assign:
		default:
			ok = false
		}
		return ok
	})
	slices.SortFunc(words, func(a, b Span) int { return a.Start - b.Start })
	return words, ok
}

// FuzzLexerMatchesShellParser checks the lexer's words against mvdan.cc/sh
// wherever the input is plain shell commands the parser accepts.
func FuzzLexerMatchesShellParser(f *testing.F) {
	vectors := loadCommandVectors(f)
	for _, vector := range vectors.Vectors {
		f.Add(vector.Input)
	}
	for _, input := range vectors.Prose {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, src string) {
		want, ok := shellWords(src)
		if !ok {
			return
		}
		if got := lexedWords(src); !slices.Equal(got, want) {
			t.Fatalf("%q: lexer words %v, shell words %v", src, got, want)
		}
	})
}

func TestLexerMatchesShellParserOnVectors(t *testing.T) {
	t.Parallel()

	vectors := loadCommandVectors(t)
	inputs := append([]string{}, vectors.Prose...)
	for _, vector := range vectors.Vectors {
		inputs = append(inputs, vector.Input)
	}
	compared := 0
	for _, src := range inputs {
		want, ok := shellWords(src)
		if !ok {
			continue
		}
		compared++
		if got := lexedWords(src); !slices.Equal(got, want) {
			t.Errorf("%q: lexer words %v, shell words %v", src, got, want)
		}
	}
	if compared < len(inputs)/2 {
		t.Fatalf("only %d of %d inputs compared", compared, len(inputs))
	}
}

// TestCommandSpansAreLinear pins the cost of inputs that are one long
// command naming a client again and again: each reading of a client's
// command line stops at the next word naming the same client.
func TestCommandSpansAreLinear(t *testing.T) {
	t.Parallel()

	for _, unit := range []string{"mysql -p\\\n", "redis-cli auth ", "mysql -u", "redis-cli -h", "mysql redis-cli ", `mysql -p"`} {
		input := strings.Repeat(unit, 131072/len(unit))
		started := time.Now()
		commandSpans(input)
		// About 0.2 s today on a busy runner; quadratic reading took minutes.
		if elapsed := time.Since(started); elapsed > 3*time.Second {
			t.Errorf("%q: 128 KB took %v", unit, elapsed)
		}
	}
}

// TestCommandSpansBoundNesting pins that substitutions nested far past
// maxDepth are masked whole without deep recursion.
func TestCommandSpansBoundNesting(t *testing.T) {
	t.Parallel()

	for _, open := range []string{"$(", "`", "\"$("} {
		input := "echo " + strings.Repeat(open, 20000) + "mysql -pFAKEhunter2 appdb"
		redacted, _ := RedactText(input)
		if strings.Contains(redacted, "FAKEhunter2") {
			t.Errorf("%q nested: secret survived", open)
		}
	}
}

// TestArgvVectors pins argument vectors in decoded JSON: an array of
// strings, or a {"command", "args"} pair, is read as one command line.
func TestArgvVectors(t *testing.T) {
	t.Parallel()

	var vectors commandVectorFile
	loadTestdata(t, "command-redaction-vectors.json", &vectors)
	if len(vectors.ArgvVectors) == 0 {
		t.Fatal("no argv vectors loaded")
	}
	for _, vector := range vectors.ArgvVectors {
		got, _ := RedactValue(vector.Value)
		if !reflect.DeepEqual(got, vector.Expected) {
			t.Errorf("%s: RedactValue(%v) = %v, want %v", vector.Name, vector.Value, got, vector.Expected)
		}
	}
}
