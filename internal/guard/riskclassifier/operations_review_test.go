package riskclassifier_test

// Review regressions exercise the public model entry point with inert input.
// Failure modes: false clean partial scans; dead-code alerts; child/function
// scope leaks; option-dependent scores; malformed calls; unbounded parse/copy
// work; and replay output paths that alias the input or an existing receipt.
import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/guard/riskclassifier"
)

func TestAWSOperationReviewRegressions(t *testing.T) {
	m, err := riskclassifier.LoadOperationModel()
	if err != nil {
		t.Fatal(err)
	}
	aws := `aws secretsmanager get-secret-value --secret-id fixture`
	cases := []struct {
		name, command string
		risky         bool
	}{
		{"exit-in-if", `if true; then exit 0; fi; ` + aws, false},
		{"exit-in-block", `{ exit 0; }; ` + aws, false},
		{"exit-in-function", `f(){ exit 0; }; f; ` + aws, false},
		{"return-in-function", `f(){ if true; then return 0; fi; ` + aws + `; }; f`, false},
		{"return-stays-in-function", `f(){ return 0; }; f; ` + aws, true},
		{"unknown-branch-exit", `if unknown; then exit 0; fi; ` + aws, true},
		{"exit-in-subshell", `(exit 0); ` + aws, true},
		{"exit-in-substitution", `echo "$(exit 0)"; ` + aws, true},
		{"exit-in-child-shell", `bash -c 'exit 0'; ` + aws, true},
		{"exit-in-background", `exit 0 & ` + aws, true},
		{"background-starts-successfully", `f(){ false & }; f && ` + aws, true},
		{"background-status-is-not-job-status", `f(){ false & }; f || ` + aws, false},
		{"coprocess-exit-is-local", `coproc { exit 0; }; ` + aws, true},
		{"coprocess-functions-are-local", `coproc { aws(){ :; }; }; ` + aws, true},
		{"coprocess-start-status", `coproc { false; } || ` + aws, false},
		{"exit-in-pipeline", `exit 0 | cat; ` + aws, true},
		{"exec-replaces-shell", `exec true; ` + aws, false},
		{"exec-replaces-in-block", `{ exec true; }; ` + aws, false},
		{"exec-redirection-only", `exec >/dev/null; ` + aws, true},
		{"exec-unreached", `false && exec true; ` + aws, true},
		{"exec-unknown-branch", `unknown && exec true; ` + aws, true},
		{"exec-dynamic-command", `exec "$PROGRAM"; ` + aws, true},
		{"exec-process-name", `exec -a label ` + aws, true},
		{"exec-combined-flags", `exec -cla label ` + aws, true},
		{"function-success-or", `f(){ true; }; f || ` + aws, false},
		{"function-failure-and", `f(){ false; }; f && ` + aws, false},
		{"function-success-and", `f(){ true; }; f && ` + aws, true},
		{"function-failure-or", `f(){ false; }; f || ` + aws, true},
		{"function-return-or", `f(){ return 0; }; f || ` + aws, false},
		{"unmatched-case-function", `case x in y) f(){ ` + aws + `; };; esac; f`, false},
		{"unmatched-case-call", `case x in y) ` + aws + `;; esac`, false},
		{"matched-case-function", `case x in x) f(){ ` + aws + `; };; esac; f`, true},
		{"case-glob", `case xyz in x*) ` + aws + `;; esac`, true},
		{"case-quoted-glob", `case xyz in 'x*') ` + aws + `;; esac`, false},
		{"case-first-match", `case x in x) true;; *) ` + aws + `;; esac`, false},
		{"case-fallthrough", `case x in x) true;& y) ` + aws + `;; esac`, true},
		{"case-resume", `case x in x) true;;& y) ` + aws + `;; esac`, false},
		{"child-function-not-leaked", `bash -c 'aws(){ :; }'; ` + aws, true},
		{"parent-function-not-inherited", `aws(){ :; }; bash -c '` + aws + `'`, true},
		{"parent-function-restored", `aws(){ :; }; bash -c 'aws(){ false; }'; ` + aws, false},
		{"missing-value", `aws secretsmanager get-secret-value --secret-id`, false},
		{"flag-instead-of-value", `aws secretsmanager get-secret-value --secret-id --profile p`, false},
		{"missing-leading-global-value", `aws --profile`, false},
		{"missing-trailing-global-value", aws + ` --profile`, false},
		{"dynamic-argument-value", `aws secretsmanager get-secret-value --secret-id "$SECRET"`, true},
		{"unknown-argument", aws + ` --bogus value`, false},
		{"command-bypasses-function", `aws(){ :; }; command ` + aws, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := m.Classify(c.command)
			if (got.Verdict == riskclassifier.VerdictRisky) != c.risky {
				t.Fatalf("got %+v", got)
			}
		})
	}
	for _, flag := range []string{`--profile fixture`, `--region eu-west-1`, `--profile=fixture`, `--debug`} {
		a := m.Classify("aws " + flag + " secretsmanager get-secret-value --secret-id fixture")
		b := m.Classify("aws secretsmanager " + flag + " get-secret-value --secret-id fixture")
		c := m.Classify(aws + " " + flag)
		if a.Score == nil || b.Score == nil || c.Score == nil || math.Abs(*a.Score-*b.Score) > 1e-12 || math.Abs(*a.Score-*c.Score) > 1e-12 {
			t.Errorf("placement %s: %+v %+v %+v", flag, a, b, c)
		}
	}
}

func TestAWSOperationIncompleteAndWorkLimits(t *testing.T) {
	m, err := riskclassifier.LoadOperationModel()
	if err != nil {
		t.Fatal(err)
	}
	aws := `aws secretsmanager get-secret-value --secret-id fixture`
	routine := strings.Repeat("aws sts get-caller-identity; ", 1024)
	var copies strings.Builder
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&copies, "f%d(){ :; }; ", i)
	}
	copies.WriteString(strings.Repeat(`echo "$(true)"; `, 1000))
	cases := []struct {
		name, command string
		positive      bool
	}{
		{"negative-partial", routine + aws, false},
		{"positive-partial", aws + "; " + routine, true},
		{"repeated-parsing", `f(){ bash -c '` + strings.Repeat("# comment\n", 20000) + `'; }; ` + strings.Repeat("f; ", 1000), false},
		{"scope-copy-budget", copies.String(), false},
		{"case-pattern-budget", `f(){ case x in ` + strings.Repeat("x", 10000) + `) :;; esac; }; ` + strings.Repeat("f; ", 1000), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			start := time.Now()
			got := m.Classify(c.command)
			if got.Status != "limit_exceeded" {
				t.Fatalf("got %+v", got)
			}
			if c.positive {
				if got.Score == nil || got.Verdict != riskclassifier.VerdictRisky {
					t.Fatalf("lost positive: %+v", got)
				}
			} else if got.Score != nil || got.Verdict != "" {
				t.Fatalf("incomplete negative looks evaluated: %+v", got)
			}
			if time.Since(start) > 2*time.Second {
				t.Fatal("resource guard exceeded two seconds")
			}
		})
	}
}

func TestAWSOperationReplayOutputSafety(t *testing.T) {
	for _, kind := range []string{"lexical-alias", "symlink", "hardlink", "existing-receipt"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "corpus.jsonl")
			body := []byte("{\"id\":\"fixture\",\"command\":\"echo ready\"}\n")
			if err := os.WriteFile(input, body, 0600); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(dir, "receipt.jsonl")
			switch kind {
			case "lexical-alias":
				output = dir + "/./corpus.jsonl"
			case "symlink":
				if err := os.Symlink(input, output); err != nil {
					t.Skip(err)
				}
			case "hardlink":
				if err := os.Link(input, output); err != nil {
					t.Skip(err)
				}
			case "existing-receipt":
				if err := os.WriteFile(output, body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestAWSOperationLocalCorpusReplay$")
			cmd.Env = append(os.Environ(), "KONTEXT_OPERATIONS_REPLAY_INPUT="+input, "KONTEXT_OPERATIONS_REPLAY_OUTPUT="+output)
			if out, err := cmd.CombinedOutput(); err == nil {
				t.Fatalf("existing output accepted: %s", out)
			}
			for _, p := range []string{input, output} {
				got, err := os.ReadFile(p)
				if err != nil || string(got) != string(body) {
					t.Fatalf("modified %s: %q %v", p, got, err)
				}
			}
		})
	}
}
