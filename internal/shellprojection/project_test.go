package shellprojection

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/cedareval"
)

type corpusCase struct {
	name        string
	command     string
	programs    []string
	facts       []string
	absentFacts []string
	features    []string
	complete    bool
}

const (
	forcePush    = "github/force-push=true"
	write        = "github/write=true"
	catalogued   = "github/route=catalogued"
	unrecognized = FactRouteUnrecognized
	incomplete   = FactParseIncomplete
)

func TestGitHubShellCorpus(t *testing.T) {
	runCorpus(t, []corpusCase{
		{name: "force short", command: "git push -f origin main", programs: []string{"git"}, facts: []string{forcePush, write, catalogued}, absentFacts: []string{incomplete}, complete: true},
		{name: "force long through path and env", command: "env CI=1 /usr/bin/git -C ./repo push --force origin main", programs: []string{"git"}, facts: []string{forcePush, write}, complete: true},
		{name: "mirror through sudo", command: "sudo -u build git push --mirror origin", programs: []string{"git"}, facts: []string{forcePush, write}, complete: true},
		{name: "force refspec", command: "command -- git push origin +main:main", programs: []string{"git"}, facts: []string{forcePush, write}, complete: true},
		{name: "force with lease remains safer", command: "git push --force-with-lease origin main", programs: []string{"git"}, facts: []string{write}, absentFacts: []string{forcePush}, complete: true},
		{name: "dry run has no write effect", command: "git push --dry-run --force origin main", programs: []string{"git"}, facts: []string{"github/dry-run=true"}, absentFacts: []string{forcePush, write}, complete: true},
		{name: "git lfs push", command: "git lfs push origin main", programs: []string{"git"}, facts: []string{write}, complete: true},
		{name: "gh write", command: "gh --repo acme/api pr merge 42", programs: []string{"gh"}, facts: []string{"gh/command=pr/merge", write}, complete: true},
		{name: "gh read", command: "gh pr view 42", programs: []string{"gh"}, facts: []string{"gh/command=pr/view", catalogued}, absentFacts: []string{write}, complete: true},
		{name: "gh unknown", command: "gh extension-command run", programs: []string{"gh"}, facts: []string{unrecognized, incomplete}, complete: false},
		{name: "gh api force", command: "gh api repos/acme/api/git/refs/heads/main -X PATCH -f force=true", programs: []string{"gh"}, facts: []string{forcePush, write, "http/method=PATCH"}, complete: true},
		{name: "curl force", command: `curl -X PATCH -d '{"force":true}' https://api.github.com/repos/acme/api/git/refs/heads/main`, programs: []string{"curl"}, facts: []string{forcePush, write, "http/method=PATCH"}, complete: true},
		{name: "curl --next keeps the first request's method", command: `curl -X PATCH -d '{"force":true}' https://api.github.com/repos/acme/api/git/refs/heads/main --next -X GET https://example.com`, programs: []string{"curl"}, facts: []string{forcePush, write, unrecognized}, complete: false},
		{name: "curl globbed url is not a catalogued route", command: `curl -X PATCH --json '{"force":true,"sha":"0123456789012345678901234567890123456789"}' 'https://api.github.com/repos/acme/api/git/re{f,f}s/heads/main'`, programs: []string{"curl"}, facts: []string{unrecognized, write}, absentFacts: []string{catalogued}, complete: false},
		{name: "curl request target not in origin form is not a catalogued route", command: "curl -X OPTIONS --request-target '*' https://api.github.com/repos/acme/api", programs: []string{"curl"}, facts: []string{unrecognized}, absentFacts: []string{catalogued}, complete: false},
		{name: "curl computed body stays incomplete for github", command: `curl -X PATCH --json "{\"sha\":\"$SHA\",\"force\":true}" https://api.github.com/repos/acme/api/git/refs/heads/main`, programs: []string{"curl"}, facts: []string{unrecognized, write}, absentFacts: []string{catalogued}, complete: false},
		{name: "curl compact json", command: `curl --request=PATCH --json='{"force":true}' https://api.github.com/repos/acme/api/git/refs/heads/main`, programs: []string{"curl"}, facts: []string{forcePush, write}, complete: true},
		{name: "curl upload", command: "curl -sS -T asset.zip https://uploads.github.com/repos/acme/api/releases/1/assets", programs: []string{"curl"}, facts: []string{write, "http/method=PUT"}, complete: true},
		{name: "curl read", command: "curl https://api.github.com/repos/acme/api", programs: []string{"curl"}, facts: []string{catalogued, "http/method=GET"}, absentFacts: []string{write}, complete: true},
		{name: "curl read with short fail flag", command: "curl -sf https://api.github.com/repos/acme/api", programs: []string{"curl"}, facts: []string{catalogued, "http/method=GET"}, absentFacts: []string{write}, complete: true},
		{name: "curl plain http keeps the github hint", command: "curl -L -X DELETE http://api.github.com/repos/acme/api", programs: []string{"curl"}, facts: []string{unrecognized, write, "http/method=DELETE"}, absentFacts: []string{catalogued}, complete: false},
		{name: "dynamic curl url", command: "curl \"$URL\"", programs: []string{"curl"}, facts: []string{incomplete}, complete: false},
		{name: "quoted chain and comment", command: "git 'status' && gh pr view 42 # read only", programs: []string{"git", "gh"}, facts: []string{"gh/command=pr/view"}, complete: true},
		{name: "one deny candidate in chain", command: "git status; git push -f origin main", programs: []string{"git", "git"}, facts: []string{forcePush}, complete: true},
		{name: "nested command", command: "echo $(git push -f origin main)", programs: []string{"echo", "git"}, facts: []string{forcePush}, complete: false},
		{name: "unrelated python", command: "python -c 'print(1)'", programs: []string{"python"}, absentFacts: []string{unrecognized}, complete: true},
	})
}

// TestForcePushBypassCorpus covers every shape that used to reach the remote
// without a force-push fact. Each positive case must carry the fact; each
// case the projection cannot see through must carry the unrecognized route.
func TestForcePushBypassCorpus(t *testing.T) {
	runCorpus(t, []corpusCase{
		{name: "clustered -fu", command: "git push -fu origin main", programs: []string{"git"}, facts: []string{forcePush, write}, complete: true},
		{name: "clustered -uf", command: "git push -uf origin main", programs: []string{"git"}, facts: []string{forcePush, write}, complete: true},
		{name: "clustered -fq after refspec", command: "git push origin main -qf", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "clustered dry run wins", command: "git push -fn origin main", programs: []string{"git"}, facts: []string{"github/dry-run=true"}, absentFacts: []string{forcePush, write}, complete: true},
		{name: "push option cluster is not force", command: "git push -oskip-f origin main", programs: []string{"git"}, facts: []string{write}, absentFacts: []string{forcePush}, complete: true},
		{name: "push option value is not a refspec", command: "git push -o +ci.skip origin main", programs: []string{"git"}, facts: []string{write}, absentFacts: []string{forcePush}, complete: true},
		{name: "plus refspec without colon", command: "git push origin +main", programs: []string{"git"}, facts: []string{forcePush, write}, complete: true},
		{name: "plus refspec after double dash", command: "git push -- origin +main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "backslash escaped program", command: `\git push -f origin main`, programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "beside a current-shell substitution in quotes", command: `git push -f origin main; echo "${ :; }"`, programs: []string{"git", "echo", ":"}, facts: []string{forcePush, write}, complete: false},
		{name: "backslash escaped flag", command: `git push \-f origin main`, programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "double quoted escapes", command: `"git" push "--force" origin main`, programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "exec wrapper", command: "exec git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "exec with name", command: "exec -a git /usr/bin/git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "timeout wrapper", command: "timeout 30 git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "timeout with options", command: "timeout -s KILL --kill-after=5 30s git push --force origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "nohup wrapper", command: "nohup git push -f origin main &", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "nice wrapper", command: "nice -n 10 git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "nice numeric wrapper", command: "nice -10 git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "time keyword", command: "time git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "time through sudo", command: "sudo time -p git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "xargs wrapper", command: "echo main | xargs git push -f origin", programs: []string{"echo", "git"}, facts: []string{forcePush, incomplete}, complete: false},
		{name: "xargs with options", command: "printf main | xargs -n1 -I{} git push --force origin {}", programs: []string{"printf", "git"}, facts: []string{forcePush}, complete: false},
		{name: "xargs -l takes no next word", command: "echo main | xargs -l git push --force origin", programs: []string{"echo", "git"}, facts: []string{forcePush}, complete: false},
		{name: "xargs --max-lines takes no next word", command: "echo main | xargs --max-lines git push --force origin", programs: []string{"echo", "git"}, facts: []string{forcePush}, complete: false},
		{name: "xargs --replace takes no next word", command: "echo main | xargs --replace git push --force origin", programs: []string{"echo", "git"}, facts: []string{forcePush}, complete: false},
		{name: "xargs --eof takes no next word", command: "echo main | xargs --eof git push --force origin", programs: []string{"echo", "git"}, facts: []string{forcePush}, complete: false},
		{name: "xargs attached line count", command: "echo main | xargs -l1 --max-lines=1 git push --force origin", programs: []string{"echo", "git"}, facts: []string{forcePush}, complete: false},
		{name: "xargs hides stdin arguments", command: "echo -f | xargs git push origin main", programs: []string{"echo", "git"}, facts: []string{unrecognized, write}, absentFacts: []string{forcePush}, complete: false},
		{name: "bash -c literal", command: "bash -c 'git push -f origin main'", programs: []string{"git"}, facts: []string{forcePush}, features: []string{"nested-script"}, complete: true},
		{name: "sh -c literal", command: `sh -c "git push --force origin main"`, programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "zsh -c with options", command: "/bin/zsh -lc 'git push -f origin main'", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "bash -ec script chain", command: "bash -ec 'set -e; git push -f origin main' && echo done", programs: []string{"set", "git", "echo"}, facts: []string{forcePush}, complete: true},
		{name: "bash -c read only", command: "bash -c 'git status'", programs: []string{"git"}, absentFacts: []string{forcePush, write, unrecognized}, complete: true},
		{name: "bash script file", command: "bash deploy.sh", programs: []string{"bash"}, absentFacts: []string{unrecognized}, complete: true},
		{name: "bash -c dynamic", command: `bash -c "$CMD"`, programs: []string{"bash"}, facts: []string{incomplete}, absentFacts: []string{unrecognized}, features: []string{"dynamic-script"}, complete: false},
		{name: "bash -c partially dynamic", command: `bash -c "git push $OPTS origin main"`, programs: []string{"bash"}, facts: []string{incomplete}, absentFacts: []string{unrecognized}, features: []string{"dynamic-script"}, complete: false},
		{name: "eval quoted", command: `eval "git push -f origin main"`, programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "eval bare words", command: "eval git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "eval dynamic", command: `eval "$CMD"`, programs: []string{"eval"}, facts: []string{incomplete}, absentFacts: []string{unrecognized}, complete: false},
		{name: "eval nested within bound", command: "eval eval eval eval git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "eval nested beyond bound", command: "eval eval eval eval eval git push -f origin main", programs: []string{"eval"}, facts: []string{incomplete}, absentFacts: []string{unrecognized}, features: []string{"script-depth-exceeded"}, complete: false},
		{name: "git alias definition", command: "git -c alias.p='push -f' p", programs: []string{"git"}, facts: []string{unrecognized, "git/subcommand=p"}, features: []string{"git-alias-definition"}, absentFacts: []string{forcePush}, complete: false},
		{name: "git alias definition beside push", command: "git -c alias.x=y push -f origin main", programs: []string{"git"}, facts: []string{unrecognized, forcePush}, complete: false},
		{name: "git config env alias", command: "git --config-env=alias.p=P p", programs: []string{"git"}, facts: []string{unrecognized}, complete: false},
		{name: "git config is not an alias", command: "git -c core.sshCommand=ssh push -f origin main", programs: []string{"git"}, facts: []string{forcePush, catalogued}, complete: true},
		{name: "git no-optional-locks global", command: "git --no-optional-locks push -f origin main", programs: []string{"git"}, facts: []string{forcePush, catalogued}, complete: true},
		{name: "git paginate global", command: "git -p push -f origin main", programs: []string{"git"}, facts: []string{forcePush, catalogued}, complete: true},
		{name: "git exec-path global", command: "git --exec-path=/opt/git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "git unknown global", command: "git --future-global push -f origin main", programs: []string{"git"}, facts: []string{unrecognized}, features: []string{"unknown-git-global"}, absentFacts: []string{forcePush}, complete: false},
		{name: "git dynamic subcommand", command: "git $SUB -f origin main", programs: []string{"git"}, facts: []string{unrecognized}, complete: false},
		{name: "push dynamic options", command: "git push $OPTS origin main", programs: []string{"git"}, facts: []string{unrecognized, write, incomplete}, absentFacts: []string{forcePush, catalogued}, complete: false},
		{name: "push dynamic remote with literal force", command: "git push -f $REMOTE main", programs: []string{"git"}, facts: []string{unrecognized, forcePush}, complete: false},
		{name: "dynamic program", command: "$GIT push -f origin main", programs: []string{"dynamic"}, facts: []string{incomplete}, absentFacts: []string{unrecognized, forcePush}, features: []string{"dynamic-program"}, complete: false},
		{name: "dynamic program path", command: `"$HOME/bin/x" --flag`, programs: []string{"dynamic"}, facts: []string{incomplete}, absentFacts: []string{unrecognized}, complete: false},
		{name: "wrapper with unknown option", command: "sudo --future git push -f origin main", programs: []string{"sudo"}, facts: []string{incomplete}, absentFacts: []string{unrecognized}, features: []string{"unrecognized-wrapper-arguments"}, complete: false},
		{name: "unrelated dynamic argument", command: `echo "$MSG"`, programs: []string{"echo"}, facts: []string{incomplete}, absentFacts: []string{unrecognized}, complete: false},
		{name: "command lookup is not execution", command: "command -v git", programs: []string{"command"}, absentFacts: []string{unrecognized}, complete: true},
		{name: "env alone", command: "env", programs: []string{"env"}, absentFacts: []string{unrecognized}, complete: true},
		{name: "gh api jq read", command: "gh api repos/o/r --jq .name", programs: []string{"gh"}, facts: []string{catalogued, "http/method=GET", "http/path=repos/o/r"}, absentFacts: []string{write, unrecognized}, complete: true},
		{name: "gh api paginate jq read", command: "gh api repos/o/r --paginate --jq '.[]'", programs: []string{"gh"}, facts: []string{catalogued, "http/method=GET"}, absentFacts: []string{write, unrecognized}, complete: true},
		{name: "gh api output flags read", command: "gh api -H 'Accept: application/vnd.github+json' --cache 1h --template '{{.name}}' -i --silent --hostname ghe.example.com -p corsair repos/o/r", programs: []string{"gh"}, facts: []string{catalogued, "http/method=GET"}, absentFacts: []string{write, unrecognized}, complete: true},
		{name: "gh api jq equals form read", command: "gh api --jq=.name --preview=corsair repos/o/r", programs: []string{"gh"}, facts: []string{catalogued}, absentFacts: []string{unrecognized}, complete: true},
		{name: "gh api delete with jq", command: "gh api -X DELETE repos/o/r --jq .", programs: []string{"gh"}, facts: []string{catalogued, write, "http/method=DELETE"}, absentFacts: []string{unrecognized}, complete: true},
		{name: "gh api field write with jq", command: "gh api repos/o/r/issues -f title=bug --jq .number", programs: []string{"gh"}, facts: []string{catalogued, write, "http/method=POST"}, absentFacts: []string{unrecognized}, complete: true},
		{name: "gh api unknown flag", command: "gh api repos/o/r --future-flag", programs: []string{"gh"}, facts: []string{unrecognized}, complete: false},
		{name: "gh api dynamic path", command: "gh api $ENDPOINT --jq .name", programs: []string{"gh"}, facts: []string{unrecognized}, complete: false},
		{name: "gh api input body", command: "gh api --input body.json repos/acme/api/issues", programs: []string{"gh"}, facts: []string{"http/method=POST", write, unrecognized}, complete: false},
		{name: "gh api input body with method", command: "gh api -X PATCH --input=body.json repos/acme/api/git/refs/heads/main", programs: []string{"gh"}, facts: []string{"http/method=PATCH", write, unrecognized}, complete: false},
		{name: "curl data-binary force", command: `curl -X PATCH --data-binary '{"force":true}' https://api.github.com/repos/acme/api/git/refs/heads/main`, programs: []string{"curl"}, facts: []string{forcePush, write}, complete: true},
		{name: "curl data-urlencode write", command: "curl --data-urlencode 'title=bug' https://api.github.com/repos/acme/api/issues", programs: []string{"curl"}, facts: []string{write, "http/method=POST"}, complete: true},
		{name: "curl data-ascii write", command: "curl --data-ascii='a=b' https://api.github.com/repos/acme/api/issues", programs: []string{"curl"}, facts: []string{write, "http/method=POST"}, complete: true},
	})
}

// TestUnrecognizedRouteOnlyForGitHubPrograms pins the contract the cloud
// presets rely on: github/route=unrecognized never appears unless the
// resolved program is git, gh or curl.
func TestUnrecognizedRouteOnlyForGitHubPrograms(t *testing.T) {
	commands := []string{
		`echo "unterminated`, "$GIT push -f origin main", `"$HOME/bin/x"`, `bash -c "$CMD"`, `eval "$CMD"`,
		"sudo --future git push -f origin main", "python -c 'print(1)'", `echo "$MSG"`, "# comment only",
		"eval eval eval eval eval git push -f origin main", strings.Repeat("x", maxCommandBytes+1),
		"git push -f origin main", "git --future push -f origin main", "gh weird", "curl https://api.github.com/x",
	}
	for _, command := range commands {
		for _, projection := range Project(command) {
			github := projection.Program == "git" || projection.Program == "gh" || projection.Program == "curl"
			if contains(projection.Facts, unrecognized) && !github {
				t.Errorf("%q: program %q carries %s", command, projection.Program, unrecognized)
			}
		}
	}
}

func TestParseFailuresBecomeProjections(t *testing.T) {
	runCorpus(t, []corpusCase{
		{name: "syntax error", command: "git push -f origin main; (", programs: []string{"git"}, facts: []string{incomplete}, absentFacts: []string{unrecognized}, features: []string{FeatureParseError, "syntax-error"}, complete: false},
		{name: "unrelated syntax error", command: `echo "unterminated`, programs: []string{"echo"}, facts: []string{incomplete}, absentFacts: []string{unrecognized}, features: []string{FeatureParseError, "syntax-error"}, complete: false},
		{name: "oversized", command: strings.Repeat("x", maxCommandBytes+1), programs: []string{"unknown"}, facts: []string{incomplete}, absentFacts: []string{unrecognized}, features: []string{FeatureParseError, "command-too-large"}, complete: false},
		{name: "oversized databricks keeps its program", command: "databricks clusters delete " + strings.Repeat("x", maxCommandBytes), programs: []string{"databricks"}, facts: []string{incomplete, FactDatabricksRouteUnrecognized, "databricks/delete=true"}, features: []string{FeatureParseError, "command-too-large"}, complete: false},
		{name: "too complex", command: strings.Repeat("(", maxSyntaxDepth+1) + "true" + strings.Repeat(")", maxSyntaxDepth+1), programs: []string{"unknown"}, facts: []string{incomplete}, absentFacts: []string{unrecognized}, features: []string{FeatureParseError, "syntax-too-complex"}, complete: false},
		{name: "empty", command: "# nothing", programs: []string{"unknown"}, facts: []string{incomplete}, features: []string{"empty-command"}, complete: false},
	})
}

func runCorpus(t *testing.T, tests []corpusCase) {
	t.Helper()
	runProjectionCorpus(t, Project, tests)
}

func runProjectionCorpus(t *testing.T, project func(string) []cedareval.ShellProjectionV2, tests []corpusCase) {
	t.Helper()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			projections := project(test.command)
			if len(projections) != len(test.programs) {
				t.Fatalf("program count = %d, want %d: %#v", len(projections), len(test.programs), projections)
			}
			allComplete := true
			allFacts := make([]string, 0)
			allFeatures := make([]string, 0)
			for i, projection := range projections {
				if projection.Program != test.programs[i] {
					t.Fatalf("program[%d] = %q, want %q", i, projection.Program, test.programs[i])
				}
				allComplete = allComplete && projection.ParseComplete
				allFacts = append(allFacts, projection.Facts...)
				allFeatures = append(allFeatures, projection.Features...)
				if projection.ParseComplete == contains(projection.Facts, incomplete) {
					t.Errorf("projection %#v: parseComplete and %s fact disagree", projection, incomplete)
				}
			}
			if allComplete != test.complete {
				t.Fatalf("complete = %t, want %t: %#v", allComplete, test.complete, projections)
			}
			for _, fact := range test.facts {
				if !contains(allFacts, fact) {
					t.Errorf("facts %v do not contain %q", allFacts, fact)
				}
			}
			for _, fact := range test.absentFacts {
				if contains(allFacts, fact) {
					t.Errorf("facts %v unexpectedly contain %q", allFacts, fact)
				}
			}
			for _, feature := range test.features {
				if !contains(allFeatures, feature) {
					t.Errorf("features %v do not contain %q", allFeatures, feature)
				}
			}
		})
	}
}

func TestUnescape(t *testing.T) {
	tests := []struct {
		value  string
		quoted bool
		want   string
	}{
		{`\git`, false, "git"},
		{`e\ f`, false, "e f"},
		{`a\\b`, false, `a\b`},
		{`a\"b`, true, `a"b`},
		{`a\nb`, true, `a\nb`},
		{`a\$b`, true, "a$b"},
		{"trail\\", false, "trail\\"},
	}
	for _, test := range tests {
		if got := unescape(test.value, test.quoted); got != test.want {
			t.Errorf("unescape(%q, %t) = %q, want %q", test.value, test.quoted, got, test.want)
		}
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestProjectPowerShellCarriesDialect(t *testing.T) {
	for _, command := range []string{"git status; git push -f origin main", "", "git 'unterminated"} {
		projections := ProjectPowerShell(command)
		if len(projections) == 0 {
			t.Fatalf("%q: no projection", command)
		}
		for _, projection := range projections {
			if !contains(projection.Facts, FactDialectPowerShell) {
				t.Errorf("%q: facts %v lack %s", command, projection.Facts, FactDialectPowerShell)
			}
		}
	}
	for _, projection := range Project("git status") {
		if contains(projection.Facts, FactDialectPowerShell) {
			t.Errorf("POSIX shell projection %#v carries %s", projection, FactDialectPowerShell)
		}
	}
}

// EvaluateV2 refuses a projection whose text it cannot carry, and a refused
// call is not judged. Every projection must therefore stay within its limits.
func TestProjectionsStayWithinEvaluatorLimits(t *testing.T) {
	long := strings.Repeat("x", 5000)
	for name, command := range map[string]string{
		"long program": "rm -rf ~/x; " + long,
		"long fact":    "curl -X DELETE https://api.github.com/repos/acme/" + long,
	} {
		for dialect, project := range map[string]func(string) []cedareval.ShellProjectionV2{"posix": Project, "powershell": ProjectPowerShell} {
			t.Run(name+"/"+dialect, func(t *testing.T) {
				projections := project(command)
				if len(projections) == 0 {
					t.Fatal("no projections")
				}
				incomplete := false
				for _, p := range projections {
					if !cedareval.ValidShellText(p.Program) {
						t.Errorf("program of %d bytes is not evaluable", len(p.Program))
					}
					for _, values := range [][]string{p.Facts, p.Features} {
						for _, value := range values {
							if !cedareval.ValidShellText(value) {
								t.Errorf("value of %d bytes is not evaluable", len(value))
							}
						}
					}
					if !p.ParseComplete {
						incomplete = true
						if !contains(p.Facts, FactParseIncomplete) {
							t.Errorf("incomplete projection lacks %s: %v", FactParseIncomplete, p.Facts)
						}
					}
				}
				if !incomplete {
					t.Errorf("no projection is marked incomplete: %+v", projections)
				}
			})
		}
	}
}

func TestEvaluableLeavesOutWhatTheEvaluatorRefuses(t *testing.T) {
	facts := []string{"kept=1", strings.Repeat("y", 5000), "bad=\xff"}
	for i := 0; i < cedareval.MaxShellFacts+10; i++ {
		facts = append(facts, fmt.Sprintf("more/%04d", i))
	}
	fits := projection("git", []string{"github/write=true"}, []string{"nested-script"}, true)
	got := evaluable([]cedareval.ShellProjectionV2{
		projection(strings.Repeat("p", 5000), facts, nil, true),
		fits,
	})
	p := got[0]
	if p.Program != "unknown" || p.ParseComplete {
		t.Errorf("program %.20q complete %v, want unknown and incomplete", p.Program, p.ParseComplete)
	}
	if len(p.Facts) > cedareval.MaxShellFacts || !contains(p.Facts, "kept=1") || !contains(p.Facts, FactParseIncomplete) {
		t.Errorf("%d facts; want at most %d with kept=1 and %s", len(p.Facts), cedareval.MaxShellFacts, FactParseIncomplete)
	}
	for _, fact := range p.Facts {
		if !cedareval.ValidShellText(fact) {
			t.Errorf("kept a fact of %d bytes", len(fact))
		}
	}
	if !contains(p.Features, "oversized-projection") {
		t.Errorf("features %v do not say why", p.Features)
	}
	if !reflect.DeepEqual(got[1], fits) {
		t.Errorf("a projection that fits changed: %+v", got[1])
	}
}

// The evaluator takes exactly MaxShellFacts values, so a projection holding
// that many is not oversized.
func TestEvaluableKeepsAProjectionAtTheLimit(t *testing.T) {
	full := make([]string, cedareval.MaxShellFacts)
	for i := range full {
		full[i] = fmt.Sprintf("fact/%04d", i)
	}
	atLimit := projection("curl", full, full, true)
	got := evaluable([]cedareval.ShellProjectionV2{projection("curl", full, full, true)})[0]
	if !reflect.DeepEqual(got, atLimit) {
		t.Errorf("a projection at the limit changed: complete %v, %d facts, %d features", got.ParseComplete, len(got.Facts), len(got.Features))
	}

	// One value has to go to make room for each marker, and no more than one.
	got = evaluable([]cedareval.ShellProjectionV2{projection(strings.Repeat("p", 5000), full, full, true)})[0]
	for name, values := range map[string][]string{FactParseIncomplete: got.Facts, "oversized-projection": got.Features} {
		if len(values) != cedareval.MaxShellFacts || !contains(values, name) {
			t.Errorf("%d values with %s present %v; want %d with it", len(values), name, contains(values, name), cedareval.MaxShellFacts)
		}
	}

	// A marker that is already there takes no second slot.
	incomplete := projection("curl", full[1:], nil, false)
	got = evaluable([]cedareval.ShellProjectionV2{projection(strings.Repeat("p", 5000), full[1:], nil, false)})[0]
	if !reflect.DeepEqual(got.Facts, incomplete.Facts) {
		t.Errorf("%d facts, want the same %d", len(got.Facts), len(incomplete.Facts))
	}
}
