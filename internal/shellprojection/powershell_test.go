package shellprojection

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestPowerShellCorpus covers PowerShell syntax a POSIX parse misreads: the
// call operator, Windows paths, backtick continuations, host and cmd
// wrappers, assignments, blocks, here-strings and redirections.
func TestPowerShellCorpus(t *testing.T) {
	runProjectionCorpus(t, ProjectPowerShell, []corpusCase{
		{name: "plain force push", command: "git push --force origin main", programs: []string{"git"}, facts: []string{forcePush, write, FactDialectPowerShell}, complete: true},
		{name: "call operator", command: "& git push --force origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "call operator on a quoted Windows path", command: `& 'C:\Program Files\Git\cmd\git.exe' push --force origin main`, programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "call operator without a space", command: `&"C:\Program Files\Git\cmd\git.exe" push -f origin main`, programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "unquoted Windows path keeps its backslashes", command: `C:\Windows\System32\curl.exe -X DELETE https://api.github.com/repos/acme/api`, programs: []string{"curl"}, facts: []string{write, "http/method=DELETE"}, complete: true},
		{name: "relative Windows path", command: `.\tools\gh.exe pr merge 42`, programs: []string{"gh"}, facts: []string{"gh/command=pr/merge", write}, complete: true},
		{name: "backtick continuation", command: "git push `\n  --force origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "backtick continuation with CRLF", command: "git push `\r\n  --force origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "pipeline chain", command: "git status && git push -f origin main", programs: []string{"git", "git"}, facts: []string{forcePush}, complete: true},
		{name: "statements", command: "git fetch; git push -f origin main", programs: []string{"git", "git"}, facts: []string{forcePush}, complete: true},
		{name: "separators inside quotes", command: `Write-Output "a & b; c | d"; git status`, programs: []string{"write-output", "git"}, absentFacts: []string{forcePush}, complete: true},
		{name: "comment", command: "git status # & git push -f origin main", programs: []string{"git"}, absentFacts: []string{forcePush}, complete: true},
		{name: "block comment", command: "<# git push -f #> git status", programs: []string{"git"}, absentFacts: []string{forcePush}, complete: true},
		{name: "pwsh -Command", command: `pwsh -NoProfile -Command "git push --force origin main"`, programs: []string{"git"}, facts: []string{forcePush}, features: []string{"nested-script"}, complete: true},
		{name: "abbreviated -Command", command: `powershell.exe -nop -com 'git push -f origin main'`, programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "Windows PowerShell runs a bare argument as a command", command: "powershell git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "pwsh runs a bare argument as a file", command: "pwsh deploy.ps1", programs: []string{"pwsh"}, complete: true},
		{name: "pwsh -File", command: "pwsh -ExecutionPolicy Bypass -File deploy.ps1", programs: []string{"pwsh"}, complete: true},
		{name: "encoded command", command: "pwsh -EncodedCommand ZwBpAHQAIABwAHUAcwBoAA==", programs: []string{"pwsh"}, features: []string{"encoded-script"}, complete: false},
		{name: "unknown host parameter", command: "pwsh -Frobnicate x -c 'git status'", programs: []string{"pwsh"}, features: []string{"unrecognized-wrapper-arguments"}, complete: false},
		{name: "cmd /c", command: "cmd /c git push --force origin main", programs: []string{"git"}, facts: []string{forcePush}, features: []string{"nested-script"}, complete: true},
		{name: "cmd /C with a quoted chain", command: `cmd.exe /C "git status & git push -f origin main"`, programs: []string{"git", "git"}, facts: []string{forcePush}, complete: true},
		{name: "cmd variable", command: `cmd /c "%GIT% push -f origin main"`, programs: []string{"dynamic"}, complete: false},
		{name: "Invoke-Expression", command: "Invoke-Expression 'git push -f origin main'", programs: []string{"git"}, facts: []string{forcePush}, features: []string{"nested-script"}, complete: true},
		{name: "dynamic Invoke-Expression", command: "iex $script", programs: []string{"invoke-expression"}, features: []string{"dynamic-script"}, complete: false},
		{name: "variable without call operator is an expression", command: "$GIT push --force origin main", programs: []string{"unknown"}, features: []string{"empty-command"}, complete: false},
		{name: "variable with call operator", command: "& $GIT push --force origin main", programs: []string{"dynamic"}, complete: false},
		{name: "assignment then call", command: "$b = 'main'; git push --force origin $b", programs: []string{"git"}, facts: []string{forcePush}, complete: false},
		{name: "assigned call output", command: "$out = git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "script block", command: "Get-ChildItem | ForEach-Object { git push -f origin main }", programs: []string{"get-childitem", "foreach-object", "git"}, facts: []string{forcePush}, complete: false},
		{name: "if block", command: "if ($ok) { git push -f origin main }", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "subexpression", command: "Write-Output $(git push -f origin main)", programs: []string{"write-output", "git"}, facts: []string{forcePush}, complete: false},
		{name: "subexpression in a string", command: `Write-Output "pushed: $(git push -f origin main)"`, programs: []string{"write-output", "git"}, facts: []string{forcePush}, complete: false},
		{name: "grouping as an argument", command: "git push origin (git branch --show-current) --force", programs: []string{"git", "git"}, facts: []string{forcePush}, complete: false},
		{name: "here-string message", command: "git commit -m @'\nfix: a & b; c\n'@", programs: []string{"git"}, complete: true},
		{name: "redirections", command: "git log --oneline -1 2>&1 > out.txt", programs: []string{"git"}, complete: true},
		{name: "stop-parsing token", command: "git --% push -f origin main", programs: []string{"git"}, complete: false},
		{name: "dot-sourcing", command: `. .\build.ps1`, programs: []string{"build.ps1"}, complete: true},
		{name: "unterminated string", command: "git push 'oops", programs: []string{"git", "git"}, features: []string{FeatureParseError, "syntax-error"}, complete: false},
		{name: "unbalanced block", command: "ForEach-Object { git push -f origin main", programs: []string{"foreach-object", "foreach-object"}, features: []string{FeatureParseError}, complete: false},
		{name: "text that does not tokenize is read as POSIX too", command: "git push -f origin main }", programs: []string{"git", "git"}, facts: []string{forcePush}, features: []string{FeatureParseError}, complete: false},
		{name: "call operator after an assignment", command: `$out = & 'C:\Program Files\Git\cmd\git.exe' push --force origin main`, programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "typographic quotes", command: "git push \u201c--force\u201d origin \u2018main\u2019", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "string piped into Invoke-Expression", command: "'git push -f origin main' | Invoke-Expression", programs: []string{"git"}, facts: []string{forcePush}, features: []string{"nested-script"}, complete: true},
		{name: "download piped into iex", command: "iwr https://example.com/x.ps1 | iex", programs: []string{"iwr", "invoke-expression"}, features: []string{"dynamic-script"}, complete: false},
		{name: "cast of a grouping", command: "[void](git push -f origin main)", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "method call arguments", command: "[IO.File]::WriteAllText('a.txt', 'b')", programs: []string{"unknown"}, features: []string{"empty-command"}, complete: false},
		{name: "subexpression in a here-string", command: "Write-Output @\"\n$(git push -f origin main)\n\"@", programs: []string{"write-output", "git"}, facts: []string{forcePush}, complete: false},
		{name: "comment closing brace inside a block", command: "ForEach-Object { # }\ngit push -f origin main }", programs: []string{"foreach-object", "git"}, facts: []string{forcePush}, complete: false},
		{name: "cmdlet with environment variable", command: "Write-Output $env:USERPROFILE", programs: []string{"write-output"}, complete: false},
		{name: "doubled quote in single quotes", command: "git commit -m 'it''s done'", programs: []string{"git"}, complete: true},
	})
}

// TestPowerShellHostFromPOSIXShell covers pwsh and cmd started from a POSIX
// shell, where the script after -c or /c is PowerShell or cmd text.
func TestPowerShellHostFromPOSIXShell(t *testing.T) {
	runCorpus(t, []corpusCase{
		{name: "pwsh -c", command: "pwsh -c 'git push -f origin main'", programs: []string{"git"}, facts: []string{forcePush, FactDialectPowerShell}, features: []string{"nested-script"}, complete: true},
		{name: "pwsh -Command with call operator", command: `pwsh -Command '& git push --force origin main'`, programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "cmd.exe /c", command: "cmd.exe /c git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, absentFacts: []string{FactDialectPowerShell}, complete: true},
		{name: "interactive pwsh", command: "pwsh -NoLogo", programs: []string{"pwsh"}, complete: true},
	})
}

// TestPowerShellRecordedHookPayloads replays PreToolUse payloads Claude Code
// sent for its PowerShell and Bash tools on macOS and Windows 11, reduced to
// the tool name and input.
func TestPowerShellRecordedHookPayloads(t *testing.T) {
	data, err := os.ReadFile("testdata/powershell-hook-payloads.json")
	if err != nil {
		t.Fatal(err)
	}
	var payloads []struct {
		Platform  string `json:"platform"`
		ToolName  string `json:"tool_name"`
		ToolInput struct {
			Command     string `json:"command"`
			Description string `json:"description"`
		} `json:"tool_input"`
		Programs []string `json:"programs"`
	}
	if err := json.Unmarshal(data, &payloads); err != nil {
		t.Fatal(err)
	}
	if len(payloads) == 0 {
		t.Fatal("no recorded payloads")
	}
	for _, payload := range payloads {
		t.Run(payload.Platform+"/"+payload.ToolName+"/"+payload.ToolInput.Command, func(t *testing.T) {
			project := Project
			if strings.EqualFold(payload.ToolName, "PowerShell") {
				project = ProjectPowerShell
			}
			projections := project(payload.ToolInput.Command)
			programs := make([]string, len(projections))
			for i, projection := range projections {
				programs[i] = projection.Program
				if contains(projection.Features, FeatureParseError) {
					t.Errorf("projection %#v: parse error", projection)
				}
			}
			if strings.Join(programs, " ") != strings.Join(payload.Programs, " ") {
				t.Fatalf("programs = %v, want %v", programs, payload.Programs)
			}
		})
	}
}

// FuzzProjectPowerShell checks that projection never panics and never
// returns nothing, whatever the text.
func FuzzProjectPowerShell(f *testing.F) {
	for _, seed := range []string{
		"git push --force origin main", "& 'C:\\x\\git.exe' push -f", "$out = & $git push", "git push `\n -f",
		"pwsh -c 'cmd /c git push -f'", "@'\nx\n'@", "@\"\n$(git push)\n\"@", "{ # }\n}", "[void](git push)",
		"'x' | iex", "| iex", "cmd /c \"%A% & b\"", "$", "`", "&", "@", "<#", "2>&", "$(", "@{", "[", "\"$(\"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, command string) {
		projections := ProjectPowerShell(command)
		if len(projections) == 0 {
			t.Fatalf("%q: no projection", command)
		}
		for _, projection := range projections {
			if projection.ParseComplete == contains(projection.Facts, incomplete) {
				t.Fatalf("%q: parseComplete and %s disagree in %#v", command, incomplete, projection)
			}
		}
	})
}
