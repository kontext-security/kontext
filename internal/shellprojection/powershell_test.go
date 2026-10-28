package shellprojection

import (
	"encoding/json"
	"os"
	"slices"
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
		{name: "cmd delayed expansion", command: `cmd /v:on /c "set FORCE=--force& git push !FORCE! origin main"`, programs: []string{"set", "git"}, absentFacts: []string{forcePush}, complete: false},
		{name: "cmd delayed expansion in quotes", command: `cmd /v:on /c git push "!FORCE!" origin main`, programs: []string{"git"}, absentFacts: []string{forcePush}, complete: false},
		{name: "Invoke-Expression", command: "Invoke-Expression 'git push -f origin main'", programs: []string{"git"}, facts: []string{forcePush}, features: []string{"nested-script"}, complete: true},
		{name: "dynamic Invoke-Expression", command: "iex $script", programs: []string{"invoke-expression"}, features: []string{"dynamic-script"}, complete: false},
		{name: "Invoke-Expression with an abbreviated -Command", command: "Invoke-Expression -c 'git push -f origin main'", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "iex -Command with a colon", command: "iex -Command:'git push -f origin main'", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "Invoke-Expression with an unknown parameter", command: "Invoke-Expression -x 'git push -f origin main'", programs: []string{"invoke-expression"}, features: []string{"unrecognized-wrapper-arguments"}, complete: false},
		{name: "variable without call operator is an expression", command: "$GIT push --force origin main", programs: []string{"unknown"}, features: []string{"empty-command"}, complete: false},
		{name: "variable with call operator", command: "& $GIT push --force origin main", programs: []string{"dynamic"}, complete: false},
		{name: "assignment then call", command: "$b = 'main'; git push --force origin $b", programs: []string{"git"}, facts: []string{forcePush}, complete: false},
		{name: "assigned call output", command: "$out = git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "script block", command: "Get-ChildItem | ForEach-Object { git push -f origin main }", programs: []string{"get-childitem", "foreach-object", "git"}, facts: []string{forcePush}, complete: false},
		{name: "if block", command: "if ($ok) { git push -f origin main }", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "statement after an if block without a separator", command: "if ($ok) { } git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "statement after try and catch", command: "try { } catch [System.Exception] { } git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "statement after do while", command: "do { } while ($x) git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "statement after a function", command: "function f { } git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "call operator after an if block", command: `if ($ok) { } & 'C:\Program Files\Git\cmd\git.exe' push --force origin main`, programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "call operator after do while", command: `do { } while ($x) & 'C:\Program Files\Git\cmd\git.exe' push --force origin main`, programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "clauses stay in their construct", command: "if ($a) { git status } elseif ($b) { } else { }; try { } catch { } finally { }", programs: []string{"git"}, absentFacts: []string{forcePush}, complete: true},
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
		{name: "return runs its pipeline", command: "return git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "throw runs its pipeline", command: "throw git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "exit runs its pipeline", command: "exit git push -f origin main; git status", programs: []string{"git", "git"}, facts: []string{forcePush}, complete: true},
		{name: "exit with a number", command: "exit 1", programs: []string{"unknown"}, features: []string{"empty-command"}, complete: false},
		{name: "hashtable value", command: "$h = @{ a = git push -f origin main }", programs: []string{"dynamic", "git"}, facts: []string{forcePush}, complete: false},
		{name: "hashtable value on its own line", command: "$h = @{ a = 1\n b = git push -f origin main }", programs: []string{"dynamic", "git"}, facts: []string{forcePush}, complete: false},
		{name: "cast hashtable value", command: "[ordered]@{ a = git push -f origin main }", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "subexpression in a hashtable argument", command: "Invoke-RestMethod -Body @{ a = $(git push -f origin main) }", programs: []string{"invoke-restmethod", "git"}, facts: []string{forcePush}, complete: false},
		{name: "hashtable keys and number values are not calls", command: "$o = [pscustomobject]@{ Name = 'x'; Count = 2 }", programs: []string{"unknown"}, features: []string{"empty-command"}, complete: false},
		{name: "quoted key with an equals sign", command: "$h = @{ 'k=v' = 1; b = 'x' }", programs: []string{"dynamic"}, complete: false},
		{name: "subexpression in a hashtable key", command: `$h = @{ "$(git push -f origin main)" = 1 }`, programs: []string{"dynamic", "git"}, facts: []string{forcePush}, complete: false},
		{name: "grouping in a cast hashtable key", command: "[ordered]@{ (git push -f origin main) = 1 }", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "block comment before a hashtable key", command: "[ordered]@{ <# c #> \"$(git push -f origin main)\" = 1 }", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "foreach over a pipeline", command: "foreach ($x in git push -f origin main) { }", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "foreach over a range", command: "foreach ($i in 1..3) { Write-Output $i }", programs: []string{"write-output"}, complete: false},
		{name: "multiple assignment", command: "$a, $b = git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "multiple assignment without spaces", command: "$a,$b=git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "typed assignment", command: "[string]$x = git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "chained assignment", command: "$x = [string]$s = git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "property assignment", command: "$x.Prop = git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "element assignment without spaces", command: "$x[0]=git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "property assignment without spaces", command: "$x.Prop=git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "space before the operator only", command: "$x[0] =git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "member chain with the call operator", command: `$x.a[0].b=& 'C:\Program Files\Git\cmd\git.exe' push --force origin main`, programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "element of a braced variable", command: "${x}[0]=git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "element in a multiple assignment", command: "$a,$x[0]=git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "static property assignment", command: "[Console]::Title=git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "string stored in an element", command: "$x[0]='git push -f origin main'", programs: []string{"unknown"}, absentFacts: []string{forcePush}, features: []string{"empty-command"}, complete: false},
		{name: "comparison with an element", command: "$x[0] -eq 'git push -f origin main'", programs: []string{"unknown"}, absentFacts: []string{forcePush}, features: []string{"empty-command"}, complete: false},
		{name: "subexpression in an assigned index", command: "$x[$(git push -f origin main)]=1", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "grouping in an assigned index before a call", command: "$x[(git push -f origin main)]=git status", programs: []string{"git", "git"}, facts: []string{forcePush}, complete: true},
		{name: "subexpression in an expandable index", command: `$x["$(git push -f origin main)"]=1`, programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "script block in an attribute", command: "[ValidateScript({ git push -f origin main })][string]$v = 'a'", programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "attribute arguments are not calls", command: "[Parameter(Mandatory)][string]$Name", programs: []string{"unknown"}, features: []string{"empty-command"}, complete: false},
		{name: "a command name starting with a digit", command: "7z x archive.zip", programs: []string{"7z"}, complete: true},
		{name: "call operator after return", command: `return & 'C:\Program Files\Git\cmd\git.exe' push --force origin main`, programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "call operator after throw", command: `throw & "C:\Program Files\Git\cmd\git.exe" push -f origin main`, programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "call operator after exit", command: `exit & 'C:\Program Files\Git\cmd\git.exe' push --force origin main`, programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "call operator after foreach's in", command: `foreach ($x in & 'C:\Program Files\Git\cmd\git.exe' push --force origin main) { }`, programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "call operator after a multiple assignment", command: `$a, $b = & 'C:\Program Files\Git\cmd\git.exe' push --force origin main`, programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "call operator after a property assignment", command: `$x.Prop = & 'C:\Program Files\Git\cmd\git.exe' push --force origin main`, programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "call operator after a typed assignment", command: `[string]$x = & 'C:\Program Files\Git\cmd\git.exe' push --force origin main`, programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "call operator after a chained assignment", command: `$x = $y = & 'C:\Program Files\Git\cmd\git.exe' push --force origin main`, programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "variable called after return", command: "return & $GIT push -f origin main", programs: []string{"dynamic"}, complete: false},
		{name: "return called as a command", command: "& return git push -f origin main", programs: []string{"return"}, absentFacts: []string{forcePush}, complete: true},
		{name: "background job before a statement", command: "git status & git push -f origin main", programs: []string{"git", "git"}, facts: []string{forcePush}, complete: true},
		{name: "block comment in a hashtable", command: "$h = @{ <# a = git push -f origin main; #> Name = 'x' }", programs: []string{"dynamic"}, absentFacts: []string{forcePush}, complete: false},
		{name: "quote in a hashtable block comment", command: "$h = @{ <# it's a note #> a = git push -f origin main }", programs: []string{"dynamic", "git"}, facts: []string{forcePush}, complete: false},
		{name: "block comment after a hashtable value", command: "$h = @{ a = git push -f origin main <# c #> }", programs: []string{"dynamic", "git"}, facts: []string{forcePush}, complete: false},
		{name: "block comment in a cast hashtable", command: "[ordered]@{ <# k = git push -f origin main #> n = 1 }", programs: []string{"unknown"}, absentFacts: []string{forcePush}, complete: false},
	})
}

// TestPowerShellHostFromPOSIXShell covers pwsh and cmd started from a POSIX
// shell, where the script after -c or /c is PowerShell or cmd text.
func TestPowerShellHostFromPOSIXShell(t *testing.T) {
	runCorpus(t, []corpusCase{
		{name: "pwsh -c", command: "pwsh -c 'git push -f origin main'", programs: []string{"git"}, facts: []string{forcePush, FactDialectPowerShell}, features: []string{"nested-script"}, complete: true},
		{name: "pwsh -Command with call operator", command: `pwsh -Command '& git push --force origin main'`, programs: []string{"git"}, facts: []string{forcePush}, complete: true},
		{name: "cmd.exe /c", command: "cmd.exe /c git push -f origin main", programs: []string{"git"}, facts: []string{forcePush}, absentFacts: []string{FactDialectPowerShell}, complete: true},
		{name: "cmd.exe delayed expansion", command: `cmd /v:on /c "set FORCE=--force& git push !FORCE! origin main"`, programs: []string{"set", "git"}, absentFacts: []string{forcePush, FactDialectPowerShell}, complete: false},
		{name: "interactive pwsh", command: "pwsh -NoLogo", programs: []string{"pwsh"}, complete: true},
	})
}

// TestPowerShellWebCmdlets covers Invoke-RestMethod and Invoke-WebRequest,
// read through curl's classification: their parameters, what makes a request
// unreadable, input from the pipeline, and Windows PowerShell's curl and wget
// aliases, which a path, an .exe suffix or a POSIX shell never take.
func TestPowerShellWebCmdlets(t *testing.T) {
	const repo = "https://api.github.com/repos/acme/api"
	deleteRepo := "github/operation=delete-repository"
	runProjectionCorpus(t, ProjectPowerShell, []corpusCase{
		{name: "Invoke-RestMethod deletes a repository", command: "Invoke-RestMethod -Method Delete " + repo, programs: []string{"invoke-restmethod"}, facts: []string{deleteRepo, write, catalogued, "http/method=DELETE"}, complete: true},
		{name: "values after a colon", command: "irm -Method:Delete -Uri:" + repo, programs: []string{"irm"}, facts: []string{deleteRepo, write, catalogued}, complete: true},
		{name: "abbreviated parameters", command: "irm -Meth Delete -Ur " + repo, programs: []string{"irm"}, facts: []string{deleteRepo, write}, complete: true},
		{name: "custom method", command: "iwr -CustomMethod DELETE " + repo, programs: []string{"iwr"}, facts: []string{deleteRepo, write}, complete: true},
		{name: "module-qualified name", command: `Microsoft.PowerShell.Utility\Invoke-WebRequest -Method Delete ` + repo, programs: []string{"invoke-webrequest"}, facts: []string{deleteRepo, write}, complete: true},
		{name: "positional URI is a read", command: "iwr " + repo, programs: []string{"iwr"}, facts: []string{catalogued, "http/method=GET"}, absentFacts: []string{write}, complete: true},
		{name: "parameters that shape only the output", command: "irm " + repo + " -UseBasicParsing -OutFile a.json -ea Stop -TimeoutSec 5", programs: []string{"irm"}, facts: []string{catalogued}, absentFacts: []string{write, incomplete}, complete: true},
		{name: "computed URI", command: "irm -Method Delete -Uri $u", programs: []string{"irm"}, facts: []string{incomplete}, complete: false},
		{name: "computed method", command: "irm -Method $m " + repo, programs: []string{"irm"}, facts: []string{unrecognized}, complete: false},
		{name: "splatted parameters", command: "irm @p", programs: []string{"irm"}, facts: []string{incomplete}, complete: false},
		{name: "a second positional value", command: "irm " + repo + " https://api.github.com/repos/acme/other", programs: []string{"irm"}, facts: []string{unrecognized, "http/path=/repos/acme/other"}, complete: false},
		{name: "a parameter that cannot be read keeps the URL", command: "iwr -Fo body " + repo, programs: []string{"iwr"}, facts: []string{unrecognized, "curl/host=api.github.com"}, complete: false},
		{name: "ambiguous abbreviation", command: "irm -m Delete " + repo, programs: []string{"irm"}, facts: []string{unrecognized}, complete: false},
		{name: "missing value", command: "irm " + repo + " -Method", programs: []string{"irm"}, facts: []string{unrecognized}, complete: false},
		{name: "web session", command: "irm " + repo + " -WebSession $s", programs: []string{"irm"}, facts: []string{unrecognized}, complete: false},
		{name: "computed headers", command: "irm -Headers $h -Method Delete " + repo, programs: []string{"irm"}, facts: []string{deleteRepo, write, unrecognized}, complete: false},
		{name: "literal GraphQL mutation", command: `irm -Method Post https://api.github.com/graphql -Body '{"query":"mutation { deleteRepository(input: {}) { clientMutationId } }"}'`, programs: []string{"irm"}, facts: []string{write, catalogued}, complete: true},
		{name: "GraphQL body from a file", command: "irm -Method Post https://api.github.com/graphql -InFile q.json", programs: []string{"irm"}, facts: []string{write, unrecognized}, features: []string{FeatureGraphQLNotLiteral}, complete: false},
		{name: "body from the pipeline", command: `'{"event":"APPROVE"}' | irm -Method Post ` + repo + "/pulls/1/reviews", programs: []string{"irm"}, facts: []string{write, unrecognized}, complete: false},
		{name: "Windows PowerShell's curl alias", command: "curl -Method Delete -Uri " + repo, programs: []string{"invoke-webrequest"}, facts: []string{deleteRepo, write}, complete: true},
		{name: "Windows PowerShell's wget alias", command: "wget -Uri " + repo + " -Method Delete", programs: []string{"invoke-webrequest"}, facts: []string{deleteRepo, write}, complete: true},
		{name: "alias in capitals", command: "CURL -Uri " + repo + " -Method Delete", programs: []string{"invoke-webrequest"}, facts: []string{deleteRepo, write}, complete: true},
		{name: "curl.exe is the program", command: "curl.exe -Method Delete -Uri " + repo, programs: []string{"curl"}, absentFacts: []string{write}, complete: false},
		{name: "curl with its own options", command: "curl -X DELETE " + repo, programs: []string{"curl"}, facts: []string{deleteRepo, write, catalogued}, complete: true},
	})
	runProjectionCorpus(t, Project, []corpusCase{
		{name: "POSIX curl with cmdlet parameters", command: "curl -Method Delete -Uri " + repo, programs: []string{"curl"}, absentFacts: []string{write}, complete: false},
		{name: "POSIX reading of a cmdlet call", command: "irm -Method Delete " + repo, programs: []string{"irm"}, facts: []string{deleteRepo, write, catalogued}, complete: true},
	})
}

// TestPowerShellWebCmdletsMatchCurl holds each cmdlet call to the facts of its
// curl equivalent, so every provider's rules apply to both alike.
func TestPowerShellWebCmdletsMatchCurl(t *testing.T) {
	for _, tc := range []struct{ cmdlet, curl string }{
		{"irm -Method Delete https://api.github.com/repos/acme/api", "curl -X DELETE https://api.github.com/repos/acme/api"},
		{"iwr https://api.github.com/repos/acme/api", "curl https://api.github.com/repos/acme/api"},
		{"Invoke-WebRequest -Method Post -Uri https://api.github.com/repos/acme/api/merges -Body '{}'", "curl -X POST https://api.github.com/repos/acme/api/merges -d '{}'"},
		{"irm -Method Patch https://api.github.com/repos/acme/api -Body '{}'", "curl -X PATCH https://api.github.com/repos/acme/api -d '{}'"},
		{"irm -Method Put https://api.github.com/repos/acme/api/branches/main/protection -Body '{}'", "curl -X PUT https://api.github.com/repos/acme/api/branches/main/protection -d '{}'"},
		{`irm -Method Post https://api.github.com/repos/acme/api/pulls/1/reviews -Body '{"event":"APPROVE"}'`, `curl -X POST https://api.github.com/repos/acme/api/pulls/1/reviews -d '{"event":"APPROVE"}'`},
		{`'{"event":"APPROVE"}' | irm -Method Post https://api.github.com/repos/acme/api/pulls/1/reviews`, `printf x | curl -X POST https://api.github.com/repos/acme/api/pulls/1/reviews --data-binary @-`},
		{"irm -Headers $h https://api.github.com/repos/acme/api", `curl -H "$h" https://api.github.com/repos/acme/api`},
		{"irm -Method Delete https://api.hubapi.com/crm/v3/objects/contacts/1", "curl -X DELETE https://api.hubapi.com/crm/v3/objects/contacts/1"},
	} {
		got, want := ProjectPowerShell(tc.cmdlet), Project(tc.curl)
		g, w := got[len(got)-1], want[len(want)-1]
		gotFacts := slices.DeleteFunc(slices.Clone(g.Facts), func(fact string) bool { return fact == FactDialectPowerShell })
		wantFacts := slices.Clone(w.Facts)
		slices.Sort(gotFacts)
		slices.Sort(wantFacts)
		if len(wantFacts) < 2 || !slices.Equal(gotFacts, wantFacts) || g.ParseComplete != w.ParseComplete {
			t.Errorf("%s: facts %v, complete %t; want those of %s: %v, complete %t", tc.cmdlet, gotFacts, g.ParseComplete, tc.curl, wantFacts, w.ParseComplete)
		}
	}
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
