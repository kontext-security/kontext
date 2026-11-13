package agentauthority

import (
	"strings"
	"testing"
)

// A path with spaces in a Bash grant is redacted as a whole, quoted or not,
// on either system's spelling; nothing of a folder name stays behind.
func TestGrantRedactsWholePathWithSpaces(t *testing.T) {
	for _, tc := range []struct{ grant, want string }{
		{`Bash("C:\Program Files\App\run.exe" --x)`, `Bash(<redacted> --x)`},
		{`Bash(C:\Program Files\App\run.exe --x)`, `Bash(<redacted> --x)`},
		{`Bash(type C:\Users\Jane Mary Doe\notes.txt)`, `Bash(type <redacted>)`},
		{`Bash(cat "/Users/Jane Doe/notes.txt")`, `Bash(cat <redacted>)`},
		{`Bash(cat /Users/Jane Doe/notes.txt)`, `Bash(cat <redacted>)`},
		{`Bash(cat '/Users/Jane Doe/a b/notes.txt' -n)`, `Bash(cat <redacted> -n)`},
		{`Bash(tool --config="C:\Users\Jane Doe\tool.toml")`, `Bash(tool <redacted>)`},
		{`Bash(cat "/Users/Jane Doe/never closed)`, `Bash(cat <redacted>)`},
		{`Bash(copy C:\Users\Jane Doe\a.txt D:\Back Up\a.txt)`, `Bash(copy <redacted> <redacted>)`},
		{`Bash(sh -c "cat /Users/Jane Doe/notes.txt")`, `Bash(sh -c <redacted>)`},
		{`Bash(pwsh -Command "Get-Content C:\Users\Jane Doe\notes.txt")`, `Bash(pwsh -Command <redacted>)`},
		{`Bash(echo don't cat /Users/Jane Doe/notes.txt)`, `Bash(echo don't cat <redacted>)`},
		{`Bash(sh -c 'cat /Users/Jane Doe/notes.txt)`, `Bash(sh -c <redacted>)`},
		{`Bash(sh -c "cat \"/Users/Jane Doe/notes.txt\"")`, `Bash(sh -c <redacted>)`},
		{`Bash(pwsh -Command "Get-Content \"C:\Users\Jane Doe\notes.txt\"")`, `Bash(pwsh -Command <redacted>)`},
	} {
		got := safeGrant(tc.grant)
		if got != tc.want {
			t.Errorf("safeGrant(%q) = %q, want %q", tc.grant, got, tc.want)
		}
		for _, name := range []string{"Jane", "Doe", "Mary", "Files", "notes", "Back", "Up"} {
			if strings.Contains(got, name) {
				t.Errorf("safeGrant(%q) = %q keeps %q of the path", tc.grant, got, name)
			}
		}
	}
}

// A secret inside a quoted stretch takes the stretch with it, and the one
// shape that is not covered is pinned so that a change to it is seen.
func TestGrantQuotedSecretAndKnownLimit(t *testing.T) {
	for _, tc := range []struct{ grant, want string }{
		{`Bash(sh -c "env API_TOKEN=abc ./run")`, `Bash(sh -c <redacted>)`},
		{`Bash(tool "--password hunter2 go")`, `Bash(tool <redacted>)`},
		{`Bash(ls /Users/Jane Doe)`, `Bash(ls <redacted> Doe)`},
	} {
		if got := safeGrant(tc.grant); got != tc.want {
			t.Errorf("safeGrant(%q) = %q, want %q", tc.grant, got, tc.want)
		}
	}
}

// Grants without a path with spaces read as they did.
func TestGrantWithoutSpacedPathIsUnchanged(t *testing.T) {
	for _, tc := range []struct{ grant, want string }{
		{`Bash(npm run test:*)`, `Bash(npm run test:*)`},
		{`Bash(git log origin/main --oneline)`, `Bash(git log origin/main --oneline)`},
		{`Bash(git commit -m "fix the thing")`, `Bash(git commit -m fix the thing)`},
		{`Bash(echo don't stop)`, `Bash(echo don't stop)`},
		{`Bash(rm /tmp/scratch build)`, `Bash(rm <redacted> build)`},
		{`Bash(cp /etc/hosts /tmp/hosts)`, `Bash(cp <redacted> <redacted>)`},
		{`Bash(curl https://example.com/a b/c)`, `Bash(curl https://example.com b/c)`},
		{`Bash(sh -c "echo one two")`, `Bash(sh -c echo one two)`},
		{`Read(//etc/**)`, `Read(//etc/**)`},
	} {
		if got := safeGrant(tc.grant); got != tc.want {
			t.Errorf("safeGrant(%q) = %q, want %q", tc.grant, got, tc.want)
		}
	}
}
