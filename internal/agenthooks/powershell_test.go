package agenthooks

import (
	"reflect"
	"testing"
)

func TestPowerShellCommandQuotesEveryWord(t *testing.T) {
	for _, tc := range []struct {
		name  string
		words []string
		want  string
	}{
		{
			name:  "a plain path",
			words: []string{`C:\Users\someone\kontext.exe`, "hook", "--agent", "codex", "pre-tool-use"},
			want:  `$LASTEXITCODE = 1; & 'C:\Users\someone\kontext.exe' 'hook' '--agent' 'codex' 'pre-tool-use'; exit $LASTEXITCODE`,
		},
		{
			name:  "a path with spaces",
			words: []string{`C:\Program Files\Kontext\kontext.exe`, "hook"},
			want:  `$LASTEXITCODE = 1; & 'C:\Program Files\Kontext\kontext.exe' 'hook'; exit $LASTEXITCODE`,
		},
		{
			name:  "a path with a quote and things PowerShell would expand",
			words: []string{`C:\Users\O'Brien\$env:TEMP\` + "`" + `n\kontext.exe`, "hook"},
			want:  `$LASTEXITCODE = 1; & 'C:\Users\O''Brien\$env:TEMP\` + "`" + `n\kontext.exe' 'hook'; exit $LASTEXITCODE`,
		},
		{
			// PowerShell ends a single-quoted string at a typographic quote
			// as it does at the plain one, so each is written twice too.
			name:  "a path with typographic quotes",
			words: []string{"C:\\Users\\O\u2019Brien \u2018x\u201A\u201B\\kontext.exe", "hook"},
			want:  "$LASTEXITCODE = 1; & 'C:\\Users\\O\u2019\u2019Brien \u2018\u2018x\u201A\u201A\u201B\u201B\\kontext.exe' 'hook'; exit $LASTEXITCODE",
		},
		{
			name:  "a word that holds the command's own tail, and an empty one",
			words: []string{`C:\kontext.exe`, "; exit $LASTEXITCODE", ""},
			want:  `$LASTEXITCODE = 1; & 'C:\kontext.exe' '; exit $LASTEXITCODE' ''; exit $LASTEXITCODE`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := PowerShellCommand(tc.words...)
			if got != tc.want {
				t.Fatalf("PowerShellCommand = %s, want %s", got, tc.want)
			}
			back, ok := SplitPowerShellCommand(got)
			if !ok || !reflect.DeepEqual(back, tc.words) {
				t.Fatalf("SplitPowerShellCommand = %q, %v, want the words back", back, ok)
			}
		})
	}
}

// Only what PowerShellCommand writes is read back: a command that expands,
// pipes or runs something more is not Kontext's.
func TestSplitPowerShellCommandRefusesOtherCommands(t *testing.T) {
	for name, command := range map[string]string{
		"empty":                       "",
		"the POSIX form":              `'C:\kontext.exe' 'hook'`,
		"no exit code set first":      `& 'C:\kontext.exe' 'hook'; exit $LASTEXITCODE`,
		"no exit code handed on":      `$LASTEXITCODE = 1; & 'C:\kontext.exe' 'hook'`,
		"double quotes, which expand": `$LASTEXITCODE = 1; & "C:\kontext.exe" 'hook'; exit $LASTEXITCODE`,
		"a bare word":                 `$LASTEXITCODE = 1; & 'C:\kontext.exe' hook; exit $LASTEXITCODE`,
		"two spaces":                  `$LASTEXITCODE = 1; & 'C:\kontext.exe'  'hook'; exit $LASTEXITCODE`,
		"a tab":                       "$LASTEXITCODE = 1; & 'C:\\kontext.exe'\t'hook'; exit $LASTEXITCODE",
		"a pipe":                      `$LASTEXITCODE = 1; & 'C:\kontext.exe' 'hook' | Out-Null; exit $LASTEXITCODE`,
		"one more command":            `$LASTEXITCODE = 1; & 'C:\kontext.exe' 'hook'; calc; exit $LASTEXITCODE`,
		"an open quote":               `$LASTEXITCODE = 1; & 'C:\kontext.exe' 'hook; exit $LASTEXITCODE`,
		"no words":                    `$LASTEXITCODE = 1; &; exit $LASTEXITCODE`,
		"a leading space":             ` $LASTEXITCODE = 1; & 'C:\kontext.exe' 'hook'; exit $LASTEXITCODE`,
		// PowerShell would end the first word at the typographic quote, run
		// calc, and start another string at the next one.
		"a typographic quote that closes a word": "$LASTEXITCODE = 1; & 'C:\\a\u2019 ; calc ; & \u2018C:\\kontext.exe' 'hook'; exit $LASTEXITCODE",
		"a word opened with a typographic quote": "$LASTEXITCODE = 1; & \u2018C:\\kontext.exe' 'hook'; exit $LASTEXITCODE",
	} {
		if words, ok := SplitPowerShellCommand(command); ok {
			t.Errorf("%s: SplitPowerShellCommand(%s) = %q, want it refused", name, command, words)
		}
	}
}

// What the writer writes comes back word for word, whatever the words hold.
func FuzzPowerShellCommandRoundTrip(f *testing.F) {
	f.Add("C:\\Users\\O\u2019Brien\\kontext.exe", "it's", "")
	f.Add("'", "''", "\u2018\u2019")
	f.Add("; exit $LASTEXITCODE", "$LASTEXITCODE = 1; &", " '")
	f.Fuzz(func(t *testing.T, a, b, c string) {
		words := []string{a, b, c}
		back, ok := SplitPowerShellCommand(PowerShellCommand(words...))
		if !ok || !reflect.DeepEqual(back, words) {
			t.Fatalf("%q came back as %q, %v", words, back, ok)
		}
	})
}
