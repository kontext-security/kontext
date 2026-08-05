package diagnostic

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// EnabledFromEnv reports whether diagnostic output was requested by env.
func EnabledFromEnv() bool {
	return os.Getenv("KONTEXT_DEBUG") == "1"
}

// Logger writes human diagnostics only when verbose output is enabled.
type Logger struct {
	out     io.Writer
	enabled bool
}

func New(out io.Writer, enabled bool) Logger {
	return Logger{out: out, enabled: enabled}
}

func (l Logger) Enabled() bool {
	return l.enabled
}

func (l Logger) Printf(format string, args ...any) {
	if !l.enabled || l.out == nil {
		return
	}
	fmt.Fprint(l.out, Redact(fmt.Sprintf(format, args...)))
}

// LogAlways writes a redacted line even when verbose output is disabled: an
// enabled logger keeps its configured sink, a disabled one falls back to
// stderr. For messages that must reach the process log unconditionally —
// Printf is debug-gated and silently drops them.
func LogAlways(log Logger, format string, args ...any) {
	if log.Enabled() {
		log.Printf(format, args...)
		return
	}
	fmt.Fprint(os.Stderr, Redact(fmt.Sprintf(format, args...)))
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._~+/=-]+`),
	regexp.MustCompile(`(?i)(access_token|id_token|refresh_token|authorization|cookie)=([^&\s]+)`),
	regexp.MustCompile(`(?i)(code|token)=([^&\s]+)`),
}

var jsonSecretPattern = regexp.MustCompile(`(?i)("(?:access_token|id_token|refresh_token|authorization|cookie|code|token)"\s*:\s*")([^"]+)(")`)

// Redact removes credential-shaped values before diagnostics reach stderr.
func Redact(input string) string {
	output := jsonSecretPattern.ReplaceAllString(input, `${1}[REDACTED]${3}`)
	for _, pattern := range secretPatterns {
		output = pattern.ReplaceAllStringFunc(output, func(match string) string {
			if len(match) >= 6 && strings.EqualFold(match[:6], "Bearer") {
				return "Bearer [REDACTED]"
			}
			parts := pattern.FindStringSubmatch(match)
			if len(parts) >= 2 {
				return parts[1] + "=[REDACTED]"
			}
			return "[REDACTED]"
		})
	}
	return output
}
