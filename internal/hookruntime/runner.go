package hookruntime

import (
	"fmt"
	"io"

	"github.com/kontext-security/kontext/internal/hook"
)

type Codec interface {
	DecodeHookEvent([]byte) (hook.Event, error)
	EncodeHookResult(hook.Event, hook.Result) ([]byte, error)
}

// NoDecisionCodec is a codec whose agent needs explicit output to mean "no
// decision": Cursor reads empty stdout from a fail-closed hook as a block.
type NoDecisionCodec interface {
	NoDecision() []byte
}

// Run answers one hook event and returns the process exit code. Its own
// failures never block the agent: Claude Code and Codex both read exit 2 as a
// block, so every internal error, panics included, exits 0 with no output,
// which both read as "no decision" (a NoDecisionCodec writes its own). The
// error goes to stderr.
func Run(stdin io.Reader, stdout, stderr io.Writer, codec Codec, evaluate func(hook.Event) (hook.Result, error)) (code int) {
	failed := func() int {
		if c, ok := codec.(NoDecisionCodec); ok {
			_, _ = stdout.Write(c.NoDecision())
		}
		return 0
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			fmt.Fprintf(stderr, "kontext: hook failed: %v\n", recovered)
			code = 0
		}
	}()

	input, err := io.ReadAll(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "kontext: failed to read stdin: %v\n", err)
		return failed()
	}

	event, err := codec.DecodeHookEvent(input)
	if err != nil {
		fmt.Fprintf(stderr, "kontext: failed to decode hook input: %v\n", err)
		return failed()
	}

	result, err := evaluate(event)
	if err != nil {
		fmt.Fprintf(stderr, "kontext: evaluation error: %v\n", err)
		return failed()
	}

	out, err := codec.EncodeHookResult(event, result)
	if err != nil {
		fmt.Fprintf(stderr, "kontext: failed to encode hook output: %v\n", err)
		return failed()
	}
	if _, err := stdout.Write(out); err != nil {
		fmt.Fprintf(stderr, "kontext: failed to write hook output: %v\n", err)
		return 0
	}
	return 0
}
