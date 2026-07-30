package hookruntime

import (
	"errors"
	"fmt"
	"io"

	"github.com/kontext-security/kontext-cli/internal/hook"
)

type Codec interface {
	DecodeHookEvent([]byte) (hook.Event, error)
	EncodeHookResult(hook.Event, hook.Result) ([]byte, error)
}

func Run(stdin io.Reader, stdout, stderr io.Writer, codec Codec, evaluate func(hook.Event) (hook.Result, error)) int {
	input, err := io.ReadAll(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "kontext: failed to read stdin: %v\n", err)
		return 2
	}

	event, err := codec.DecodeHookEvent(input)
	if err != nil {
		// An adapter that recognizes the event but does not translate it is not
		// a failure: succeed without emitting a decision, so runtimes that read
		// a non-zero exit as "block" let the tool call proceed.
		if errors.Is(err, hook.ErrSkipEvent) {
			return 0
		}
		fmt.Fprintf(stderr, "kontext: failed to decode hook input: %v\n", err)
		return 2
	}

	result, err := evaluate(event)
	if err != nil {
		fmt.Fprintf(stderr, "kontext: evaluation error: %v\n", err)
		return 2
	}

	out, err := codec.EncodeHookResult(event, result)
	if err != nil {
		fmt.Fprintf(stderr, "kontext: failed to encode hook output: %v\n", err)
		return 2
	}
	if _, err := stdout.Write(out); err != nil {
		fmt.Fprintf(stderr, "kontext: failed to write hook output: %v\n", err)
		return 2
	}
	return 0
}
