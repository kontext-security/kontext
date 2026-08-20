package hookcmd

import (
	"fmt"
	"io"
	"os"

	"github.com/kontext-security/kontext/internal/agent"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/hookruntime"
)

func Run(a agent.Agent, evaluate func(hook.Event) (hook.Result, error)) {
	os.Exit(run(os.Stdin, os.Stdout, os.Stderr, a, evaluate))
}

func RunWithExpectedEvent(a agent.Agent, expected hook.HookName, evaluate func(hook.Event) (hook.Result, error)) {
	os.Exit(runWithExpectedEvent(os.Stdin, os.Stdout, os.Stderr, a, expected, evaluate))
}

func run(stdin io.Reader, stdout, stderr io.Writer, a agent.Agent, evaluate func(hook.Event) (hook.Result, error)) int {
	return runWithExpectedEvent(stdin, stdout, stderr, a, "", evaluate)
}

func runWithExpectedEvent(stdin io.Reader, stdout, stderr io.Writer, a agent.Agent, expected hook.HookName, evaluate func(hook.Event) (hook.Result, error)) int {
	codec := agentCodec{agentName: a.Name(), agent: a, expected: expected}
	return hookruntime.Run(stdin, stdout, stderr, codec, evaluate)
}

type agentCodec struct {
	agentName string
	agent     agent.Agent
	expected  hook.HookName
}

func (c agentCodec) DecodeHookEvent(input []byte) (hook.Event, error) {
	event, err := c.agent.DecodeHookInput(input)
	if err != nil {
		return hook.Event{}, err
	}
	if event.Agent == "" {
		event.Agent = c.agentName
	}
	if c.expected != "" && event.HookName != c.expected {
		return hook.Event{}, fmt.Errorf("hook event alias %q does not match stdin event %q", c.expected, event.HookName)
	}
	return event, nil
}

func (c agentCodec) EncodeHookResult(event hook.Event, result hook.Result) ([]byte, error) {
	return c.agent.EncodeHookResult(event, result)
}
