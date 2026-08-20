package hookruntime

import (
	"errors"
	"io"

	"github.com/kontext-security/kontext/internal/agent"
	"github.com/kontext-security/kontext/internal/hook"
)

type AgentAdapter struct {
	Agent     agent.Agent
	AgentName string
}

func (a AgentAdapter) Decode(r io.Reader) (hook.Event, error) {
	if a.Agent == nil {
		return hook.Event{}, errors.New("agent adapter missing agent")
	}
	input, err := io.ReadAll(r)
	if err != nil {
		return hook.Event{}, err
	}
	event, err := a.Agent.DecodeHookInput(input)
	if err != nil {
		return hook.Event{}, err
	}
	if a.outputAgentName() != "" {
		event.Agent = a.outputAgentName()
	}
	if event.SessionID == "" {
		event.SessionID = "local"
	}
	if event.HookName == "" {
		return hook.Event{}, errors.New("hook event name missing")
	}
	return event, nil
}

func (a AgentAdapter) Encode(out io.Writer, event hook.Event, result hook.Result) error {
	if a.Agent == nil {
		return errors.New("agent adapter missing agent")
	}
	payload, err := a.Agent.EncodeHookResult(event, result)
	if err != nil {
		return err
	}
	_, err = out.Write(append(payload, '\n'))
	return err
}

func (a AgentAdapter) MalformedHookName() hook.HookName {
	return hook.HookPreToolUse
}

func (a AgentAdapter) outputAgentName() string {
	if a.AgentName != "" {
		return a.AgentName
	}
	if a.Agent != nil {
		return a.Agent.Name()
	}
	return ""
}

var _ Adapter = AgentAdapter{}
