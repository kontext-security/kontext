package agenthooks

import (
	"errors"
	"fmt"
	"sort"

	"github.com/kontext-security/kontext/internal/hook"
)

type SchemaVersion string

const SchemaVersionV1 SchemaVersion = "kontext.agenthooks/v1"

type ProviderID string

const (
	ProviderClaudeCode ProviderID = "claude-code"
	ProviderCodex      ProviderID = "codex"
)

type OwnerID string

const OwnerKontextManagedObserve OwnerID = "kontext/managed-observe"

type Placement string

const PlacementAppend Placement = "append"

type MatchSpec struct {
	Pattern string
}

type CommandHook struct {
	Command string
	Args    []string
	Timeout int
	Async   *bool
}

type EventPlan struct {
	Match     MatchSpec
	Command   CommandHook
	Placement Placement
}

type Plan struct {
	Version  SchemaVersion
	Provider ProviderID
	Owner    OwnerID
	Events   map[hook.HookName]EventPlan
}

func (p Plan) Validate() error {
	if p.Version != SchemaVersionV1 {
		return fmt.Errorf("hook plan version must be %q", SchemaVersionV1)
	}
	if p.Provider == "" {
		return errors.New("hook plan provider is required")
	}
	if p.Owner == "" {
		return errors.New("hook plan owner is required")
	}
	for event, plan := range p.Events {
		if !event.IsKnown() {
			return fmt.Errorf("hook event %q is not recognized", event)
		}
		if err := plan.Validate(); err != nil {
			return fmt.Errorf("%s hook plan: %w", event, err)
		}
	}
	return nil
}

func (p Plan) sortedEvents() []hook.HookName {
	events := make([]hook.HookName, 0, len(p.Events))
	for event := range p.Events {
		events = append(events, event)
	}
	sort.Slice(events, func(i, j int) bool {
		return events[i].String() < events[j].String()
	})
	return events
}

func (p EventPlan) Validate() error {
	if p.Command.Command == "" {
		return errors.New("command is required")
	}
	switch p.normalizedPlacement() {
	case PlacementAppend:
		return nil
	default:
		return errUnsupportedPlacement(p.Placement)
	}
}

func (p EventPlan) normalizedPlacement() Placement {
	if p.Placement != "" {
		return p.Placement
	}
	return PlacementAppend
}

func (p EventPlan) nativeGroup() (map[string]any, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	handler := map[string]any{
		"type":    "command",
		"command": p.Command.Command,
	}
	if len(p.Command.Args) > 0 {
		args := make([]any, 0, len(p.Command.Args))
		for _, arg := range p.Command.Args {
			args = append(args, arg)
		}
		handler["args"] = args
	}
	if p.Command.Timeout != 0 {
		handler["timeout"] = float64(p.Command.Timeout)
	}
	if p.Command.Async != nil {
		handler["async"] = *p.Command.Async
	}
	return map[string]any{
		"matcher": p.Match.Pattern,
		"hooks":   []any{handler},
	}, nil
}

func errUnsupportedPlacement(placement Placement) error {
	return fmt.Errorf("placement must be %q, got %q", PlacementAppend, placement)
}
