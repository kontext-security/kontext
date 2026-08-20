package runtimecore

import (
	"context"
	"errors"
	"fmt"

	"github.com/kontext-security/kontext/internal/hook"
)

type HookRuntime interface {
	EvaluateHook(context.Context, hook.Event) (hook.Result, error)
	IngestEvent(context.Context, hook.Event) (hook.Result, error)
}

type SessionSource string

const (
	SessionSourceWrapperOwned   SessionSource = "wrapper_owned"
	SessionSourceDaemonObserved SessionSource = "daemon_observed"
)

type Session struct {
	ID         string
	Agent      string
	CWD        string
	Source     SessionSource
	ExternalID string
}

type SessionRuntime interface {
	OpenSession(context.Context, Session) (Session, error)
	CloseSession(context.Context, string) error
	EnsureSessionForEvent(context.Context, hook.Event) (hook.Event, error)
}

type Core struct {
	runtime  HookRuntime
	sessions SessionRuntime
}

func New(runtime HookRuntime) (*Core, error) {
	if runtime == nil {
		return nil, errors.New("runtime core requires hook runtime")
	}
	core := &Core{runtime: runtime}
	if sessions, ok := runtime.(SessionRuntime); ok {
		core.sessions = sessions
	}
	return core, nil
}

func (c *Core) OpenSession(ctx context.Context, session Session) (Session, error) {
	if c.sessions == nil {
		return Session{}, errors.New("runtime core does not support session lifecycle")
	}
	return c.sessions.OpenSession(ctx, session)
}

func (c *Core) CloseSession(ctx context.Context, sessionID string) error {
	if c.sessions == nil {
		return errors.New("runtime core does not support session lifecycle")
	}
	return c.sessions.CloseSession(ctx, sessionID)
}

func (c *Core) EnsureSessionForEvent(ctx context.Context, event hook.Event) (hook.Event, error) {
	if c.sessions == nil {
		return event, nil
	}
	return c.sessions.EnsureSessionForEvent(ctx, event)
}

func (c *Core) EvaluateHook(ctx context.Context, event hook.Event) (hook.Result, error) {
	if err := ValidateEvaluateHook(event); err != nil {
		return hook.Result{}, err
	}
	var err error
	event, err = c.EnsureSessionForEvent(ctx, event)
	if err != nil {
		return hook.Result{}, err
	}
	return c.runtime.EvaluateHook(ctx, event)
}

func ValidateEvaluateHook(event hook.Event) error {
	if event.HookName == "" {
		return errors.New("hook event name is required")
	}
	if !event.HookName.IsKnown() {
		return fmt.Errorf("hook event %q is not recognized", event.HookName)
	}
	if !event.HookName.CanBlock() {
		return fmt.Errorf("hook event %q cannot be evaluated for enforcement", event.HookName)
	}
	return nil
}

func (c *Core) IngestEvent(ctx context.Context, event hook.Event) (hook.Result, error) {
	if err := ValidateIngestEvent(event); err != nil {
		return hook.Result{}, err
	}
	if event.HookName.CanBlock() {
		return hook.Result{}, fmt.Errorf("hook event %q must be evaluated for enforcement", event.HookName)
	}
	var err error
	event, err = c.EnsureSessionForEvent(ctx, event)
	if err != nil {
		return hook.Result{}, err
	}
	return c.runtime.IngestEvent(ctx, event)
}

func ValidateIngestEvent(event hook.Event) error {
	if event.HookName == "" {
		return errors.New("hook event name is required")
	}
	if !event.HookName.IsKnown() {
		return fmt.Errorf("hook event %q is not recognized", event.HookName)
	}
	if event.HookName.CanBlock() {
		return fmt.Errorf("hook event %q must be evaluated for enforcement", event.HookName)
	}
	return nil
}

func (c *Core) ProcessHook(ctx context.Context, event hook.Event) (hook.Result, error) {
	if event.HookName.CanBlock() {
		return c.EvaluateHook(ctx, event)
	}
	return c.IngestEvent(ctx, event)
}
