package localruntime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/runtimecore"
)

const hookConnDeadline = 10 * time.Second

type Service struct {
	socketPath  string
	listener    net.Listener
	core        *runtimecore.Core
	sessionID   string
	agentName   string
	asyncIngest bool
	transform   func(hook.Event, hook.Result) hook.Result
	onFailure   func(hook.Event, error) hook.Result
	diagnostic  diagnostic.Logger
	cancel      context.CancelFunc
	serveDone   chan struct{}
	wg          sync.WaitGroup
}

type Options struct {
	SocketPath  string
	Core        *runtimecore.Core
	SessionID   string
	AgentName   string
	AsyncIngest bool
	Transform   func(hook.Event, hook.Result) hook.Result
	OnFailure   func(hook.Event, error) hook.Result
	Diagnostic  diagnostic.Logger
}

func NewService(opts Options) (*Service, error) {
	if opts.SocketPath == "" {
		return nil, errors.New("local runtime service requires socket path")
	}
	if opts.Core == nil {
		return nil, errors.New("local runtime service requires runtime core")
	}
	return &Service{
		socketPath:  opts.SocketPath,
		core:        opts.Core,
		sessionID:   opts.SessionID,
		agentName:   opts.AgentName,
		asyncIngest: opts.AsyncIngest,
		transform:   opts.Transform,
		onFailure:   opts.OnFailure,
		diagnostic:  opts.Diagnostic,
	}, nil
}

func (s *Service) SocketPath() string { return s.socketPath }

func (s *Service) Start(ctx context.Context) error {
	if err := os.Remove(s.socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale local runtime socket: %w", err)
	}
	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return err
	}
	s.listener = ln

	ctx, s.cancel = context.WithCancel(ctx)
	s.serveDone = make(chan struct{})
	go s.acceptLoop(ctx, ln, s.serveDone)
	return nil
}

func (s *Service) Stop() {
	_ = s.Shutdown(context.Background())
}

func (s *Service) Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var shutdownErr error
	if s.listener != nil {
		if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			shutdownErr = errors.Join(shutdownErr, err)
		}
	}
	if err := os.Remove(s.socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		shutdownErr = errors.Join(shutdownErr, fmt.Errorf("remove local runtime socket: %w", err))
	}

	if s.serveDone != nil {
		select {
		case <-s.serveDone:
		case <-ctx.Done():
			if s.cancel != nil {
				s.cancel()
			}
			return errors.Join(shutdownErr, ctx.Err())
		}
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		if s.cancel != nil {
			s.cancel()
		}
		return shutdownErr
	case <-ctx.Done():
		if s.cancel != nil {
			s.cancel()
		}
		return errors.Join(shutdownErr, ctx.Err())
	}
}

func (s *Service) acceptLoop(ctx context.Context, listener net.Listener, done chan<- struct{}) {
	defer close(done)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
				s.diagnostic.Printf("local runtime accept: %v\n", err)
				return
			}
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(ctx, conn)
		}()
	}
}

func (s *Service) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(hookConnDeadline)); err != nil {
		s.diagnostic.Printf("local runtime deadline: %v\n", err)
		return
	}

	var req EvaluateRequest
	if err := ReadMessage(conn, &req); err != nil {
		s.diagnostic.Printf("local runtime read: %v\n", err)
		return
	}

	result := s.process(ctx, &req)
	if err := WriteMessage(conn, result); err != nil {
		s.diagnostic.Printf("local runtime write: %v\n", err)
		return
	}

	if s.asyncIngest && shouldAsyncIngest(&req) {
		s.wg.Add(1)
		// Detach from the accept-loop context: shutdown cancels it, and a
		// pending telemetry write must drain rather than abort — Shutdown
		// already bounds the drain with its own context via wg.Wait.
		ingestCtx := context.WithoutCancel(ctx)
		go func() {
			defer s.wg.Done()
			s.ingestEvent(ingestCtx, &req)
		}()
	}
}

func (s *Service) ingestEvent(ctx context.Context, req *EvaluateRequest) {
	event, err := EventFromEvaluateRequest(s.sessionID, s.agentName, req)
	if err != nil {
		s.diagnostic.Printf("local runtime ingest decode: %v\n", err)
		return
	}
	if _, err := s.core.IngestEvent(ctx, event); err != nil {
		s.diagnostic.Printf("local runtime ingest: %v\n", err)
		return
	}
	s.closeSessionEnd(ctx, event)
}

func shouldAsyncIngest(req *EvaluateRequest) bool {
	if req == nil {
		return false
	}
	hookName, ok := normalizeHookName(req.HookEvent)
	return ok && !hookName.CanBlock()
}

func (s *Service) process(ctx context.Context, req *EvaluateRequest) EvaluateResult {
	event, err := EventFromEvaluateRequest(s.sessionID, s.agentName, req)
	if err != nil {
		s.diagnostic.Printf("local runtime decode: %v\n", err)
		return EvaluateResultFromResult(decodeFailureResult(req))
	}
	if s.asyncIngest && !event.HookName.CanBlock() {
		return s.result(event, hook.Result{Decision: hook.DecisionAllow})
	}
	result, err := s.core.ProcessHook(ctx, event)
	if err != nil {
		s.diagnostic.Printf("local runtime process: %v\n", err)
		if s.onFailure != nil {
			return s.result(event, s.onFailure(event, err))
		}
		return s.result(event, processFailureResult(event))
	}
	s.closeSessionEnd(ctx, event)
	return s.result(event, result)
}

func (s *Service) result(event hook.Event, result hook.Result) EvaluateResult {
	if s.transform != nil {
		result = s.transform(event, result)
	}
	return EvaluateResultFromResult(result)
}

func (s *Service) closeSessionEnd(ctx context.Context, event hook.Event) {
	if event.HookName != hook.HookSessionEnd {
		return
	}
	if err := s.core.CloseSession(ctx, event.SessionID); err != nil {
		s.diagnostic.Printf("local runtime session close: %v\n", err)
	}
}

func decodeFailureResult(req *EvaluateRequest) hook.Result {
	if req != nil {
		hookName, ok := normalizeHookName(req.HookEvent)
		if ok && !hookName.CanBlock() {
			return hook.Result{
				Decision: hook.DecisionAllow,
				Reason:   "Kontext hook event could not be decoded.",
			}
		}
	}
	return hook.Result{
		Decision: hook.DecisionDeny,
		Reason:   "Kontext hook event could not be decoded.",
	}
}

func processFailureResult(event hook.Event) hook.Result {
	if !event.HookName.CanBlock() {
		return hook.Result{
			Decision: hook.DecisionAllow,
			Reason:   "Kontext hook event could not be ingested.",
		}
	}
	return hook.Result{
		Decision: hook.DecisionDeny,
		Reason:   "Kontext access policy could not be evaluated.",
	}
}
