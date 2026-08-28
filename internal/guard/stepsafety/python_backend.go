package stepsafety

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

//go:embed worker.py
var pythonWorker string

type workerProcess struct {
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	stdout   *bufio.Reader
	wait     chan error
	killOnce sync.Once
	stopOnce sync.Once
	stopErr  error
}

type pythonBackend struct {
	mu            sync.Mutex
	operation     chan struct{}
	cfg           Config
	pythonPath    string
	workerSource  string
	worker        *workerProcess
	restarting    bool
	restartCancel context.CancelFunc
	closed        bool
	nextID        uint64
	device        string
}

type workerRequest struct {
	ID                   uint64 `json:"id"`
	Type                 string `json:"type"`
	UserRequest          string `json:"user_request,omitempty"`
	InteractionHistory   string `json:"interaction_history,omitempty"`
	ToolName             string `json:"tool_name,omitempty"`
	ToolArguments        any    `json:"tool_arguments,omitempty"`
	AvailableToolSchemas any    `json:"available_tool_schemas,omitempty"`
}

type workerResponse struct {
	ID           uint64     `json:"id"`
	Type         string     `json:"type"`
	Status       string     `json:"status"`
	ModelVersion string     `json:"model_version"`
	Device       string     `json:"device"`
	Logits       [2]float64 `json:"logits"`
	ErrorCode    string     `json:"error_code"`
}

func newPythonBackend(ctx context.Context, cfg Config) (*pythonBackend, error) {
	if err := ValidateModelDir(cfg.ModelDir); err != nil {
		return nil, err
	}
	pythonPath, err := exec.LookPath(cfg.Python)
	if err != nil {
		return nil, backendError(ErrorUnavailable, errors.New("step-safety Python runtime is unavailable"))
	}
	backend := &pythonBackend{
		operation:    make(chan struct{}, 1),
		cfg:          cfg,
		pythonPath:   pythonPath,
		workerSource: pythonWorker,
	}
	startupCtx, cancel := context.WithTimeout(ctx, cfg.StartupTimeout)
	defer cancel()
	process, ready, err := launchPythonWorker(startupCtx, cfg, pythonPath, pythonWorker)
	if err != nil {
		return nil, backendError(ErrorUnavailable, err)
	}
	if err := validateReadyResponse(ready, cfg.ModelVersion); err != nil {
		_ = process.stop()
		return nil, err
	}
	backend.worker = process
	backend.device = ready.Device
	return backend, nil
}

func launchPythonWorker(ctx context.Context, cfg Config, pythonPath, source string) (*workerProcess, workerResponse, error) {
	cmd := exec.Command(pythonPath,
		"-u", "-c", source,
		"--model-dir", cfg.ModelDir,
		"--model-version", cfg.ModelVersion,
		"--device", cfg.Device,
	)
	cmd.Env = append(os.Environ(),
		"HF_HUB_OFFLINE=1",
		"TRANSFORMERS_OFFLINE=1",
		"TOKENIZERS_PARALLELISM=false",
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, workerResponse{}, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, workerResponse{}, err
	}
	// Worker stderr may contain dependency diagnostics, but it must never be
	// allowed to mingle with hook contents or persisted telemetry.
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, workerResponse{}, err
	}
	process := &workerProcess{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewReaderSize(stdout, 64*1024),
		wait:   make(chan error, 1),
	}
	go func() { process.wait <- cmd.Wait() }()
	ready, err := readWorkerResponse(ctx, process.stdout)
	if err != nil {
		_ = process.stop()
		return nil, workerResponse{}, err
	}
	return process, ready, nil
}

func validateReadyResponse(ready workerResponse, modelVersion string) error {
	if ready.Type != "ready" || ready.Status != "ready" || ready.ModelVersion != modelVersion {
		return backendError(ErrorProtocol, errors.New("step-safety worker returned an invalid ready response"))
	}
	return nil
}

func (p *workerProcess) stop() error {
	if p == nil {
		return nil
	}
	p.kill()
	p.stopOnce.Do(func() {
		if p.wait != nil {
			select {
			case err := <-p.wait:
				if err != nil {
					var exitErr *exec.ExitError
					if !errors.As(err, &exitErr) {
						p.stopErr = err
					}
				}
			case <-time.After(2 * time.Second):
				p.stopErr = errors.New("step-safety worker did not exit")
			}
		}
	})
	return p.stopErr
}

func (p *workerProcess) kill() {
	if p == nil {
		return
	}
	p.killOnce.Do(func() {
		if p.stdin != nil {
			_ = p.stdin.Close()
		}
		if p.cmd != nil && p.cmd.Process != nil {
			_ = p.cmd.Process.Kill()
		}
	})
}

func (b *pythonBackend) Infer(ctx context.Context, input Input) ([2]float64, error) {
	response, err := b.roundTrip(ctx, workerRequest{
		Type:                 "infer",
		UserRequest:          input.UserRequest,
		InteractionHistory:   input.InteractionHistory,
		ToolName:             input.ToolName,
		ToolArguments:        input.ToolArguments,
		AvailableToolSchemas: input.AvailableToolSchemas,
	})
	if err != nil {
		return [2]float64{}, err
	}
	if response.Type != "result" {
		return [2]float64{}, backendError(ErrorProtocol, errors.New("unexpected step-safety worker response"))
	}
	if response.ErrorCode != "" {
		return [2]float64{}, backendError(normalizeWorkerError(response.ErrorCode), errors.New("step-safety inference failed"))
	}
	return response.Logits, nil
}

func (b *pythonBackend) Health(ctx context.Context) (Health, error) {
	response, err := b.roundTrip(ctx, workerRequest{Type: "health"})
	if err != nil {
		return Health{}, err
	}
	if response.Type != "health" || response.Status != "ready" {
		return Health{}, backendError(ErrorProtocol, errors.New("invalid step-safety health response"))
	}
	return Health{
		Enabled:      true,
		Status:       "ready",
		ModelVersion: response.ModelVersion,
		Device:       response.Device,
	}, nil
}

func (b *pythonBackend) roundTrip(ctx context.Context, request workerRequest) (workerResponse, error) {
	select {
	case b.operation <- struct{}{}:
		defer func() { <-b.operation }()
	case <-ctx.Done():
		return workerResponse{}, backendError(ErrorTimeout, ctx.Err())
	}

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return workerResponse{}, backendError(ErrorUnavailable, errors.New("step-safety worker is closed"))
	}
	process := b.worker
	if process == nil {
		b.mu.Unlock()
		b.scheduleRestart()
		return workerResponse{}, backendError(ErrorUnavailable, errors.New("step-safety worker is restarting"))
	}
	b.nextID++
	request.ID = b.nextID
	b.mu.Unlock()

	encoded, err := json.Marshal(request)
	if err != nil {
		return workerResponse{}, backendError(ErrorProtocol, err)
	}
	if _, err := process.stdin.Write(append(encoded, '\n')); err != nil {
		b.invalidate(process)
		return workerResponse{}, backendError(ErrorUnavailable, err)
	}
	response, err := readWorkerResponse(ctx, process.stdout)
	if err != nil {
		// Once a response deadline is missed the stream boundary is unknowable.
		// Retire that process, but keep the singleton backend alive: one
		// detached, bounded restart reloads the local model for later calls.
		b.invalidate(process)
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return workerResponse{}, backendError(ErrorTimeout, err)
		}
		return workerResponse{}, backendError(ErrorUnavailable, err)
	}
	if response.ID != request.ID {
		b.invalidate(process)
		return workerResponse{}, backendError(ErrorProtocol, fmt.Errorf("step-safety response id mismatch"))
	}
	return response, nil
}

func readWorkerResponse(ctx context.Context, reader *bufio.Reader) (workerResponse, error) {
	type readResult struct {
		line []byte
		err  error
	}
	done := make(chan readResult, 1)
	go func() {
		line, err := reader.ReadBytes('\n')
		done <- readResult{line: line, err: err}
	}()
	select {
	case <-ctx.Done():
		return workerResponse{}, ctx.Err()
	case result := <-done:
		if result.err != nil {
			return workerResponse{}, result.err
		}
		var response workerResponse
		if err := json.Unmarshal(result.line, &response); err != nil {
			return workerResponse{}, backendError(ErrorProtocol, err)
		}
		return response, nil
	}
}

func (b *pythonBackend) invalidate(process *workerProcess) {
	b.mu.Lock()
	if b.worker != process {
		b.mu.Unlock()
		return
	}
	b.worker = nil
	b.device = ""
	b.mu.Unlock()
	// Process.Kill is immediate; reap outside the hook response path so the
	// worker's OS shutdown can never consume the shadow fail-open budget.
	process.kill()
	go func() { _ = process.stop() }()
	b.scheduleRestart()
}

func (b *pythonBackend) scheduleRestart() {
	b.mu.Lock()
	if b.closed || b.restarting || b.worker != nil {
		b.mu.Unlock()
		return
	}
	restartCtx, cancel := context.WithTimeout(context.Background(), b.cfg.StartupTimeout)
	b.restarting = true
	b.restartCancel = cancel
	b.mu.Unlock()

	go func() {
		defer cancel()
		process, ready, err := launchPythonWorker(restartCtx, b.cfg, b.pythonPath, b.workerSource)
		if err == nil {
			err = validateReadyResponse(ready, b.cfg.ModelVersion)
		}
		b.mu.Lock()
		b.restarting = false
		b.restartCancel = nil
		closed := b.closed
		if err == nil && !closed && b.worker == nil {
			b.worker = process
			b.device = ready.Device
			process = nil
		}
		b.mu.Unlock()
		if process != nil {
			_ = process.stop()
		}
	}()
}

func (b *pythonBackend) Close() error {
	if b == nil {
		return nil
	}
	b.operation <- struct{}{}
	defer func() { <-b.operation }()
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	process := b.worker
	b.worker = nil
	cancel := b.restartCancel
	b.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return process.stop()
}

func normalizeWorkerError(code string) string {
	switch strings.TrimSpace(code) {
	case ErrorInference:
		return ErrorInference
	case ErrorInvalidOutput:
		return ErrorInvalidOutput
	case ErrorInputTooLarge:
		return ErrorInputTooLarge
	default:
		return ErrorProtocol
	}
}
