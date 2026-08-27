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
)

//go:embed worker.py
var pythonWorker string

type pythonBackend struct {
	mu           sync.Mutex
	closeOnce    sync.Once
	cmd          *exec.Cmd
	stdin        io.WriteCloser
	stdout       *bufio.Reader
	wait         chan error
	modelVersion string
	device       string
	closed       bool
	nextID       uint64
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
	cmd := exec.Command(pythonPath,
		"-u", "-c", pythonWorker,
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
		return nil, backendError(ErrorUnavailable, err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, backendError(ErrorUnavailable, err)
	}
	// Worker stderr may contain dependency diagnostics, but it must never be
	// allowed to mingle with hook contents or persisted telemetry.
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, backendError(ErrorUnavailable, err)
	}
	backend := &pythonBackend{
		cmd:          cmd,
		stdin:        stdin,
		stdout:       bufio.NewReaderSize(stdout, 64*1024),
		wait:         make(chan error, 1),
		modelVersion: cfg.ModelVersion,
	}
	go func() { backend.wait <- cmd.Wait() }()

	startupCtx, cancel := context.WithTimeout(ctx, cfg.StartupTimeout)
	defer cancel()
	ready, err := backend.readResponse(startupCtx)
	if err != nil {
		_ = backend.Close()
		return nil, backendError(ErrorUnavailable, err)
	}
	if ready.Type != "ready" || ready.Status != "ready" || ready.ModelVersion != cfg.ModelVersion {
		_ = backend.Close()
		return nil, backendError(ErrorProtocol, errors.New("step-safety worker returned an invalid ready response"))
	}
	backend.device = ready.Device
	return backend, nil
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
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return workerResponse{}, backendError(ErrorUnavailable, errors.New("step-safety worker is closed"))
	}
	b.nextID++
	request.ID = b.nextID
	encoded, err := json.Marshal(request)
	if err != nil {
		return workerResponse{}, backendError(ErrorProtocol, err)
	}
	if _, err := b.stdin.Write(append(encoded, '\n')); err != nil {
		return workerResponse{}, backendError(ErrorUnavailable, err)
	}
	response, err := b.readResponse(ctx)
	if err != nil {
		// Once a response deadline is missed the stream boundary is unknowable.
		// Kill the singleton and make all later calls fail open immediately.
		_ = b.closeLocked()
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return workerResponse{}, backendError(ErrorTimeout, err)
		}
		return workerResponse{}, backendError(ErrorUnavailable, err)
	}
	if response.ID != request.ID {
		_ = b.closeLocked()
		return workerResponse{}, backendError(ErrorProtocol, fmt.Errorf("step-safety response id mismatch"))
	}
	return response, nil
}

func (b *pythonBackend) readResponse(ctx context.Context) (workerResponse, error) {
	type readResult struct {
		line []byte
		err  error
	}
	done := make(chan readResult, 1)
	go func() {
		line, err := b.stdout.ReadBytes('\n')
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

func (b *pythonBackend) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closeLocked()
}

func (b *pythonBackend) closeLocked() error {
	var closeErr error
	b.closeOnce.Do(func() {
		b.closed = true
		if b.stdin != nil {
			_ = b.stdin.Close()
		}
		if b.cmd != nil && b.cmd.Process != nil {
			_ = b.cmd.Process.Kill()
		}
		if b.wait != nil {
			if err := <-b.wait; err != nil {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) {
					closeErr = err
				}
			}
		}
	})
	return closeErr
}

func normalizeWorkerError(code string) string {
	switch strings.TrimSpace(code) {
	case ErrorInference:
		return ErrorInference
	case ErrorInvalidOutput:
		return ErrorInvalidOutput
	default:
		return ErrorProtocol
	}
}
