package stepsafety

import (
	"context"
	"errors"
	"path/filepath"
	goruntime "runtime"
	"slices"
	"sync"
	"sync/atomic"

	ort "github.com/shota3506/onnxruntime-purego/onnxruntime"
)

// One CPU session, entirely in this process. There is no Python interpreter,
// subprocess, pipe protocol, network access, or GPU dependency at serving time.
type onnxBackend struct {
	closed       atomic.Bool
	mu           sync.Mutex // ONNX wrapper session and Close are not concurrency-safe.
	runtime      *ort.Runtime
	env          *ort.Env
	session      *ort.Session
	tokenizer    *tokenizer
	modelVersion string
}

func newONNXBackend(ctx context.Context, cfg Config) (*onnxBackend, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.StartupTimeout)
	defer cancel()
	type result struct {
		backend *onnxBackend
		err     error
	}
	ready := make(chan result)
	// Native session creation cannot be interrupted. Bound daemon startup and
	// clean up a late load rather than leaking a session after its deadline.
	go func() {
		backend, err := loadONNXBackend(ctx, cfg)
		select {
		case ready <- result{backend, err}:
		case <-ctx.Done():
			if backend != nil {
				_ = backend.Close()
			}
		}
	}()
	select {
	case loaded := <-ready:
		return loaded.backend, loaded.err
	case <-ctx.Done():
		return nil, backendError(ErrorTimeout, ctx.Err())
	}
}

func loadONNXBackend(ctx context.Context, cfg Config) (_ *onnxBackend, err error) {
	if err := ValidateModelDir(cfg.ModelDir); err != nil {
		return nil, err
	}
	library, err := ValidateRuntimeDir(cfg.ModelDir)
	if err != nil {
		return nil, backendError(ErrorUnavailable, err)
	}
	b := &onnxBackend{modelVersion: cfg.ModelVersion}
	defer func() {
		if err != nil {
			_ = b.Close()
		}
	}()
	b.tokenizer, err = loadTokenizer(filepath.Join(cfg.ModelDir, "tokenizer.json"))
	if err != nil {
		return nil, backendError(ErrorUnavailable, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// API 23 is supported by both of our pinned runtime releases.
	b.runtime, err = ort.NewRuntime(library, 23)
	if err != nil {
		return nil, backendError(ErrorUnavailable, err)
	}
	// Fatal-only logging avoids emitting model paths or input-derived native
	// diagnostics. Hooks receive stable redacted error codes from Evaluate.
	b.env, err = b.runtime.NewEnv("kontext-step-safety", ort.LoggingLevelFatal)
	if err != nil {
		return nil, backendError(ErrorUnavailable, err)
	}
	b.session, err = b.runtime.NewSession(b.env, filepath.Join(cfg.ModelDir, "model.onnx"), &ort.SessionOptions{
		IntraOpNumThreads: 4,
	})
	if err != nil {
		return nil, backendError(ErrorUnavailable, err)
	}
	if !slices.Equal(b.session.InputNames(), []string{"input_ids", "attention_mask"}) || !slices.Equal(b.session.OutputNames(), []string{"logits"}) {
		return nil, backendError(ErrorInvalidOutput, errors.New("unexpected ONNX input/output contract"))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *onnxBackend) Infer(ctx context.Context, input Input) (InferenceResult, error) {
	packed, err := packInput(ctx, b.tokenizer, input)
	if err != nil {
		return InferenceResult{}, err
	}
	return b.inferPacked(ctx, packed)
}

func (b *onnxBackend) inferPacked(ctx context.Context, packed packedInput) (InferenceResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return InferenceResult{}, err
	}
	if b.session == nil {
		return InferenceResult{}, backendError(ErrorUnavailable, nil)
	}
	// The native tensors borrow Go-owned buffers. Pin them until Run and
	// tensor destruction finish; the binding does not retain Go references.
	var pinned goruntime.Pinner
	pinned.Pin(&packed.IDs[0])
	pinned.Pin(&packed.Mask[0])
	defer pinned.Unpin()
	ids, err := ort.NewTensorValue(b.runtime, packed.IDs, []int64{1, maxSequenceLength})
	if err != nil {
		return InferenceResult{}, err
	}
	defer ids.Close()
	mask, err := ort.NewTensorValue(b.runtime, packed.Mask, []int64{1, maxSequenceLength})
	if err != nil {
		return InferenceResult{}, err
	}
	defer mask.Close()
	outputs, err := b.session.Run(ctx, map[string]*ort.Value{"input_ids": ids, "attention_mask": mask})
	if err != nil {
		if ctx.Err() != nil {
			return InferenceResult{}, ctx.Err()
		}
		return InferenceResult{}, err
	}
	defer func() {
		for _, output := range outputs {
			output.Close()
		}
	}()
	if err := ctx.Err(); err != nil {
		return InferenceResult{}, err
	}
	logits, ok := outputs["logits"]
	if !ok || logits == nil {
		return InferenceResult{}, backendError(ErrorInvalidOutput, nil)
	}
	values, shape, err := ort.GetTensorData[float32](logits)
	if err != nil || !slices.Equal(shape, []int64{1, 2}) || len(values) != 2 {
		return InferenceResult{}, backendError(ErrorInvalidOutput, nil)
	}
	return InferenceResult{Logits: [2]float64{float64(values[0]), float64(values[1])}, HistoryOmitted: packed.HistoryOmitted}, nil
}

func (b *onnxBackend) Health(ctx context.Context) (Health, error) {
	if err := ctx.Err(); err != nil {
		return Health{}, err
	}
	if b.closed.Load() {
		return Health{}, backendError(ErrorUnavailable, nil)
	}
	return Health{Status: "ready", ModelVersion: b.modelVersion, Device: "onnx-cpu"}, nil
}

func (b *onnxBackend) Close() error {
	b.closed.Store(true)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.session != nil {
		b.session.Close()
		b.session = nil
	}
	if b.env != nil {
		b.env.Close()
		b.env = nil
	}
	if b.runtime != nil {
		err := b.runtime.Close()
		b.runtime = nil
		return err
	}
	return nil
}
