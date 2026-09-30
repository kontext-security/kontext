package stepsafety

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"sync"
	"sync/atomic"
)

//go:embed model/native/*.gz
var nativeAssets embed.FS

var nativeOnce sync.Once
var nativeReady = make(chan struct{})
var nativeShared struct {
	model     *nativeModel
	tokenizer *tokenizer
	err       error
}

type nativeBackend struct {
	model        *nativeModel
	tokenizer    *tokenizer
	modelVersion string
	closed       atomic.Bool
}

// Load one immutable, checksum-verified checkpoint per process, just as Kestrel
// does. No files are extracted, no library is loaded, and no download occurs.
// A caller's startup deadline never poisons the shared load for later callers.
func newNativeBackend(ctx context.Context, cfg Config) (*nativeBackend, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.StartupTimeout)
	defer cancel()
	nativeOnce.Do(func() {
		go func() {
			defer close(nativeReady)
			nativeShared.model, nativeShared.tokenizer, nativeShared.err = loadNativeAssets(context.Background())
		}()
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-nativeReady:
		if nativeShared.err != nil {
			return nil, backendError(ErrorUnavailable, nativeShared.err)
		}
		return &nativeBackend{model: nativeShared.model, tokenizer: nativeShared.tokenizer, modelVersion: cfg.ModelVersion}, nil
	}
}

func loadNativeAssets(ctx context.Context) (*nativeModel, *tokenizer, error) {
	names, err := fs.Glob(nativeAssets, "model/native/weights.*.gz")
	if err != nil || len(names) != 5 {
		return nil, nil, errors.New("missing embedded native weights")
	}
	readers := make([]io.Reader, 0, len(names))
	for _, name := range names {
		f, err := nativeAssets.Open(name)
		if err != nil {
			return nil, nil, err
		}
		defer f.Close()
		readers = append(readers, f)
	}
	r, err := gzip.NewReader(io.MultiReader(readers...))
	if err != nil {
		return nil, nil, err
	}
	defer r.Close()
	weights, err := readNativeWeights(ctx, r)
	if err != nil {
		return nil, nil, err
	}
	model, err := buildNativeModel(ctx, weights)
	if err != nil {
		return nil, nil, err
	}
	f, err := nativeAssets.Open("model/native/tokenizer.json.gz")
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	t, err := gzip.NewReader(f)
	if err != nil {
		return nil, nil, err
	}
	defer t.Close()
	data, err := io.ReadAll(io.LimitReader(t, 8340655))
	if err != nil {
		return nil, nil, err
	}
	digest := sha256.Sum256(data)
	if len(data) != 8340654 || hex.EncodeToString(digest[:]) != "d6c20af053b5d86d986a9f70898c1fceccb9d93e7ce6f63dabc899a12a53b031" {
		return nil, nil, errors.New("embedded tokenizer checksum mismatch")
	}
	tok, err := parseTokenizer(data)
	return model, tok, err
}

func (b *nativeBackend) Infer(ctx context.Context, input Input) (InferenceResult, error) {
	if b.closed.Load() {
		return InferenceResult{}, backendError(ErrorUnavailable, nil)
	}
	packed, err := packInput(ctx, b.tokenizer, input)
	if err != nil {
		return InferenceResult{}, err
	}
	return b.model.infer(ctx, packed)
}

func (b *nativeBackend) Health(ctx context.Context) (Health, error) {
	if err := ctx.Err(); err != nil {
		return Health{}, err
	}
	if b.closed.Load() {
		return Health{}, backendError(ErrorUnavailable, nil)
	}
	return Health{Status: "ready", ModelVersion: b.modelVersion, Device: "go-cpu"}, nil
}

func (b *nativeBackend) Close() error { b.closed.Store(true); return nil }
