// Package stepsafety runs the local, observe-only step-level tool safety pilot.
//
// The package deliberately has no enforcement API. A result is evidence for
// review, never an authorization decision, and every model failure degrades to
// an unavailable shadow result instead of an error returned to the hook path.
package stepsafety

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	ModelVersion = "toolsafe-deberta-v3-xsmall-no-thought-v1"
	Threshold    = 0.5

	calibrationScale = 1.157280529495871
	calibrationBias  = 1.1360845295110542

	defaultTimeout        = 250 * time.Millisecond
	maxConfiguredTimeout  = 500 * time.Millisecond
	defaultStartupTimeout = 30 * time.Second
	defaultConcurrency    = 1

	// Packing remains token-exact for admitted inputs, but hook-controlled
	// strings must be bounded before the tokenizer sees them. Each limit is
	// still orders of magnitude above its final token budget.
	maxPretokenizedFieldBytes = 64 * 1024
	maxPretokenizedTotalBytes = 128 * 1024
)

const (
	DecisionSafe        = "safe"
	DecisionUnsafe      = "unsafe"
	DecisionUnavailable = "unavailable"
)

const (
	ErrorTimeout       = "timeout"
	ErrorUnavailable   = "unavailable"
	ErrorProtocol      = "protocol_error"
	ErrorInference     = "inference_error"
	ErrorConcurrency   = "concurrency_timeout"
	ErrorInvalidOutput = "invalid_output"
	ErrorInputTooLarge = "input_too_large"
)

// Input is the complete production-available no-Thought representation. The
// action stays structured until the worker renders the exact training form.
type Input struct {
	UserRequest          string `json:"user_request"`
	InteractionHistory   string `json:"interaction_history"`
	ToolName             string `json:"tool_name"`
	ToolArguments        any    `json:"tool_arguments"`
	AvailableToolSchemas any    `json:"available_tool_schemas"`
}

// Evaluation is returned for every enabled PreToolUse call. UnsafeProbability
// is absent on failure; ShadowDecision then becomes unavailable and the real
// tool authorization remains untouched (fail open for this pilot).
type Evaluation struct {
	UnsafeProbability  *float64 `json:"unsafe_probability,omitempty"`
	ShadowDecision     string   `json:"shadow_decision"`
	Threshold          float64  `json:"threshold"`
	ModelVersion       string   `json:"model_version"`
	LatencyMS          float64  `json:"latency_ms"`
	ErrorCode          string   `json:"error_code,omitempty"`
	Enforced           bool     `json:"enforced"`
	UserRequestPresent bool     `json:"user_request_present"`
	HistoryPresent     bool     `json:"history_present"`
	ToolSchemasPresent bool     `json:"tool_schemas_present"`
}

type Health struct {
	Enabled      bool   `json:"enabled"`
	Status       string `json:"status"`
	ModelVersion string `json:"model_version,omitempty"`
	Device       string `json:"device,omitempty"`
	ErrorCode    string `json:"error_code,omitempty"`
}

type Config struct {
	Enabled        bool
	ModelDir       string
	Python         string
	Device         string
	Timeout        time.Duration
	StartupTimeout time.Duration
	MaxConcurrency int
	ModelVersion   string
}

// Backend is the narrow boundary between safety policy plumbing and local
// inference. Production uses one PythonBackend; tests use deterministic fakes.
type Backend interface {
	Infer(context.Context, Input) ([2]float64, error)
	Health(context.Context) (Health, error)
	Close() error
}

type codedError struct {
	code string
	err  error
}

func (e codedError) Error() string { return e.err.Error() }
func (e codedError) Unwrap() error { return e.err }

func backendError(code string, err error) error {
	if err == nil {
		err = errors.New(code)
	}
	return codedError{code: code, err: err}
}

type Evaluator struct {
	backend      Backend
	timeout      time.Duration
	slots        chan struct{}
	modelVersion string
	unavailable  string
}

func ConfigFromEnv(dbPath string) (Config, error) {
	enabled, err := envBool("KONTEXT_STEP_SAFETY_SHADOW", false)
	if err != nil {
		return Config{}, err
	}
	if !enabled {
		return Config{Enabled: false}, nil
	}
	timeout, err := envDuration("KONTEXT_STEP_SAFETY_TIMEOUT", defaultTimeout)
	if err != nil {
		return Config{}, err
	}
	if timeout > maxConfiguredTimeout {
		return Config{}, fmt.Errorf("KONTEXT_STEP_SAFETY_TIMEOUT must not exceed %s", maxConfiguredTimeout)
	}
	startupTimeout, err := envDuration("KONTEXT_STEP_SAFETY_STARTUP_TIMEOUT", defaultStartupTimeout)
	if err != nil {
		return Config{}, err
	}
	concurrency, err := envInt("KONTEXT_STEP_SAFETY_MAX_CONCURRENCY", defaultConcurrency)
	if err != nil {
		return Config{}, err
	}
	if concurrency != 1 {
		return Config{}, errors.New("KONTEXT_STEP_SAFETY_MAX_CONCURRENCY must be 1 for the singleton pilot worker")
	}
	// One worker processes one request at a time. The admission bound prevents
	// bursts from building an unbounded queue behind the singleton model.
	return Config{
		Enabled:        enabled,
		ModelDir:       envString("KONTEXT_STEP_SAFETY_MODEL_DIR", DefaultModelDir(dbPath)),
		Python:         envString("KONTEXT_STEP_SAFETY_PYTHON", "python3"),
		Device:         envString("KONTEXT_STEP_SAFETY_DEVICE", "auto"),
		Timeout:        timeout,
		StartupTimeout: startupTimeout,
		MaxConcurrency: concurrency,
		ModelVersion:   ModelVersion,
	}, nil
}

// New loads a single worker when the feature is enabled. Missing artifacts or
// runtime dependencies produce an unavailable evaluator rather than failing
// daemon startup; each call will record the redacted failure code and fail open.
func New(ctx context.Context, cfg Config) *Evaluator {
	if !cfg.Enabled {
		return nil
	}
	cfg = normalizeConfig(cfg)
	backend, err := newPythonBackend(ctx, cfg)
	if err != nil {
		return &Evaluator{
			timeout:      cfg.Timeout,
			slots:        make(chan struct{}, cfg.MaxConcurrency),
			modelVersion: cfg.ModelVersion,
			unavailable:  errorCode(err),
		}
	}
	return NewWithBackend(backend, cfg.Timeout, cfg.MaxConcurrency, cfg.ModelVersion)
}

func NewWithBackend(backend Backend, timeout time.Duration, maxConcurrency int, modelVersion string) *Evaluator {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if maxConcurrency <= 0 {
		maxConcurrency = defaultConcurrency
	}
	if strings.TrimSpace(modelVersion) == "" {
		modelVersion = ModelVersion
	}
	return &Evaluator{
		backend:      backend,
		timeout:      timeout,
		slots:        make(chan struct{}, maxConcurrency),
		modelVersion: modelVersion,
	}
}

func normalizeConfig(cfg Config) Config {
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.StartupTimeout <= 0 {
		cfg.StartupTimeout = defaultStartupTimeout
	}
	if cfg.MaxConcurrency <= 0 {
		cfg.MaxConcurrency = defaultConcurrency
	}
	if strings.TrimSpace(cfg.Python) == "" {
		cfg.Python = "python3"
	}
	if strings.TrimSpace(cfg.Device) == "" {
		cfg.Device = "auto"
	}
	if strings.TrimSpace(cfg.ModelVersion) == "" {
		cfg.ModelVersion = ModelVersion
	}
	return cfg
}

func (e *Evaluator) Evaluate(ctx context.Context, input Input) Evaluation {
	started := time.Now()
	result := Evaluation{
		ShadowDecision:     DecisionUnavailable,
		Threshold:          Threshold,
		ModelVersion:       ModelVersion,
		Enforced:           false,
		UserRequestPresent: strings.TrimSpace(input.UserRequest) != "",
		HistoryPresent:     strings.TrimSpace(input.InteractionHistory) != "",
		ToolSchemasPresent: input.AvailableToolSchemas != nil,
	}
	if e == nil {
		return result
	}
	result.ModelVersion = e.modelVersion
	if err := validateInputBounds(input); err != nil {
		result.ErrorCode = errorCode(err)
		result.LatencyMS = elapsedMilliseconds(started)
		return result
	}
	if e.unavailable != "" || e.backend == nil {
		result.ErrorCode = firstNonEmpty(e.unavailable, ErrorUnavailable)
		result.LatencyMS = elapsedMilliseconds(started)
		return result
	}

	callCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	select {
	case e.slots <- struct{}{}:
		defer func() { <-e.slots }()
	case <-callCtx.Done():
		result.ErrorCode = ErrorConcurrency
		result.LatencyMS = elapsedMilliseconds(started)
		return result
	}

	logits, err := e.backend.Infer(callCtx, input)
	result.LatencyMS = elapsedMilliseconds(started)
	if err != nil {
		result.ErrorCode = errorCode(err)
		return result
	}
	if math.IsNaN(logits[0]) || math.IsNaN(logits[1]) || math.IsInf(logits[0], 0) || math.IsInf(logits[1], 0) {
		result.ErrorCode = ErrorInvalidOutput
		return result
	}
	probability := CalibratedProbability(logits[1] - logits[0])
	result.UnsafeProbability = &probability
	result.ShadowDecision = DecisionSafe
	if probability >= Threshold {
		result.ShadowDecision = DecisionUnsafe
	}
	return result
}

func validateInputBounds(input Input) error {
	arguments, err := json.Marshal(input.ToolArguments)
	if err != nil {
		return backendError(ErrorInference, errors.New("step-safety arguments are not JSON encodable"))
	}
	schemas := []byte(nil)
	if input.AvailableToolSchemas != nil {
		schemas, err = json.Marshal(input.AvailableToolSchemas)
		if err != nil {
			return backendError(ErrorInference, errors.New("step-safety schemas are not JSON encodable"))
		}
	}
	fields := []int{
		len(input.UserRequest),
		len(input.InteractionHistory),
		len(input.ToolName) + len(arguments) + len("[TOOL_NAME]\n\n[ARGUMENTS]\n"),
		len(schemas),
	}
	total := 0
	for _, size := range fields {
		if size > maxPretokenizedFieldBytes {
			return backendError(ErrorInputTooLarge, errors.New("step-safety input field exceeds preprocessing bound"))
		}
		total += size
	}
	if total > maxPretokenizedTotalBytes {
		return backendError(ErrorInputTooLarge, errors.New("step-safety input exceeds preprocessing bound"))
	}
	return nil
}

func CalibratedProbability(margin float64) float64 {
	z := calibrationScale*margin + calibrationBias
	if z >= 0 {
		return 1 / (1 + math.Exp(-z))
	}
	exp := math.Exp(z)
	return exp / (1 + exp)
}

func (e *Evaluator) Health(ctx context.Context) Health {
	if e == nil {
		return Health{Enabled: false, Status: "disabled"}
	}
	if e.unavailable != "" || e.backend == nil {
		return Health{Enabled: true, Status: "unavailable", ModelVersion: e.modelVersion, ErrorCode: firstNonEmpty(e.unavailable, ErrorUnavailable)}
	}
	health, err := e.backend.Health(ctx)
	if err != nil {
		return Health{Enabled: true, Status: "unavailable", ModelVersion: e.modelVersion, ErrorCode: errorCode(err)}
	}
	health.Enabled = true
	if health.ModelVersion == "" {
		health.ModelVersion = e.modelVersion
	}
	return health
}

func (e *Evaluator) Close() error {
	if e == nil || e.backend == nil {
		return nil
	}
	return e.backend.Close()
}

func errorCode(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return ErrorTimeout
	}
	var coded codedError
	if errors.As(err, &coded) && coded.code != "" {
		return coded.code
	}
	return ErrorInference
}

func elapsedMilliseconds(started time.Time) float64 {
	return float64(time.Since(started).Microseconds()) / 1000
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func envString(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envBool(key string, fallback bool) (bool, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean: %w", key, err)
	}
	return parsed, nil
}

func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", key)
	}
	return parsed, nil
}

func envInt(key string, fallback int) (int, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", key, err)
	}
	return parsed, nil
}
