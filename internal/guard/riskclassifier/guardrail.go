package riskclassifier

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
)

const (
	// DefaultGuardrailTimeout matches the local judge budget: the guardrail is
	// an observe-mode signal and must never hold a hook path hostage.
	DefaultGuardrailTimeout = 2 * time.Second

	// guardrailMaxCommandChars bounds the prompt so pathological commands stay
	// inside the small model's context window. Normalization already collapses
	// the usual offenders (long base64 payloads).
	guardrailMaxCommandChars = 4000

	guardrailMaxTokens = 8
)

//go:embed prompts/guardrail-v0.md
var guardrailPrompt string

// LLMVerdict is the LLM half of a classifier record: the guardrail model's
// RISKY/SAFE answer mapped onto the contract labels, with the raw completion
// preserved for the feedback dataset.
type LLMVerdict struct {
	Verdict    string `json:"verdict"`
	Raw        string `json:"raw"`
	Model      string `json:"model"`
	DurationMs int64  `json:"duration_ms"`
	Cached     bool   `json:"cached,omitempty"`
}

// Guardrail asks a llama-server (or any OpenAI-compatible localhost endpoint)
// for a one-word RISKY/SAFE opinion on a normalized bash command.
type Guardrail struct {
	endpoint   string
	model      string
	timeout    time.Duration
	httpClient *http.Client
}

type GuardrailOptions struct {
	BaseURL    string
	Model      string
	Timeout    time.Duration
	HTTPClient *http.Client
}

func NewGuardrail(opts GuardrailOptions) (*Guardrail, error) {
	baseURL := strings.TrimSpace(opts.BaseURL)
	if baseURL == "" {
		return nil, errors.New("guardrail base URL is required")
	}
	endpoint, err := guardrailEndpoint(baseURL)
	if err != nil {
		return nil, err
	}
	model := strings.TrimSpace(opts.Model)
	if model == "" {
		return nil, errors.New("guardrail model is required")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultGuardrailTimeout
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &Guardrail{endpoint: endpoint, model: model, timeout: timeout, httpClient: client}, nil
}

// Model reports the guardrail model name stamped on records.
func (g *Guardrail) Model() string {
	if g == nil {
		return ""
	}
	return g.model
}

// Classify normalizes the raw command and asks the guardrail model for a
// verdict. Errors are recorded by the caller; they never influence decisions.
func (g *Guardrail) Classify(ctx context.Context, command string) (LLMVerdict, error) {
	if g == nil {
		return LLMVerdict{}, errors.New("guardrail is not configured")
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()

	normalized := truncateAtRuneBoundary(NormalizeCommand(command), guardrailMaxCommandChars)
	payload, err := json.Marshal(guardrailChatRequest{
		Model: g.model,
		Messages: []guardrailMessage{
			{Role: "system", Content: guardrailPrompt},
			{Role: "user", Content: normalized},
		},
		Temperature: 0,
		MaxTokens:   guardrailMaxTokens,
	})
	if err != nil {
		return LLMVerdict{}, fmt.Errorf("marshal guardrail request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.endpoint, bytes.NewReader(payload))
	if err != nil {
		return LLMVerdict{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return LLMVerdict{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return LLMVerdict{}, fmt.Errorf("guardrail returned %s", resp.Status)
	}
	var decoded guardrailChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return LLMVerdict{}, fmt.Errorf("decode guardrail response: %w", err)
	}
	raw := strings.TrimSpace(decoded.firstContent())
	verdict, err := parseGuardrailVerdict(raw)
	if err != nil {
		return LLMVerdict{}, err
	}
	return LLMVerdict{
		Verdict:    verdict,
		Raw:        raw,
		Model:      g.model,
		DurationMs: time.Since(start).Milliseconds(),
	}, nil
}

// parseGuardrailVerdict maps the model's answer onto the contract labels. The
// prompt demands one word, but small instruct models decorate ("RISKY.",
// "safe"), so the first token decides, case-insensitively.
func parseGuardrailVerdict(raw string) (string, error) {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return unicode.IsSpace(r) || r == '.' || r == ',' || r == '!' || r == ':' || r == ';' || r == '"' || r == '\''
	})
	if len(fields) == 0 {
		return "", errors.New("empty guardrail output")
	}
	switch strings.ToUpper(fields[0]) {
	case "RISKY":
		return VerdictRisky, nil
	case "SAFE":
		return VerdictNotRisky, nil
	default:
		return "", fmt.Errorf("unrecognized guardrail output %q", raw)
	}
}

// truncateAtRuneBoundary caps s at max bytes without splitting a UTF-8
// sequence.
func truncateAtRuneBoundary(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut]
}

func guardrailEndpoint(baseURL string) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse guardrail URL: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("guardrail URL must include scheme and host")
	}
	path := strings.TrimRight(parsed.Path, "/")
	switch {
	case strings.HasSuffix(path, "/chat/completions"):
		return parsed.String(), nil
	case strings.HasSuffix(path, "/v1"):
		parsed.Path = path + "/chat/completions"
	default:
		parsed.Path = path + "/v1/chat/completions"
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

type guardrailChatRequest struct {
	Model       string             `json:"model"`
	Messages    []guardrailMessage `json:"messages"`
	Temperature float64            `json:"temperature"`
	MaxTokens   int                `json:"max_tokens"`
}

type guardrailMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type guardrailChatResponse struct {
	Choices []struct {
		Message guardrailMessage `json:"message"`
	} `json:"choices"`
}

func (r guardrailChatResponse) firstContent() string {
	if len(r.Choices) == 0 {
		return ""
	}
	return r.Choices[0].Message.Content
}
