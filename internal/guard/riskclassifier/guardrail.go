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
	"sync"
	"time"
)

const (
	// DefaultGuardrailTimeout bounds one inference. The classifier runs in the
	// decision path, so this is a hard budget on how long a tool call can wait:
	// ~9x the measured warm latency (44 ms p50) to absorb a cold prefix cache,
	// and far below any hook deadline. Slower states — a sidecar loading its
	// model — are handled by the readiness probe rather than by waiting.
	DefaultGuardrailTimeout = 400 * time.Millisecond

	// guardrailMaxCommandChars bounds the prompt so pathological commands stay
	// inside the model's context. Normalization already collapses the usual
	// offender (long base64 payloads).
	guardrailMaxCommandChars = 4000

	// guardrailMaxTokens mirrors the eval's max_new_tokens=8, plus room for an
	// empty <think></think> pair that a reasoning model emits even when told
	// not to reason.
	guardrailMaxTokens = 24

	guardrailPromptSchema = "kontext-guardrail-prompt/1"
)

// guardrailPromptJSON is the exact prompt the V2 row was measured with,
// exported from authz-bench by scripts/riskclassifier/export_prompt.py. It is
// data rather than source because a reworded bullet is a different classifier.
//
//go:embed prompts/guardrail-v2.json
var guardrailPromptJSON []byte

// LLMVerdict is the LLM half of a classifier record: the guardrail model's
// RISKY/SAFE answer mapped onto the contract labels, with the raw completion
// preserved for the feedback dataset.
type LLMVerdict struct {
	Verdict    string `json:"verdict"`
	Raw        string `json:"raw"`
	Model      string `json:"model"`
	PromptID   string `json:"prompt_id,omitempty"`
	DurationMs int64  `json:"duration_ms"`
	Cached     bool   `json:"cached,omitempty"`
}

type guardrailPrompt struct {
	Schema       string `json:"schema"`
	Variant      string `json:"variant"`
	UserTemplate string `json:"user_template"`
	System       string `json:"system"`
	Fewshot      []struct {
		Command string `json:"command"`
		Answer  string `json:"answer"`
	} `json:"fewshot"`
}

var (
	promptOnce sync.Once
	prompt     guardrailPrompt
	promptErr  error
	// promptPrefix is the fixed system + few-shot turns, identical on every
	// call. llama-server keeps its KV cache across requests, so this prefix is
	// evaluated once and reused rather than re-tokenized per command.
	promptPrefix []guardrailMessage
)

func loadGuardrailPrompt() ([]guardrailMessage, guardrailPrompt, error) {
	promptOnce.Do(func() {
		if err := json.Unmarshal(guardrailPromptJSON, &prompt); err != nil {
			promptErr = fmt.Errorf("decode guardrail prompt: %w", err)
			return
		}
		if prompt.Schema != guardrailPromptSchema {
			promptErr = fmt.Errorf("guardrail prompt schema %q, want %q", prompt.Schema, guardrailPromptSchema)
			return
		}
		if strings.TrimSpace(prompt.System) == "" || !strings.Contains(prompt.UserTemplate, "{command}") {
			promptErr = errors.New("guardrail prompt is missing its system text or user template")
			return
		}
		promptPrefix = append(promptPrefix, guardrailMessage{Role: "system", Content: prompt.System})
		for _, shot := range prompt.Fewshot {
			promptPrefix = append(promptPrefix,
				guardrailMessage{Role: "user", Content: renderCommand(prompt.UserTemplate, shot.Command)},
				guardrailMessage{Role: "assistant", Content: shot.Answer},
			)
		}
	})
	return promptPrefix, prompt, promptErr
}

func renderCommand(template, command string) string {
	return strings.ReplaceAll(template, "{command}", command)
}

// Guardrail asks a llama-server (or any OpenAI-compatible localhost endpoint)
// for a one-word RISKY/SAFE opinion on a bash command, using the prompt the
// authz-bench sweep selected.
type Guardrail struct {
	endpoint        string
	modelsURL       string
	model           string
	timeout         time.Duration
	httpClient      *http.Client
	disableThinking bool
	prefix          []guardrailMessage
	template        string
	variant         string
}

type GuardrailOptions struct {
	BaseURL    string
	Model      string
	Timeout    time.Duration
	HTTPClient *http.Client
	// DisableThinking forces non-thinking mode. Reasoning models are detected
	// by name; the eval measured this prompt with thinking off, and with it on
	// the model spends the whole token budget reasoning and never answers.
	DisableThinking bool
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
	prefix, loaded, err := loadGuardrailPrompt()
	if err != nil {
		return nil, err
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
	modelsURL, err := guardrailModelsURL(baseURL)
	if err != nil {
		return nil, err
	}
	return &Guardrail{
		endpoint:        endpoint,
		modelsURL:       modelsURL,
		model:           model,
		timeout:         timeout,
		httpClient:      client,
		disableThinking: opts.DisableThinking || modelNeedsNoThink(model),
		prefix:          prefix,
		template:        loaded.UserTemplate,
		variant:         loaded.Variant,
	}, nil
}

// readinessProbe reports whether the endpoint is serving. Used before the first
// classify call and after the circuit breaker's cooldown.
func (g *Guardrail) readinessProbe() func(context.Context) error {
	if g == nil {
		return nil
	}
	return httpReadinessProbe(g.httpClient, g.modelsURL)
}

// guardrailModelsURL derives the /v1/models URL from the same base as the
// completions endpoint. llama-server serves it only once the model is loaded,
// which is precisely the readiness signal we need.
func guardrailModelsURL(baseURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", fmt.Errorf("parse guardrail URL: %w", err)
	}
	path := strings.TrimRight(parsed.Path, "/")
	path = strings.TrimSuffix(path, "/chat/completions")
	if !strings.HasSuffix(path, "/v1") {
		path += "/v1"
	}
	parsed.Path = path + "/models"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

// modelNeedsNoThink reports whether the model reasons by default and must be
// told not to. Qwen3 honors the /no_think directive in the prompt.
func modelNeedsNoThink(model string) bool {
	return strings.Contains(strings.ToLower(model), "qwen3")
}

// Model reports the guardrail model name stamped on records.
func (g *Guardrail) Model() string {
	if g == nil {
		return ""
	}
	return g.model
}

// PromptVariant reports which measured prompt variant is in use.
func (g *Guardrail) PromptVariant() string {
	if g == nil {
		return ""
	}
	return g.variant
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

	// Normalized, because the eval scored this prompt on authz-bench's
	// normalized corpus — raw URLs and IPs would be out of distribution.
	normalized := truncateAtRuneBoundary(NormalizeCommand(command), guardrailMaxCommandChars)
	content := renderCommand(g.template, normalized)
	if g.disableThinking {
		content = "/no_think\n\n" + content
	}
	messages := make([]guardrailMessage, 0, len(g.prefix)+1)
	messages = append(messages, g.prefix...)
	messages = append(messages, guardrailMessage{Role: "user", Content: content})

	payload, err := json.Marshal(guardrailChatRequest{
		Model:       g.model,
		Messages:    messages,
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
	raw := strings.TrimSpace(stripThinkBlocks(decoded.firstContent()))
	verdict, err := parseGuardrailVerdict(raw)
	if err != nil {
		return LLMVerdict{}, err
	}
	return LLMVerdict{
		Verdict:    verdict,
		Raw:        raw,
		Model:      g.model,
		PromptID:   g.variant,
		DurationMs: time.Since(start).Milliseconds(),
	}, nil
}

// stripThinkBlocks removes a reasoning model's <think>…</think> preamble. Even
// in non-thinking mode Qwen3 may emit an empty pair before the verdict, and an
// unclosed block means the token budget ran out mid-reasoning — in that case
// nothing usable follows, so the remainder is dropped and the caller reports an
// unparseable verdict rather than guessing.
func stripThinkBlocks(content string) string {
	for {
		start := strings.Index(content, "<think>")
		if start < 0 {
			return content
		}
		rest := content[start+len("<think>"):]
		end := strings.Index(rest, "</think>")
		if end < 0 {
			return content[:start]
		}
		content = content[:start] + rest[end+len("</think>"):]
	}
}

// parseGuardrailVerdict mirrors the eval's parse(): whichever of RISKY/SAFE
// appears first wins, and neither appearing is an error rather than a guess.
// Matching the eval matters — its reported precision and recall are defined by
// this rule.
func parseGuardrailVerdict(raw string) (string, error) {
	lowered := strings.ToLower(raw)
	risky := strings.Index(lowered, "risky")
	safe := strings.Index(lowered, "safe")
	switch {
	case risky < 0 && safe < 0:
		return "", fmt.Errorf("unrecognized guardrail output %q", raw)
	case safe < 0:
		return VerdictRisky, nil
	case risky < 0:
		return VerdictNotRisky, nil
	case risky < safe:
		return VerdictRisky, nil
	default:
		return VerdictNotRisky, nil
	}
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
