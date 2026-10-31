package tooloutput

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/kontext-security/kontext/internal/cloudhttp"
)

const (
	// MaxRequestBytes caps a compaction request. Context is trimmed to fit;
	// an output that still does not fit is left as it is.
	MaxRequestBytes  = 1 << 20
	maxResponseBytes = 2 << 20
	maxEventIDBytes  = 256
	// tokenLifetime bounds how long a resolved install token is reused. A
	// keychain read forks a process, too slow to repeat for every output.
	tokenLifetime = 5 * time.Minute
)

const (
	ModeLive   = "live"
	ModeShadow = "shadow"

	KindText      = "text"
	KindFileLines = "file_lines"

	DecisionKeep    = "keep"
	DecisionReplace = "replace"
)

// Request is the body of POST /api/v1/installations/{id}/tool-output-compaction.
type Request struct {
	Mode      string         `json:"mode"`
	Agent     string         `json:"agent"`
	SessionID string         `json:"sessionId"`
	ToolUseID string         `json:"toolUseId"`
	ToolName  string         `json:"toolName"`
	ToolInput map[string]any `json:"toolInput"`
	Model     *string        `json:"model"`
	Output    Output         `json:"output"`
	Context   Context        `json:"context"`
}

type Output struct {
	Kind string `json:"kind"`
	Text string `json:"text"`
	// RecoveryPath is where the daemon saves the full output of a "text"
	// output it replaces.
	RecoveryPath string `json:"recoveryPath,omitempty"`
	// FilePath and StartLine place a Read result ("file_lines") in its file.
	FilePath  string `json:"filePath,omitempty"`
	StartLine int    `json:"startLine,omitempty"`
}

type Context struct {
	Goal    string        `json:"goal"`
	Current Current       `json:"current"`
	History []HistoryItem `json:"history"`
	// HistoryLength counts every visible item before the call, of which
	// History is the tail. It is sent only when the daemon saw them all.
	HistoryLength *int `json:"historyLength,omitempty"`
}

type Current struct {
	AssistantText string         `json:"assistantText"`
	ToolName      string         `json:"toolName"`
	ToolInput     map[string]any `json:"toolInput"`
}

type HistoryItem struct {
	Role      string     `json:"role"`
	Content   string     `json:"content"`
	ToolCalls []ToolCall `json:"toolCalls,omitempty"`
	// ToolUseID names the call a "tool" item answers.
	ToolUseID string `json:"toolUseId,omitempty"`
}

type ToolCall struct {
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

// Response is the server's answer. Text is set when Decision is "replace".
type Response struct {
	Decision      string  `json:"decision"`
	EventID       string  `json:"eventId"`
	Text          *string `json:"text"`
	RemovedBytes  *int64  `json:"removedBytes"`
	RemovedTokens *int64  `json:"removedTokens"`
}

func (r Response) validate() error {
	switch r.Decision {
	case DecisionKeep:
	case DecisionReplace:
		if r.Text == nil {
			return errors.New("replace without text")
		}
	default:
		return fmt.Errorf("unknown decision %q", r.Decision)
	}
	if r.EventID == "" || len(r.EventID) > maxEventIDBytes || strings.IndexFunc(r.EventID, func(c rune) bool { return !unicode.IsPrint(c) }) >= 0 {
		return errors.New("invalid event ID")
	}
	return nil
}

// ReadBack is the body of POST .../tool-output-compaction/read-backs: a later
// call read back what a compaction left out.
type ReadBack struct {
	SessionID string `json:"sessionId"`
	EventID   string `json:"eventId"`
	ToolUseID string `json:"toolUseId"`
}

// TokenSource resolves the install token, as for the configuration call.
type TokenSource func(context.Context) (string, error)

// Client calls the Kontext API's tool output compaction endpoints with the
// install token.
type Client struct {
	endpoint string
	tokens   TokenSource
	http     *http.Client
	now      func() time.Time

	mu       sync.Mutex
	cached   string
	cachedAt time.Time
}

func NewClient(baseURL, installationID string, tokens TokenSource, httpClient *http.Client) (*Client, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("tool output compaction: invalid base URL")
	}
	if strings.TrimSpace(installationID) == "" || tokens == nil {
		return nil, errors.New("tool output compaction: installation ID and token source are required")
	}
	if httpClient == nil {
		// Each call carries its own deadline.
		httpClient = cloudhttp.NewClient(0)
	}
	return &Client{
		endpoint: strings.TrimRight(parsed.String(), "/") + "/api/v1/installations/" + url.PathEscape(installationID) + "/tool-output-compaction",
		tokens:   tokens,
		http:     httpClient,
		now:      time.Now,
	}, nil
}

// Compact sends one output. Any status but 200, and any reply that is not a
// valid decision, is an error.
func (c *Client) Compact(ctx context.Context, body []byte) (Response, error) {
	if len(body) > MaxRequestBytes {
		return Response{}, errors.New("tool output compaction: request too large")
	}
	var response Response
	data, err := c.post(ctx, c.endpoint, body, http.StatusOK)
	if err != nil {
		return Response{}, err
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return Response{}, fmt.Errorf("tool output compaction: decode response: %w", err)
	}
	if err := response.validate(); err != nil {
		return Response{}, fmt.Errorf("tool output compaction: %w", err)
	}
	return response, nil
}

// ReportReadBack reports one read-back. Any 2xx status is success.
func (c *Client) ReportReadBack(ctx context.Context, readBack ReadBack) error {
	body, err := json.Marshal(readBack)
	if err != nil {
		return err
	}
	_, err = c.post(ctx, c.endpoint+"/read-backs", body, 0)
	return err
}

// post sends body and returns the response body. want is the only status
// accepted, or 0 for any 2xx.
func (c *Client) post(ctx context.Context, endpoint string, body []byte, want int) ([]byte, error) {
	token, err := c.installToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("tool output compaction: install token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tool output compaction: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("tool output compaction: read response: %w", err)
	}
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		c.forgetToken()
	}
	if want != 0 && response.StatusCode != want || want == 0 && (response.StatusCode < 200 || response.StatusCode > 299) {
		return nil, fmt.Errorf("tool output compaction: unexpected status %d", response.StatusCode)
	}
	if len(data) > maxResponseBytes {
		return nil, fmt.Errorf("tool output compaction: response exceeds %d bytes", maxResponseBytes)
	}
	return data, nil
}

func (c *Client) installToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	cached, fresh := c.cached, c.cached != "" && c.now().Sub(c.cachedAt) < tokenLifetime
	c.mu.Unlock()
	if fresh {
		return cached, nil
	}
	// Resolved outside the lock and under the caller's own deadline: a slow
	// keychain read for a background request must not hold up a live one.
	token, err := c.tokens(ctx)
	if err != nil {
		return "", err
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", errors.New("empty install token")
	}
	c.mu.Lock()
	c.cached, c.cachedAt = token, c.now()
	c.mu.Unlock()
	return token, nil
}

// forgetToken drops a token the server refused, so the next call resolves it
// again (an install that was set up anew has a new one).
func (c *Client) forgetToken() {
	c.mu.Lock()
	c.cached = ""
	c.mu.Unlock()
}
