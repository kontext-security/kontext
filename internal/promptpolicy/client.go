package promptpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	baseURL *url.URL
	http    *http.Client
}

type Request struct {
	Token                    string
	InstallationID           string
	AuthorizationSessionID   string
	PromptSequence           uint64
	Prompt                   string
	ParentDeploymentIdentity string
}

type HTTPError struct {
	StatusCode int
	Response   ErrorResponse
	RetryAfter time.Duration
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("prompt-policy request failed: HTTP %d (%s)", e.StatusCode, e.Response.Code)
}

type TransportError struct{ Err error }

func (e *TransportError) Error() string { return e.Err.Error() }
func (e *TransportError) Unwrap() error { return e.Err }

func NewClient(baseURL string, httpClient *http.Client) (*Client, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("invalid prompt-policy base URL")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 60 * time.Second}
	}
	return &Client{baseURL: parsed, http: httpClient}, nil
}

func (c *Client) Put(ctx context.Context, input Request) (Bundle, error) {
	if input.Token == "" || input.PromptSequence == 0 || len([]byte(input.Prompt)) == 0 || len([]byte(input.Prompt)) > MaxPromptBytes {
		return Bundle{}, errors.New("invalid prompt-policy request")
	}
	body, err := json.Marshal(PutRequest{
		PromptPolicyContractVersion:      RequestContractVersion,
		Prompt:                           input.Prompt,
		ExpectedParentDeploymentIdentity: input.ParentDeploymentIdentity,
	})
	if err != nil {
		return Bundle{}, fmt.Errorf("encode prompt-policy request: %w", err)
	}
	path := "/api/v1/installations/" + url.PathEscape(input.InstallationID) +
		"/authorization-sessions/" + url.PathEscape(input.AuthorizationSessionID) +
		"/prompt-policies/" + strconv.FormatUint(input.PromptSequence, 10)
	endpoint := c.baseURL.ResolveReference(&url.URL{Path: path})
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return Bundle{}, fmt.Errorf("create prompt-policy request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+input.Token)
	req.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		return Bundle{}, &TransportError{Err: fmt.Errorf("send prompt-policy request: %w", err)}
	}
	defer response.Body.Close()
	const maxResponseBytes = 6*maxPolicySetBytes + 64*1024
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return Bundle{}, &TransportError{Err: fmt.Errorf("read prompt-policy response: %w", err)}
	}
	if len(data) > maxResponseBytes {
		return Bundle{}, errors.New("prompt-policy response exceeds size limit")
	}
	if response.StatusCode != http.StatusOK {
		var apiError ErrorResponse
		if err := decodeStrict(data, &apiError); err != nil {
			return Bundle{}, fmt.Errorf("decode prompt-policy error: %w", err)
		}
		if apiError.ResponseVersion != ResponseVersion || apiError.Code == "" {
			return Bundle{}, errors.New("invalid prompt-policy error response")
		}
		return Bundle{}, &HTTPError{StatusCode: response.StatusCode, Response: apiError, RetryAfter: retryAfter(response.Header.Get("Retry-After"))}
	}
	return DecodeBundle(data)
}

func retryAfter(value string) time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || seconds <= 0 || seconds > 5 {
		return 500 * time.Millisecond
	}
	return time.Duration(seconds) * time.Second
}
