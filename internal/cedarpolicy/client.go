package cedarpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var installationIDPattern = regexp.MustCompile(`^ins_[A-Za-z0-9_-]{32}$`)

type FetchResult struct {
	State      State
	Deployment *Deployment
	Response   *StateResponse
	ETag       string
}

type Client struct {
	baseURL string
	http    *http.Client
}

func NewClient(baseURL string, httpClient *http.Client) (*Client, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("cedar policy: invalid base URL")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())) {
		return nil, errors.New("cedar policy: base URL must use HTTPS or loopback HTTP")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{baseURL: strings.TrimRight(parsed.String(), "/"), http: httpClient}, nil
}

func (c *Client) Fetch(ctx context.Context, installToken, installationID, deploymentIdentity string) (FetchResult, error) {
	if !installationIDPattern.MatchString(installationID) {
		return FetchResult{}, errors.New("cedar policy: invalid installation ID")
	}
	if strings.TrimSpace(installToken) == "" {
		return FetchResult{}, errors.New("cedar policy: install token is required")
	}
	endpoint, err := url.Parse(c.baseURL + "/api/v1/installations/" + installationID + "/policy")
	if err != nil {
		return FetchResult{}, err
	}
	query := endpoint.Query()
	query.Set("response_version", fmt.Sprint(ResponseVersion))
	query.Set("request_contract_version", fmt.Sprint(RequestContractVersion))
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return FetchResult{}, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(installToken))
	if deploymentIdentity != "" {
		if !sha256HexPattern.MatchString(deploymentIdentity) {
			return FetchResult{}, errors.New("cedar policy: invalid conditional deployment identity")
		}
		req.Header.Set("If-None-Match", `"`+deploymentIdentity+`"`)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return FetchResult{}, fmt.Errorf("cedar policy fetch: %w", err)
	}
	defer resp.Body.Close()
	etag := parseETag(resp.Header.Get("ETag"))
	if resp.StatusCode == http.StatusNotModified {
		if deploymentIdentity == "" || etag != deploymentIdentity {
			return FetchResult{}, errors.New("cedar policy: invalid not-modified ETag")
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1))
		return FetchResult{State: StateNotModified, ETag: etag}, nil
	}

	if resp.StatusCode == http.StatusOK {
		var probe struct {
			State State `json:"state"`
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
		if err != nil {
			return FetchResult{}, err
		}
		if len(body) > MaxResponseBytes {
			return FetchResult{}, fmt.Errorf("cedar policy: response exceeds %d bytes", MaxResponseBytes)
		}
		if err := json.Unmarshal(body, &probe); err != nil {
			return FetchResult{}, fmt.Errorf("cedar policy: decode response: %w", err)
		}
		if probe.State == "" {
			var deployment Deployment
			if err := decodeStrict(strings.NewReader(string(body)), &deployment); err != nil {
				return FetchResult{}, fmt.Errorf("cedar policy: decode deployment: %w", err)
			}
			if err := deployment.Validate(); err != nil {
				return FetchResult{}, err
			}
			if etag == "" || etag != deployment.DeploymentIdentity {
				return FetchResult{}, errors.New("cedar policy: ETag does not match deployment identity")
			}
			return FetchResult{State: StateSuccess, Deployment: &deployment, ETag: etag}, nil
		}
		return decodeStateResult(
			body,
			etag,
			StateDisabled,
			StateNoActivePolicy,
			StatePrincipalUnavailable,
		)
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusNotAcceptable || resp.StatusCode == http.StatusServiceUnavailable {
		body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
		if err != nil {
			return FetchResult{}, err
		}
		if len(body) > MaxResponseBytes {
			return FetchResult{}, fmt.Errorf("cedar policy: response exceeds %d bytes", MaxResponseBytes)
		}
		expectedState := StateUnauthorized
		if resp.StatusCode == http.StatusNotAcceptable {
			expectedState = StateUnsupportedVersion
		} else if resp.StatusCode == http.StatusServiceUnavailable {
			expectedState = StateUnavailable
		}
		return decodeStateResult(body, etag, expectedState)
	}
	return FetchResult{}, fmt.Errorf("cedar policy fetch: unexpected status %d", resp.StatusCode)
}

func decodeStateResult(body []byte, etag string, allowedStates ...State) (FetchResult, error) {
	var state StateResponse
	if err := decodeStrict(strings.NewReader(string(body)), &state); err != nil {
		return FetchResult{}, fmt.Errorf("cedar policy: decode state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return FetchResult{}, err
	}
	for _, allowed := range allowedStates {
		if state.State == allowed {
			return FetchResult{State: state.State, Response: &state, ETag: etag}, nil
		}
	}
	return FetchResult{}, fmt.Errorf("cedar policy: response state %q does not match HTTP status", state.State)
}

func parseETag(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "W/")
	if len(value) != 66 || value[0] != '"' || value[len(value)-1] != '"' {
		return ""
	}
	identity := value[1 : len(value)-1]
	if !sha256HexPattern.MatchString(identity) {
		return ""
	}
	return identity
}

func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
