package endpointconfig

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var installationIDPattern = regexp.MustCompile(`^ins_[A-Za-z0-9_-]{32}$`)

type FetchResult struct {
	NotModified bool
	Response    *Response
	ETag        string
}

type Client struct {
	baseURL string
	http    *http.Client
}

func NewClient(baseURL string, httpClient *http.Client) (*Client, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("endpoint configuration: invalid base URL")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())) {
		return nil, errors.New("endpoint configuration: base URL must use HTTPS or loopback HTTP")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{baseURL: strings.TrimRight(parsed.String(), "/"), http: httpClient}, nil
}

func (c *Client) Fetch(ctx context.Context, installToken, installationID, configIdentity string) (FetchResult, error) {
	if !installationIDPattern.MatchString(installationID) {
		return FetchResult{}, errors.New("endpoint configuration: invalid installation ID")
	}
	if strings.TrimSpace(installToken) == "" {
		return FetchResult{}, errors.New("endpoint configuration: install token is required")
	}
	endpoint, err := url.Parse(c.baseURL + "/api/v1/installations/" + installationID + "/configuration")
	if err != nil {
		return FetchResult{}, err
	}
	query := endpoint.Query()
	// Ask for the version this build implements. The server serves v1 and v2 side
	// by side, so this is what selects the shape and the identity domain.
	query.Set("response_version", strconv.Itoa(ResponseVersion))
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return FetchResult{}, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(installToken))
	if configIdentity != "" {
		if !sha256HexPattern.MatchString(configIdentity) {
			return FetchResult{}, errors.New("endpoint configuration: invalid conditional identity")
		}
		req.Header.Set("If-None-Match", `"`+configIdentity+`"`)
	}
	response, err := c.http.Do(req)
	if err != nil {
		return FetchResult{}, fmt.Errorf("endpoint configuration fetch: %w", err)
	}
	defer response.Body.Close()
	etag := parseETag(response.Header.Get("ETag"))
	if response.StatusCode == http.StatusNotModified {
		if configIdentity == "" || etag != configIdentity {
			return FetchResult{}, errors.New("endpoint configuration: invalid not-modified ETag")
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1))
		return FetchResult{NotModified: true, ETag: etag}, nil
	}
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, MaxResponseBytes+1))
		return FetchResult{}, fmt.Errorf("endpoint configuration fetch: unexpected status %d", response.StatusCode)
	}
	var decoded Response
	if err := decodeStrict(response.Body, &decoded); err != nil {
		return FetchResult{}, fmt.Errorf("endpoint configuration: decode response: %w", err)
	}
	if err := decoded.Validate(); err != nil {
		return FetchResult{}, err
	}
	if etag == "" || etag != decoded.ConfigIdentity {
		return FetchResult{}, errors.New("endpoint configuration: ETag does not match config identity")
	}
	return FetchResult{Response: &decoded, ETag: etag}, nil
}

func parseETag(value string) string {
	value = strings.TrimSpace(value)
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
