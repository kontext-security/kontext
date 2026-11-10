package endpointconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kontext-security/kontext/internal/cloudhttp"
)

var ErrAuthorityRejected = errors.New("endpoint configuration authority rejected")

var installationIDPattern = regexp.MustCompile(`^ins_[A-Za-z0-9_-]{32}$`)

type FetchResult struct {
	NotModified bool
	Response    *Response
	ETag        string
}

type Client struct {
	baseURL string
	http    *http.Client
	now     func() time.Time

	mu sync.Mutex
	// fallbackUntil is when the client next asks for ResponseVersion, after
	// the server last refused it.
	fallbackUntil time.Time
}

// fallbackFor is how long the client asks a server that refused
// ResponseVersion for FallbackResponseVersion straight away, one request per
// refresh, before it asks for ResponseVersion again.
const fallbackFor = time.Hour

func NewClient(baseURL string, httpClient *http.Client) (*Client, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("endpoint configuration: invalid base URL")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())) {
		return nil, errors.New("endpoint configuration: base URL must use HTTPS or loopback HTTP")
	}
	if httpClient == nil {
		httpClient = cloudhttp.NewClient(10 * time.Second)
	}
	return &Client{baseURL: strings.TrimRight(parsed.String(), "/"), http: httpClient, now: time.Now}, nil
}

// errUnsupportedVersion is a server's 406 unsupported_version: it predates the
// response version asked for.
var errUnsupportedVersion = errors.New("endpoint configuration: response version not supported by the server")

// Fetch gets the configuration as ResponseVersion has it, or as
// FallbackResponseVersion has it from a server that predates
// ResponseVersion. The conditional value may be either version's:
// identities differ across versions, so it matches only a response of its
// own.
func (c *Client) Fetch(ctx context.Context, installToken, installationID, configIdentity string) (FetchResult, error) {
	c.mu.Lock()
	fallingBack := c.now().Before(c.fallbackUntil)
	c.mu.Unlock()
	if fallingBack {
		return c.fetch(ctx, FallbackResponseVersion, installToken, installationID, configIdentity)
	}
	result, err := c.fetch(ctx, ResponseVersion, installToken, installationID, configIdentity)
	if errors.Is(err, errUnsupportedVersion) {
		c.mu.Lock()
		c.fallbackUntil = c.now().Add(fallbackFor)
		c.mu.Unlock()
		return c.fetch(ctx, FallbackResponseVersion, installToken, installationID, configIdentity)
	}
	return result, err
}

func (c *Client) fetch(ctx context.Context, version int, installToken, installationID, configIdentity string) (FetchResult, error) {
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
	// Ask for a version this build implements. The server serves every version
	// side by side, so this is what selects the shape and the identity domain.
	query.Set("response_version", strconv.Itoa(version))
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
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return FetchResult{}, fmt.Errorf("%w: status %d", ErrAuthorityRejected, response.StatusCode)
	}
	etag := parseETag(response.Header.Get("ETag"))
	if response.StatusCode == http.StatusNotModified {
		if configIdentity == "" || etag != configIdentity {
			return FetchResult{}, errors.New("endpoint configuration: invalid not-modified ETag")
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1))
		return FetchResult{NotModified: true, ETag: etag}, nil
	}
	if response.StatusCode == http.StatusNotAcceptable && version != FallbackResponseVersion {
		var refused struct {
			Code string `json:"code"`
		}
		data, _ := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
		if json.Unmarshal(data, &refused) == nil && refused.Code == "unsupported_version" {
			return FetchResult{}, errUnsupportedVersion
		}
		return FetchResult{}, fmt.Errorf("endpoint configuration fetch: unexpected status %d", response.StatusCode)
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
	if decoded.ResponseVersion != version {
		return FetchResult{}, fmt.Errorf("endpoint configuration: response version %d, asked for %d", decoded.ResponseVersion, version)
	}
	if etag == "" || etag != decoded.ConfigIdentity {
		return FetchResult{}, errors.New("endpoint configuration: ETag does not match config identity")
	}
	return FetchResult{Response: &decoded, ETag: etag}, nil
}

// parseETag extracts the config identity from a strong or weak ETag. Weak
// ETags are accepted because an intermediary that transforms the response
// representation (compression, say) may legally weaken the validator
// (RFC 9110 section 8.8.1); the identity inside is still the value the origin
// computed. The Cedar policy client applies the same tolerance.
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
