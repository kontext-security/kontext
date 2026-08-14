// Package ledgerping resolves an install token to the workspace that owns it,
// via the hosted ledger API's ping endpoint. Setup uses it to validate a
// pasted token before anything is written; the daemon uses it to learn the
// organization id that keys the device reconciliation key. It is the one
// place the CLI answers "whose token is this", so the two callers cannot
// drift apart.
package ledgerping

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const Path = "/api/v1/authorization-ledger/ping"

// ErrUnauthorized reports a 401/403: the token itself was rejected. Callers
// own the user-facing copy — setup tells a human where to mint a new token,
// the daemon just logs — so this stays a bare sentinel.
var ErrUnauthorized = errors.New("install token rejected")

// StatusError reports any other non-2xx answer, preserving the code so
// callers can phrase their own message around it.
type StatusError struct {
	StatusCode int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("ping returned HTTP %d", e.StatusCode)
}

type Response struct {
	OrganizationID string `json:"organization_id"`
	// JSON null (the legacy env-fallback org) decodes to "".
	OrganizationName string `json:"organization_name"`
}

// Ping resolves token against cloudURL. A nil client gets a 10s-timeout
// default, matching what setup has always used.
func Ping(ctx context.Context, client *http.Client, cloudURL, token string) (Response, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(cloudURL, "/")+Path, nil)
	if err != nil {
		return Response{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return Response{}, fmt.Errorf("cannot reach %s: %w", cloudURL, err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return Response{}, ErrUnauthorized
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return Response{}, &StatusError{StatusCode: resp.StatusCode}
	}

	var ping Response
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&ping); err != nil {
		return Response{}, fmt.Errorf("parse ping response: %w", err)
	}
	if strings.TrimSpace(ping.OrganizationID) == "" {
		return Response{}, errors.New("server did not return an organization id for this token")
	}
	return ping, nil
}
