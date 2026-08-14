package ledgerping

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func pingServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != Path {
			t.Errorf("path = %q, want %q", r.URL.Path, Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("authorization = %q, want bearer token", got)
		}
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}

func TestPingResolvesWorkspace(t *testing.T) {
	server := pingServer(t, http.StatusOK, `{"organization_id":"org_katana","organization_name":"Katana"}`)

	got, err := Ping(context.Background(), server.Client(), server.URL+"/", "test-token")
	if err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
	if got.OrganizationID != "org_katana" || got.OrganizationName != "Katana" {
		t.Fatalf("Ping() = %+v", got)
	}
}

func TestPingTreatsNullOrganizationNameAsEmpty(t *testing.T) {
	server := pingServer(t, http.StatusOK, `{"organization_id":"org_katana","organization_name":null}`)

	got, err := Ping(context.Background(), server.Client(), server.URL, "test-token")
	if err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
	if got.OrganizationName != "" {
		t.Fatalf("organization_name = %q, want empty for JSON null", got.OrganizationName)
	}
}

func TestPingReportsRejectedToken(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		server := pingServer(t, status, "")
		if _, err := Ping(context.Background(), server.Client(), server.URL, "test-token"); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("Ping() with HTTP %d error = %v, want ErrUnauthorized", status, err)
		}
	}
}

func TestPingReportsOtherStatuses(t *testing.T) {
	server := pingServer(t, http.StatusBadGateway, "")

	_, err := Ping(context.Background(), server.Client(), server.URL, "test-token")
	var statusErr *StatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusBadGateway {
		t.Fatalf("Ping() error = %v, want StatusError{502}", err)
	}
}

func TestPingRejectsMissingOrganizationID(t *testing.T) {
	server := pingServer(t, http.StatusOK, `{"organization_id":"  "}`)

	if _, err := Ping(context.Background(), server.Client(), server.URL, "test-token"); err == nil {
		t.Fatal("Ping() error = nil, want refusal on blank organization id")
	}
}

func TestPingRejectsMalformedBody(t *testing.T) {
	server := pingServer(t, http.StatusOK, `not json`)

	if _, err := Ping(context.Background(), server.Client(), server.URL, "test-token"); err == nil {
		t.Fatal("Ping() error = nil, want parse failure")
	}
}
