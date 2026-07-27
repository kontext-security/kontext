package run

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/auth"
	"github.com/kontext-security/kontext-cli/internal/credential"
	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	guardhookruntime "github.com/kontext-security/kontext-cli/internal/guard/hookruntime"
)

func TestResolveLocalModeAllowsOnlyObserve(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{"", "observe"} {
		got, err := resolveLocalMode(mode)
		if err != nil || got != guardhookruntime.ModeObserve {
			t.Fatalf("resolveLocalMode(%q) = %q, %v; want observe, nil", mode, got, err)
		}
	}
	for _, mode := range []string{"enforce", "remote"} {
		if _, err := resolveLocalMode(mode); err == nil || !strings.Contains(err.Error(), "managed daemon") {
			t.Fatalf("resolveLocalMode(%q) error = %v, want managed-daemon guidance", mode, err)
		}
	}
}

func TestFilterArgs(t *testing.T) {
	t.Parallel()

	args := []string{
		"--settings", "user-settings.json",
		"--dangerously-skip-permissions",
		"--setting-sources=local",
		"--allowed",
		"value",
		"--bare",
		"prompt",
	}

	got := filterArgs(args)
	want := []string{"--allowed", "value", "prompt"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filterArgs() = %#v, want %#v", got, want)
	}
}

func TestFindExecutableReturnsExecutablePath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "test-agent")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := findExecutable("test-agent", dir)
	if err != nil {
		t.Fatalf("findExecutable() error = %v", err)
	}
	if got != path {
		t.Fatalf("findExecutable() = %q, want %q", got, path)
	}
}

func TestFindExecutableDistinguishesNonExecutable(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "test-agent"), []byte("not executable"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := findExecutable("test-agent", dir)
	if err == nil {
		t.Fatal("findExecutable() error = nil, want non-executable error")
	}
	if !strings.Contains(err.Error(), "not executable") {
		t.Fatalf("findExecutable() error = %q, want not executable", err)
	}
}

func TestFindExecutableSkipsNonExecutablePathMatch(t *testing.T) {
	t.Parallel()

	firstDir := t.TempDir()
	secondDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(firstDir, "test-agent"), []byte("not executable"), 0o644); err != nil {
		t.Fatal(err)
	}

	want := filepath.Join(secondDir, "test-agent")
	if err := os.WriteFile(want, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := findExecutable("test-agent", firstDir+string(os.PathListSeparator)+secondDir)
	if err != nil {
		t.Fatalf("findExecutable() error = %v", err)
	}
	if got != want {
		t.Fatalf("findExecutable() = %q, want %q", got, want)
	}
}

func TestFindExecutableRejectsRelativePathMatch(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.Mkdir("bin", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("bin", "test-agent"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := findExecutable("test-agent", "bin")
	if !errors.Is(err, exec.ErrDot) {
		t.Fatalf("findExecutable() error = %v, want exec.ErrDot", err)
	}
}

func TestFindExecutableDistinguishesMissing(t *testing.T) {
	t.Parallel()

	_, err := findExecutable("test-agent", t.TempDir())
	if err == nil {
		t.Fatal("findExecutable() error = nil, want missing error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("findExecutable() error = %q, want not found", err)
	}
}

func TestCredentialFailureSummaryHidesRawDetails(t *testing.T) {
	t.Parallel()

	err := &credentialResolutionError{
		Reason:  failureTransient,
		Message: "Authorization: Bearer secret-token",
	}
	if got := credentialFailureSummary(err); got != "temporary exchange error" {
		t.Fatalf("credentialFailureSummary() = %q, want temporary exchange error", got)
	}

	rawErr := errors.New("code=secret-code")
	if got := credentialFailureSummary(rawErr); got != "run with --verbose for details" {
		t.Fatalf("credentialFailureSummary(raw) = %q, want verbose hint", got)
	}
}

func TestPrintHostedConnectInstructionsNonInteractiveDoesNotPrompt(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	var opened bool
	prompt := printHostedConnectInstructions(
		&output,
		"linear",
		"https://app.kontext.security/providers/connect#handshake=test",
		false,
		func(string) error {
			opened = true
			return nil
		},
	)
	if prompt {
		t.Fatal("prompt = true, want false")
	}
	if opened {
		t.Fatal("browser opener was called for non-interactive flow")
	}
	got := output.String()
	if !strings.Contains(got, "Open this URL") || strings.Count(got, "https://app.kontext.security") != 1 {
		t.Fatalf("output = %q, want one fallback URL", got)
	}
}

func TestPrintHostedConnectInstructionsShowsFallbackWhenBrowserOpenFails(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	prompt := printHostedConnectInstructions(
		&output,
		"linear, slack",
		"https://app.kontext.security/providers/connect#handshake=test",
		true,
		func(string) error {
			return fmt.Errorf("browser unavailable")
		},
	)
	if !prompt {
		t.Fatal("prompt = false, want true")
	}
	got := output.String()
	if !strings.Contains(got, "Could not open the browser automatically") {
		t.Fatalf("output = %q, want browser fallback", got)
	}
	if strings.Count(got, "https://app.kontext.security") != 1 {
		t.Fatalf("output = %q, want one fallback URL", got)
	}
}

func TestLaunchAgentWithSettingsReturnsAgentExitError(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("shell script launch test is POSIX-specific")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "test-agent")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 42\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	err := launchAgentWithSettings(context.Background(), "test-agent", path, os.Environ(), nil, "")
	var exitErr *AgentExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("launchAgentWithSettings() error = %T, want *AgentExitError", err)
	}
	if exitErr.ExitCode() != 42 {
		t.Fatalf("ExitCode() = %d, want 42", exitErr.ExitCode())
	}
}

func TestFetchConnectURL(t *testing.T) {
	t.Parallel()

	handlerErrs := make(chan error, 1)
	recordHandlerErr := func(format string, args ...any) {
		select {
		case handlerErrs <- fmt.Errorf(format, args...):
		default:
		}
	}

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"issuer":"%s","authorization_endpoint":"%s/oauth2/auth","token_endpoint":"%s/oauth2/token","jwks_uri":"%s/.well-known/jwks.json"}`, server.URL, server.URL, server.URL, server.URL)))
		case "/oauth2/token":
			if r.Method != http.MethodPost {
				recordHandlerErr("token method = %q, want %q", r.Method, http.MethodPost)
				http.Error(w, "bad method", http.StatusBadRequest)
				return
			}
			if got := r.Header.Get("Authorization"); got != "Bearer test-access-token" {
				recordHandlerErr("token authorization = %q, want %q", got, "Bearer test-access-token")
				http.Error(w, "bad auth", http.StatusUnauthorized)
				return
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				recordHandlerErr("read token body: %v", err)
				http.Error(w, "read error", http.StatusInternalServerError)
				return
			}
			values, err := url.ParseQuery(string(body))
			if err != nil {
				recordHandlerErr("parse token body: %v", err)
				http.Error(w, "parse error", http.StatusBadRequest)
				return
			}
			if got := values.Get("client_id"); got != "app_agent-123" {
				recordHandlerErr("client_id = %q, want %q", got, "app_agent-123")
				http.Error(w, "bad client", http.StatusBadRequest)
				return
			}
			if got := values.Get("resource"); got != "mcp-gateway" {
				recordHandlerErr("resource = %q, want %q", got, "mcp-gateway")
				http.Error(w, "bad resource", http.StatusBadRequest)
				return
			}
			if got := values.Get("scope"); got != "gateway:access" {
				recordHandlerErr("scope = %q, want %q", got, "gateway:access")
				http.Error(w, "bad scope", http.StatusBadRequest)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"gateway-token"}`))
		case "/mcp/connect-session":
			if r.Method != http.MethodPost {
				recordHandlerErr("connect method = %q, want %q", r.Method, http.MethodPost)
				http.Error(w, "bad method", http.StatusBadRequest)
				return
			}
			if got := r.Header.Get("Authorization"); got != "Bearer gateway-token" {
				recordHandlerErr("connect authorization = %q, want %q", got, "Bearer gateway-token")
				http.Error(w, "bad auth", http.StatusUnauthorized)
				return
			}
			if got := r.Header.Get("Content-Type"); got != "application/json" {
				recordHandlerErr("connect content-type = %q, want %q", got, "application/json")
				http.Error(w, "bad content-type", http.StatusBadRequest)
				return
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				recordHandlerErr("read connect body: %v", err)
				http.Error(w, "read error", http.StatusInternalServerError)
				return
			}
			if got := string(body); got != "{}" {
				recordHandlerErr("connect body = %q, want %q", got, "{}")
				http.Error(w, "bad body", http.StatusBadRequest)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"connectUrl":"https://app.kontext.security/providers/connect#handshake=session-123"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	session := &auth.Session{
		IssuerURL:   server.URL,
		AccessToken: "test-access-token",
	}

	got, err := fetchConnectURL(context.Background(), session, "app_agent-123")
	if err != nil {
		t.Fatalf("fetchConnectURL() error = %v", err)
	}
	select {
	case err := <-handlerErrs:
		t.Fatal(err)
	default:
	}

	want := "https://app.kontext.security/providers/connect#handshake=session-123"
	if got != want {
		t.Fatalf("fetchConnectURL() = %q, want %q", got, want)
	}
}

func TestFetchConnectURLReturnsErrorOnNon200(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"issuer":"%s","authorization_endpoint":"%s/oauth2/auth","token_endpoint":"%s/oauth2/token","jwks_uri":"%s/.well-known/jwks.json"}`, server.URL, server.URL, server.URL, server.URL)))
		case "/oauth2/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"gateway-token"}`))
		case "/mcp/connect-session":
			http.Error(w, "boom", http.StatusBadGateway)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	session := &auth.Session{
		IssuerURL:   server.URL,
		AccessToken: "test-access-token",
	}

	_, err := fetchConnectURL(context.Background(), session, "app_agent-123")
	if err == nil {
		t.Fatal("fetchConnectURL() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "502 Bad Gateway") {
		t.Fatalf("fetchConnectURL() error = %q, want status in message", err)
	}
}

func TestFetchConnectURLReturnsErrorOnEmptyConnectURL(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"issuer":"%s","authorization_endpoint":"%s/oauth2/auth","token_endpoint":"%s/oauth2/token","jwks_uri":"%s/.well-known/jwks.json"}`, server.URL, server.URL, server.URL, server.URL)))
		case "/oauth2/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"gateway-token"}`))
		case "/mcp/connect-session":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"connectUrl":""}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	session := &auth.Session{
		IssuerURL:   server.URL,
		AccessToken: "test-access-token",
	}

	_, err := fetchConnectURL(context.Background(), session, "app_agent-123")
	if err == nil {
		t.Fatal("fetchConnectURL() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "missing connectUrl") {
		t.Fatalf("fetchConnectURL() error = %q, want missing connectUrl message", err)
	}
}

func TestFetchConnectURLWithGatewayLoginFallback(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	var tokenExchangeCalls int
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"issuer":"%s","authorization_endpoint":"%s/oauth2/auth","token_endpoint":"%s/oauth2/token","jwks_uri":"%s/.well-known/jwks.json"}`, server.URL, server.URL, server.URL, server.URL)))
		case "/oauth2/token":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			values, err := url.ParseQuery(string(body))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if values.Get("resource") != "mcp-gateway" {
				http.Error(w, "wrong resource", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			tokenExchangeCalls++
			switch tokenExchangeCalls {
			case 1:
				if got := r.Header.Get("Authorization"); got != "Bearer stale-access-token" {
					http.Error(w, "wrong stale authorization", http.StatusUnauthorized)
					return
				}
				_, _ = w.Write([]byte(`{"error":"invalid_scope","error_description":"Requested scope 'gateway:access' exceeds subject token scopes"}`))
			case 2:
				if got := r.Header.Get("Authorization"); got != "Bearer gateway-login-token" {
					http.Error(w, "wrong gateway-login authorization", http.StatusUnauthorized)
					return
				}
				_, _ = w.Write([]byte(`{"access_token":"gateway-exchange-token"}`))
			default:
				http.Error(w, "unexpected token exchange call", http.StatusBadRequest)
				return
			}
		case "/mcp/connect-session":
			if got := r.Header.Get("Authorization"); got != "Bearer gateway-exchange-token" {
				http.Error(w, "wrong gateway authorization", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"connectUrl":"https://app.kontext.security/providers/connect#handshake=session-123"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	session := &auth.Session{
		IssuerURL:   server.URL,
		Subject:     "user-123",
		AccessToken: "stale-access-token",
	}

	var loginCalls int
	login := func(ctx context.Context, issuerURL, clientID string, scopes ...string) (*auth.LoginResult, error) {
		loginCalls++
		if issuerURL != server.URL {
			t.Fatalf("login issuerURL = %q, want %q", issuerURL, server.URL)
		}
		if clientID != "app_agent-123" {
			t.Fatalf("login clientID = %q, want %q", clientID, "app_agent-123")
		}
		if got := strings.Join(scopes, " "); got != "gateway:access" {
			t.Fatalf("login scopes = %q, want %q", got, "gateway:access")
		}

		result := &auth.LoginResult{Session: &auth.Session{
			IssuerURL:   server.URL,
			Subject:     "user-123",
			AccessToken: "gateway-login-token",
		}}
		return result, nil
	}

	got, err := fetchConnectURLWithGatewayLoginFallback(
		context.Background(),
		session,
		"app_agent-123",
		login,
	)
	if err != nil {
		t.Fatalf("fetchConnectURLWithGatewayLoginFallback() error = %v", err)
	}
	if loginCalls != 1 {
		t.Fatalf("loginCalls = %d, want 1", loginCalls)
	}
	if tokenExchangeCalls != 2 {
		t.Fatalf("tokenExchangeCalls = %d, want 2", tokenExchangeCalls)
	}
	if session.AccessToken != "stale-access-token" {
		t.Fatalf("session.AccessToken = %q, want stale token unchanged", session.AccessToken)
	}

	want := "https://app.kontext.security/providers/connect#handshake=session-123"
	if got != want {
		t.Fatalf("fetchConnectURLWithGatewayLoginFallback() = %q, want %q", got, want)
	}
}

func TestFetchConnectURLWithGatewayLoginFallbackRejectsAccountMismatch(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	var tokenExchangeCalls int
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"issuer":"%s","authorization_endpoint":"%s/oauth2/auth","token_endpoint":"%s/oauth2/token","jwks_uri":"%s/.well-known/jwks.json"}`, server.URL, server.URL, server.URL, server.URL)))
		case "/oauth2/token":
			tokenExchangeCalls++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":"invalid_scope","error_description":"Requested scope 'gateway:access' exceeds subject token scopes"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	session := &auth.Session{
		IssuerURL:   server.URL,
		Subject:     "active-user",
		AccessToken: "stale-access-token",
	}
	session.User.Email = "active@example.com"

	login := func(ctx context.Context, issuerURL, clientID string, scopes ...string) (*auth.LoginResult, error) {
		result := &auth.LoginResult{Session: &auth.Session{
			IssuerURL:   server.URL,
			Subject:     "browser-user",
			AccessToken: "gateway-login-token",
		}}
		result.Session.User.Email = "browser@example.com"
		return result, nil
	}

	_, err := fetchConnectURLWithGatewayLoginFallback(
		context.Background(),
		session,
		"app_agent-123",
		login,
	)
	if err == nil {
		t.Fatal("fetchConnectURLWithGatewayLoginFallback() error = nil, want mismatch")
	}
	if !strings.Contains(err.Error(), "different account") {
		t.Fatalf("error = %q, want different account message", err)
	}
	if summary := connectFailureSummary(err); !strings.Contains(summary, "active@example.com") || !strings.Contains(summary, "browser@example.com") {
		t.Fatalf("connectFailureSummary() = %q, want account labels", summary)
	}
	if tokenExchangeCalls != 1 {
		t.Fatalf("tokenExchangeCalls = %d, want only stale-token attempt", tokenExchangeCalls)
	}
}

func TestResolveCredentialsReturnsIdentityMismatchError(t *testing.T) {
	t.Parallel()

	fakeFetcher := func(
		ctx context.Context,
		session *auth.Session,
		credentialClientID string,
		interactive bool,
		login loginFunc,
	) (string, error) {
		return "", &identityMismatchError{
			activeLabel:  "active@example.com",
			browserLabel: "browser@example.com",
		}
	}

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"issuer":"%s","authorization_endpoint":"%s/oauth2/auth","token_endpoint":"%s/oauth2/token","jwks_uri":"%s/.well-known/jwks.json"}`, server.URL, server.URL, server.URL, server.URL)))
		case "/oauth2/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":"provider_required","error_description":"User has not configured provider 'Linear Stub'","failure_reason":"disconnected_or_reauth_required","provider_name":"Linear Stub","provider_id":"provider-linear"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	session := &auth.Session{
		IssuerURL:   server.URL,
		AccessToken: "test-access-token",
	}
	provider := newHostedCredentialProvider(session, "app_agent-123")
	provider.connect = fakeFetcher

	_, err := resolveCredentials(
		context.Background(),
		provider,
		[]credential.Entry{{EnvVar: "LINEAR_API_KEY", Provider: "linear"}},
		diagnostic.New(io.Discard, false),
	)
	if err == nil {
		t.Fatal("resolveCredentials() error = nil, want mismatch")
	}

	var mismatch *identityMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("resolveCredentials() error = %T, want *identityMismatchError", err)
	}
}

func TestEnsureSameIdentityComparesIssuerAndSubject(t *testing.T) {
	t.Parallel()

	active := &auth.Session{IssuerURL: "https://issuer-a.example", Subject: "same-subject"}
	browser := &auth.Session{IssuerURL: "https://issuer-b.example", Subject: "same-subject"}

	err := ensureSameIdentity(active, browser)
	if err == nil {
		t.Fatal("ensureSameIdentity() error = nil, want issuer mismatch")
	}
	if !strings.Contains(err.Error(), "different account") {
		t.Fatalf("ensureSameIdentity() error = %q, want different account", err)
	}
}

func TestResolveCredentialsUsesInjectedProvider(t *testing.T) {
	t.Parallel()

	var calls int
	provider := recordingCredentialProvider{
		resolve: func(_ context.Context, entry credential.Entry) (credential.Resolved, error) {
			calls++
			if entry.EnvVar != "GITHUB_TOKEN" {
				t.Fatalf("entry.EnvVar = %q, want GITHUB_TOKEN", entry.EnvVar)
			}
			return credential.Resolved{Entry: entry, Value: "resolved-token"}, nil
		},
	}

	resolved, err := resolveCredentials(
		context.Background(),
		provider,
		[]credential.Entry{{EnvVar: "GITHUB_TOKEN", Provider: "github"}},
		diagnostic.New(io.Discard, false),
	)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("provider calls = %d, want 1", calls)
	}
	if len(resolved) != 1 || resolved[0].Value != "resolved-token" {
		t.Fatalf("resolved = %+v", resolved)
	}
}

func TestHostedCredentialProviderConnectURLUsesOwnSessionAndClientID(t *testing.T) {
	t.Parallel()

	session := &auth.Session{IssuerURL: "https://issuer.example"}
	provider := newHostedCredentialProvider(session, "app_agent-123")
	var gotSession *auth.Session
	var gotClientID string
	provider.connect = func(
		_ context.Context,
		session *auth.Session,
		credentialClientID string,
		interactive bool,
		login loginFunc,
	) (string, error) {
		gotSession = session
		gotClientID = credentialClientID
		if interactive {
			t.Fatal("interactive = true, want false")
		}
		return "https://app.kontext.security/providers/connect#handshake=session-123", nil
	}

	got, err := provider.ConnectURL(context.Background(), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if gotSession != session || gotClientID != "app_agent-123" {
		t.Fatalf("connect used session=%p clientID=%q, want provider-owned session=%p clientID=app_agent-123", gotSession, gotClientID, session)
	}
	if got == "" {
		t.Fatal("ConnectURL() returned empty URL")
	}
}

func TestFetchConnectURLForConnectFlowSkipsLoginWhenNonInteractive(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"issuer":"%s","authorization_endpoint":"%s/oauth2/auth","token_endpoint":"%s/oauth2/token","jwks_uri":"%s/.well-known/jwks.json"}`, server.URL, server.URL, server.URL, server.URL)))
		case "/oauth2/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":"invalid_scope","error_description":"Requested scope 'gateway:access' exceeds subject token scopes"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	session := &auth.Session{
		IssuerURL:   server.URL,
		AccessToken: "stale-access-token",
	}

	var loginCalls int
	login := func(ctx context.Context, issuerURL, clientID string, scopes ...string) (*auth.LoginResult, error) {
		loginCalls++
		return nil, fmt.Errorf("login should not be called")
	}

	_, err := fetchConnectURLForConnectFlow(
		context.Background(),
		session,
		"app_agent-123",
		false,
		login,
	)
	if err == nil {
		t.Fatal("fetchConnectURLForConnectFlow() error = nil, want non-nil")
	}
	if loginCalls != 0 {
		t.Fatalf("loginCalls = %d, want 0", loginCalls)
	}
	if !needsGatewayAccessReauthentication(err) {
		t.Fatalf("err = %v, want gateway reauthentication failure", err)
	}
}

func TestExchangeCredentialUsesProvidedClientID(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"issuer":"%s","authorization_endpoint":"%s/oauth2/auth","token_endpoint":"%s/oauth2/token","jwks_uri":"%s/.well-known/jwks.json"}`, server.URL, server.URL, server.URL, server.URL)))
		case "/oauth2/token":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			values, err := url.ParseQuery(string(body))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if got := values.Get("client_id"); got != "app_agent-123" {
				http.Error(w, "wrong client_id", http.StatusBadRequest)
				return
			}
			if got := values.Get("resource"); got != "github" {
				http.Error(w, "wrong resource", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"provider-token"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	session := &auth.Session{
		IssuerURL:   server.URL,
		AccessToken: "test-access-token",
	}

	value, err := exchangeCredential(
		context.Background(),
		session,
		credential.Entry{EnvVar: "GITHUB_TOKEN", Provider: "github"},
		"app_agent-123",
	)
	if err != nil {
		t.Fatalf("exchangeCredential() error = %v", err)
	}
	if value != "provider-token" {
		t.Fatalf("exchangeCredential() = %q, want %q", value, "provider-token")
	}
}

func TestExchangeCredentialReturnsTypedFailureReason(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"issuer":"%s","authorization_endpoint":"%s/oauth2/auth","token_endpoint":"%s/oauth2/token","jwks_uri":"%s/.well-known/jwks.json"}`, server.URL, server.URL, server.URL, server.URL)))
		case "/oauth2/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":"provider_required","error_description":"User has not configured provider 'Linear Stub'","failure_reason":"disconnected_or_reauth_required","provider_name":"Linear Stub","provider_id":"provider-linear"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	session := &auth.Session{
		IssuerURL:   server.URL,
		AccessToken: "test-access-token",
	}

	_, err := exchangeCredential(
		context.Background(),
		session,
		credential.Entry{EnvVar: "LINEAR_API_KEY", Provider: "linear"},
		"app_agent-123",
	)
	if err == nil {
		t.Fatal("exchangeCredential() error = nil, want non-nil")
	}

	resolutionErr, ok := err.(*credentialResolutionError)
	if !ok {
		t.Fatalf("exchangeCredential() error type = %T, want *credentialResolutionError", err)
	}
	if resolutionErr.Reason != failureDisconnected {
		t.Fatalf("resolutionErr.Reason = %q, want %q", resolutionErr.Reason, failureDisconnected)
	}
}

func TestClassifyCredentialFailureSupportsLegacyTokenErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		result *tokenExchangeResponse
		want   credentialFailureReason
	}{
		{
			name: "provider required",
			result: &tokenExchangeResponse{
				Error: "provider_required",
			},
			want: failureDisconnected,
		},
		{
			name: "provider not configured",
			result: &tokenExchangeResponse{
				Error: "provider_not_configured",
			},
			want: failureDisconnected,
		},
		{
			name: "reauthorization required",
			result: &tokenExchangeResponse{
				Error: "provider_reauthorization_required",
			},
			want: failureDisconnected,
		},
		{
			name: "invalid target not connected",
			result: &tokenExchangeResponse{
				Error:     "invalid_target",
				ErrorDesc: "provider is not connected",
			},
			want: failureDisconnected,
		},
		{
			name: "invalid target not allowed",
			result: &tokenExchangeResponse{
				Error:     "invalid_target",
				ErrorDesc: "provider is not allowed for this application",
			},
			want: failureDisconnected,
		},
		{
			name: "unknown legacy error",
			result: &tokenExchangeResponse{
				Error: "invalid_target",
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := classifyCredentialFailure(tt.result); got != tt.want {
				t.Fatalf("classifyCredentialFailure() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCredentialClientIDForAgent(t *testing.T) {
	t.Parallel()

	got, err := credentialClientIDForAgent("agent-123")
	if err != nil {
		t.Fatalf("credentialClientIDForAgent() error = %v", err)
	}
	if got != "app_agent-123" {
		t.Fatalf("credentialClientIDForAgent() = %q, want %q", got, "app_agent-123")
	}

	if _, err := credentialClientIDForAgent(""); err == nil {
		t.Fatal("credentialClientIDForAgent() empty agent error = nil, want non-nil")
	}
}

func TestBuildEnvUsesLiteralValuesAndResolvedPlaceholders(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "shell-token")

	env := buildEnv(
		&credential.TemplateFile{
			Entries: []credential.Entry{
				{EnvVar: "GITHUB_TOKEN", Provider: "github"},
			},
			ExistingValues: map[string]string{
				"GITHUB_TOKEN":   "{{kontext:github}}",
				"LINEAR_API_KEY": "literal-linear-token",
			},
		},
		[]credential.Resolved{
			{
				Entry: credential.Entry{
					EnvVar:   "GITHUB_TOKEN",
					Provider: "github",
				},
				Value: "resolved-github-token",
			},
		},
	)

	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "GITHUB_TOKEN=resolved-github-token") {
		t.Fatalf("buildEnv() missing resolved github token: %q", joined)
	}
	if !strings.Contains(joined, "LINEAR_API_KEY=literal-linear-token") {
		t.Fatalf("buildEnv() missing literal linear token: %q", joined)
	}
}

func TestBuildEnvNormalizesQuotedLiteralValues(t *testing.T) {
	t.Parallel()

	env := buildEnv(
		&credential.TemplateFile{
			ExistingValues: map[string]string{
				"OPENAI_API_KEY": "\"sk-test-token\"",
				"CALLBACK_URL":   "'https://example.com/callback'",
			},
		},
		nil,
	)

	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "OPENAI_API_KEY=sk-test-token") {
		t.Fatalf("buildEnv() missing normalized openai token: %q", joined)
	}
	if strings.Contains(joined, "OPENAI_API_KEY=\"sk-test-token\"") {
		t.Fatalf("buildEnv() preserved quoted openai token: %q", joined)
	}
	if !strings.Contains(joined, "CALLBACK_URL=https://example.com/callback") {
		t.Fatalf("buildEnv() missing normalized callback url: %q", joined)
	}
	if strings.Contains(joined, "CALLBACK_URL='https://example.com/callback'") {
		t.Fatalf("buildEnv() preserved quoted callback url: %q", joined)
	}
}

func TestBuildEnvStripsInlineCommentsFromLiteralValues(t *testing.T) {
	t.Parallel()

	env := buildEnv(
		&credential.TemplateFile{
			ExistingValues: map[string]string{
				"OPENAI_API_KEY": "sk-test-token # production",
				"CALLBACK_URL":   "\"https://example.com/callback\" # main callback",
			},
		},
		nil,
	)

	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "OPENAI_API_KEY=sk-test-token") {
		t.Fatalf("buildEnv() missing stripped literal token: %q", joined)
	}
	if strings.Contains(joined, "OPENAI_API_KEY=sk-test-token # production") {
		t.Fatalf("buildEnv() preserved inline comment on token: %q", joined)
	}
	if !strings.Contains(joined, "CALLBACK_URL=https://example.com/callback") {
		t.Fatalf("buildEnv() missing stripped callback url: %q", joined)
	}
	if strings.Contains(joined, "CALLBACK_URL=\"https://example.com/callback\" # main callback") {
		t.Fatalf("buildEnv() preserved inline comment on callback url: %q", joined)
	}
}

func TestBuildEnvPreservesLiteralHashFragmentsWithoutWhitespace(t *testing.T) {
	t.Parallel()

	env := buildEnv(
		&credential.TemplateFile{
			ExistingValues: map[string]string{
				"CALLBACK_URL": "https://example.com/callback#fragment",
			},
		},
		nil,
	)

	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "CALLBACK_URL=https://example.com/callback#fragment") {
		t.Fatalf("buildEnv() lost url fragment: %q", joined)
	}
}

func TestBuildEnvTreatsCommentOnlyRightHandSideAsEmpty(t *testing.T) {
	t.Parallel()

	env := buildEnv(
		&credential.TemplateFile{
			ExistingValues: map[string]string{
				"OPENAI_API_KEY": " # set later",
			},
		},
		nil,
	)

	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "OPENAI_API_KEY=") {
		t.Fatalf("buildEnv() missing empty env assignment: %q", joined)
	}
	if strings.Contains(joined, "OPENAI_API_KEY=# set later") {
		t.Fatalf("buildEnv() preserved comment-only value: %q", joined)
	}
}

type recordingSessionEnder struct {
	sessionID string
	calls     int
}

func (r *recordingSessionEnder) EndSession(_ context.Context, sessionID string) error {
	r.calls++
	r.sessionID = sessionID
	return nil
}

func TestEndManagedSessionEndsTheManagedSession(t *testing.T) {
	t.Parallel()

	client := &recordingSessionEnder{}
	var output bytes.Buffer

	endManagedSession(client, "session-1234567890", &output)

	if client.calls != 1 {
		t.Fatalf("EndSession calls = %d, want 1", client.calls)
	}
	if client.sessionID != "session-1234567890" {
		t.Fatalf("EndSession sessionID = %q, want %q", client.sessionID, "session-1234567890")
	}
	if got := output.String(); !strings.Contains(got, "Session ended") {
		t.Fatalf("output = %q, want session-ended message", got)
	}
}

func TestShouldRefreshSessionUsesProactiveWindow(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name         string
		expiresAt    time.Time
		forceRefresh bool
		want         bool
	}{
		{
			name:      "outside proactive window",
			expiresAt: now.Add(proactiveRefreshWindow + time.Second),
			want:      false,
		},
		{
			name:      "inside proactive window",
			expiresAt: now.Add(proactiveRefreshWindow - time.Second),
			want:      true,
		},
		{
			name:      "at proactive window",
			expiresAt: now.Add(proactiveRefreshWindow),
			want:      true,
		},
		{
			name:         "forced refresh",
			expiresAt:    now.Add(time.Hour),
			forceRefresh: true,
			want:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			session := &auth.Session{ExpiresAt: tt.expiresAt}
			got := shouldRefreshSession(session, tt.forceRefresh, now)
			if got != tt.want {
				t.Fatalf("shouldRefreshSession() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateSettingsWritesClaudeHooks(t *testing.T) {
	t.Parallel()

	sessionDir := t.TempDir()
	settingsPath, err := GenerateSettings(sessionDir, "/usr/local/bin/kontext", "claude")
	if err != nil {
		t.Fatalf("GenerateSettings() error = %v", err)
	}

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	var settings claudeSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	wantEvents := []string{"PreToolUse", "PostToolUse", "UserPromptSubmit"}
	if len(settings.Hooks) != len(wantEvents) {
		t.Fatalf("settings.Hooks len = %d, want %d", len(settings.Hooks), len(wantEvents))
	}

	wantCommand := "/usr/local/bin/kontext hook --agent claude"
	for _, event := range wantEvents {
		groups, ok := settings.Hooks[event]
		if !ok {
			t.Fatalf("settings.Hooks missing %q", event)
		}
		if len(groups) != 1 {
			t.Fatalf("%s groups len = %d, want 1", event, len(groups))
		}
		if groups[0].Matcher != "*" {
			t.Fatalf("%s matcher = %q, want *", event, groups[0].Matcher)
		}
		if len(groups[0].Hooks) != 1 {
			t.Fatalf("%s hooks len = %d, want 1", event, len(groups[0].Hooks))
		}

		hook := groups[0].Hooks[0]
		if hook.Type != "command" {
			t.Fatalf("%s hook type = %q, want %q", event, hook.Type, "command")
		}
		if hook.Command != wantCommand {
			t.Fatalf("%s hook command = %q, want %q", event, hook.Command, wantCommand)
		}
		if hook.Timeout != 10 {
			t.Fatalf("%s hook timeout = %d, want 10", event, hook.Timeout)
		}
	}
}

func TestGenerateLocalSettingsWritesSocketHooks(t *testing.T) {
	t.Parallel()

	sessionDir := t.TempDir()
	settingsPath, err := GenerateLocalSettings(sessionDir, "/usr/local/bin/kontext", "claude", "/tmp/kontext.sock", "observe")
	if err != nil {
		t.Fatalf("GenerateLocalSettings() error = %v", err)
	}

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	var settings claudeSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	wantEvents := []string{"PreToolUse", "PostToolUse"}
	wantCommand := `'/usr/local/bin/kontext' hook --agent 'claude' --mode 'observe' --socket '/tmp/kontext.sock'`
	for _, event := range wantEvents {
		groups, ok := settings.Hooks[event]
		if !ok {
			t.Fatalf("settings.Hooks missing %q", event)
		}
		if len(groups) != 1 {
			t.Fatalf("%s groups len = %d, want 1", event, len(groups))
		}
		if len(groups[0].Hooks) != 1 {
			t.Fatalf("%s hooks len = %d, want 1", event, len(groups[0].Hooks))
		}
		hook := groups[0].Hooks[0]
		if hook.Command != wantCommand {
			t.Fatalf("%s hook command = %q, want %q", event, hook.Command, wantCommand)
		}
		if hook.Timeout != 10 {
			t.Fatalf("%s hook timeout = %d, want 10", event, hook.Timeout)
		}
	}
}

func TestVerifyBlockingHookSettingsRequiresPreToolUseCommand(t *testing.T) {
	t.Parallel()

	sessionDir := t.TempDir()
	settingsPath, err := GenerateSettings(sessionDir, "/usr/local/bin/kontext", "claude")
	if err != nil {
		t.Fatalf("GenerateSettings() error = %v", err)
	}
	if err := VerifyBlockingHookSettings(settingsPath, "/usr/local/bin/kontext", "claude"); err != nil {
		t.Fatalf("VerifyBlockingHookSettings() error = %v", err)
	}

	settings := claudeSettings{
		Hooks: map[string][]hookGroup{
			"PostToolUse": commandHookGroups("/usr/local/bin/kontext hook --agent claude"),
		},
	}
	data, err := json.Marshal(settings)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	brokenPath := filepath.Join(sessionDir, "broken-settings.json")
	if err := os.WriteFile(brokenPath, data, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if err := VerifyBlockingHookSettings(brokenPath, "/usr/local/bin/kontext", "claude"); err == nil {
		t.Fatal("VerifyBlockingHookSettings() error = nil, want missing PreToolUse hook error")
	}
}

type recordingCredentialProvider struct {
	resolve func(context.Context, credential.Entry) (credential.Resolved, error)
	connect func(context.Context, bool, loginFunc) (string, error)
}

func (p recordingCredentialProvider) ResolveCredential(ctx context.Context, entry credential.Entry) (credential.Resolved, error) {
	if p.resolve == nil {
		return credential.Resolved{}, errors.New("resolve credential should not be called")
	}
	return p.resolve(ctx, entry)
}

func (p recordingCredentialProvider) ConnectURL(ctx context.Context, interactive bool, login loginFunc) (string, error) {
	if p.connect == nil {
		return "", errors.New("connect url should not be called")
	}
	return p.connect(ctx, interactive, login)
}
