// Package codexproxy is a loopback reverse proxy between Codex and the
// ChatGPT Codex backend. It shortens printed parts of code mode results in
// each Responses request before the model sees them, as tool output
// compaction does through hooks for other calls, which hooks cannot change.
//
// Codex reaches it through `openai_base_url = "http://127.0.0.1:<port>/<token>/backend-api/codex"`.
// The token keeps other local processes and web pages from using the proxy;
// the /backend-api/codex suffix keeps Codex's ChatGPT-backend behaviour on.
// Headers pass through untouched and are never logged, and every failure
// sends the request upstream as Codex wrote it.
package codexproxy

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
)

const (
	// DefaultUpstream is where Codex sends a ChatGPT login's model traffic,
	// and DefaultAPIUpstream where it sends an API key's.
	DefaultUpstream    = "https://chatgpt.com/backend-api/codex"
	DefaultAPIUpstream = "https://api.openai.com/v1"
	// codexSuffix is the path Codex appends its routes to. Keeping it in the
	// configured base URL keeps Codex's backend-only behaviour (model
	// headers, context management) the same as without the proxy; Codex
	// keeps those to ChatGPT logins either way.
	codexSuffix = "/backend-api/codex"

	maxBodyBytes    = 64 << 20
	maxDecodedBytes = 256 << 20

	// HealthRoute answers HealthBody straight from the proxy.
	HealthRoute = "/kontext-health"
	HealthBody  = "kontext codex proxy\n"
)

// Options configure a Server.
type Options struct {
	// Upstream is the Codex backend base URL, for requests a ChatGPT login
	// signs; DefaultUpstream when nil. APIUpstream is the OpenAI API base URL,
	// for requests an API key signs; DefaultAPIUpstream when nil.
	Upstream    *url.URL
	APIUpstream *url.URL
	// Token is the secret first path segment.
	Token string
	// Rewriter decides replacements; requests pass through unchanged when nil.
	Rewriter *Rewriter
	// Held reports whether a daemon still holds the route the proxy serves;
	// requests it finds unheld pass through unchanged, asking the daemon
	// nothing. Nil holds always.
	Held func(context.Context) bool
	// Transport reaches the upstream; a clone of http.DefaultTransport when nil.
	Transport http.RoundTripper
	// Logf receives one line per request: never headers, bodies or the token.
	Logf func(format string, args ...any)
}

// Server is the proxy's HTTP handler.
type Server struct {
	upstream    *url.URL
	apiUpstream *url.URL
	token       []byte
	rewriter    *Rewriter
	held        func(context.Context) bool
	proxy       *httputil.ReverseProxy
	logf        func(format string, args ...any)
}

// New builds a Server.
func New(opts Options) (*Server, error) {
	if len(opts.Token) < 32 {
		return nil, errors.New("codexproxy: token must be at least 32 characters")
	}
	upstream := opts.Upstream
	if upstream == nil {
		upstream, _ = url.Parse(DefaultUpstream)
	}
	apiUpstream := opts.APIUpstream
	if apiUpstream == nil {
		apiUpstream, _ = url.Parse(DefaultAPIUpstream)
	}
	transport := opts.Transport
	if transport == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		// Pass Codex's Accept-Encoding through as it is instead of adding gzip.
		t.DisableCompression = true
		transport = t
	}
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	s := &Server{upstream: upstream, apiUpstream: apiUpstream, token: []byte(opts.Token), rewriter: opts.Rewriter, held: opts.Held, logf: logf}
	s.proxy = &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			// Out.URL is already the upstream URL the request's credentials
			// pick; see ServeHTTP. No X-Forwarded-* headers: the backend
			// should see what Codex sent.
			r.Out.Host = r.Out.URL.Host
		},
		Transport:     transport,
		FlushInterval: -1, // SSE: hand every event to Codex as it arrives
		// ReverseProxy's own messages go through scrub: URLs carry the token.
		ErrorLog: log.New(logWriter(func(line string) { logf("%s", scrub(line, opts.Token)) }), "", 0),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logf("upstream error for %s: %s", r.URL.Path, scrub(err.Error(), opts.Token))
			w.WriteHeader(http.StatusBadGateway)
		},
		// Never follow a redirect: the response, Location and all, goes back
		// to Codex, which refuses redirects on its own backend routes.
	}
	return s, nil
}

// Listen binds the loopback port. Port 0 picks a free one.
func Listen(port int) (net.Listener, error) {
	return net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
}

// BaseURL is the openai_base_url Codex needs for this server.
func BaseURL(addr net.Addr, token string) string {
	return fmt.Sprintf("http://%s/%s%s", addr.String(), token, codexSuffix)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if !loopbackHost(r.Host) {
		// A web page that rebinds a hostname to 127.0.0.1 sends its own Host.
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	rest, ok := s.strip(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if rest == HealthRoute {
		// The daemon's check that this job, not another process, holds the
		// port. Nothing goes upstream.
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, HealthBody)
		return
	}
	route := strings.TrimPrefix(rest, codexSuffix)
	if route == rest || !strings.HasPrefix(route, "/") {
		http.NotFound(w, r)
		return
	}
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		// Codex switches the session to HTTP at once on 426, without retries
		// or a warning. Any other answer costs about 7 s of retries per session.
		w.WriteHeader(http.StatusUpgradeRequired)
		s.logf("%s %s -> 426 (websocket declined)", r.Method, route)
		return
	}
	upstream := s.upstreamFor(r.Header)
	r.URL.Scheme, r.URL.Host = upstream.Scheme, upstream.Host
	r.URL.Path = strings.TrimRight(upstream.Path, "/") + route
	r.URL.RawPath = ""
	// Every request asks, so a route no daemon holds goes at the first one;
	// the requests of the Codex processes that read it pass through as they
	// are.
	held := s.held == nil || s.held(r.Context())
	note := ""
	if r.Method == http.MethodPost && route == "/responses" {
		switch {
		case s.rewriter == nil:
			note = " (passed through)"
		case !held:
			note = " (passed through: no daemon holds the route)"
		default:
			note = s.rewriteRequest(r)
		}
	}
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	// One line per model request, and per failure; never headers, bodies or
	// the token. Deferred: Codex hangs up once a response completes, often
	// before the upstream ends its stream, and ReverseProxy then aborts the
	// handler with a panic.
	defer func() {
		if note != "" || rec.status >= http.StatusBadRequest {
			s.logf("%s %s -> %d in %s via %s%s", r.Method, route, rec.status, time.Since(start).Round(time.Millisecond), upstream.Host, note)
		}
	}()
	s.proxy.ServeHTTP(rec, r)
}

// upstreamFor picks where a request goes from the credentials Codex signed
// it with, as Codex itself does without a base URL of its own: every ChatGPT
// login (OAuth, tokens from the app, agent identities, access tokens) names
// its account in ChatGPT-Account-ID, which an API key, sent as a bearer
// token alone, never does. Anything else goes to the Codex backend.
func (s *Server) upstreamFor(header http.Header) *url.URL {
	if token, ok := strings.CutPrefix(header.Get("Authorization"), "Bearer "); ok &&
		strings.HasPrefix(token, "sk-") && header.Get("ChatGPT-Account-ID") == "" {
		return s.apiUpstream
	}
	return s.upstream
}

// strip removes the token segment; it compares in constant time.
func (s *Server) strip(path string) (string, bool) {
	if !strings.HasPrefix(path, "/") {
		return "", false
	}
	segment, rest, _ := strings.Cut(path[1:], "/")
	if subtle.ConstantTimeCompare([]byte(segment), s.token) != 1 {
		return "", false
	}
	return "/" + rest, true
}

// rewriteRequest replaces r.Body with the rewritten request. On any failure the
// original bytes go upstream unchanged: compaction must never break a turn.
func (s *Server) rewriteRequest(r *http.Request) string {
	original := r.Body
	raw, err := io.ReadAll(io.LimitReader(original, bodyLimit+1))
	if err != nil || int64(len(raw)) > bodyLimit {
		// What was read goes first, then the rest as it comes.
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(raw), original), original}
		return " (body too large or unreadable; passed through)"
	}
	original.Close()
	restore := func() {
		r.Body = io.NopCloser(bytes.NewReader(raw))
		r.ContentLength = int64(len(raw))
	}
	zstdBody := strings.EqualFold(r.Header.Get("Content-Encoding"), "zstd")
	body := raw
	if zstdBody {
		decoder, derr := zstdDecoder()
		if derr == nil {
			body, err = decoder.DecodeAll(raw, nil)
		} else {
			err = derr
		}
		if err != nil {
			restore()
			return " (zstd decode failed; passed through)"
		}
	}
	out, stats, err := s.rewriter.Rewrite(r.Context(), identity(r.Header), body)
	if err != nil || stats.Replaced == 0 {
		restore()
		if err != nil {
			return " (unparsed; passed through)"
		}
		return stats.String()
	}
	if zstdBody {
		encoder, err := zstdEncoder()
		if err != nil {
			restore()
			return " (zstd encode failed; passed through)"
		}
		out = encoder.EncodeAll(out, nil)
	}
	r.Body = io.NopCloser(bytes.NewReader(out))
	r.ContentLength = int64(len(out))
	r.Header.Del("Content-Length")
	return stats.String()
}

// bodyLimit is the largest request body the proxy reads to rewrite; a
// variable so tests need not send 64 MiB.
var bodyLimit int64 = maxBodyBytes

// zstdDecoder and zstdEncoder are shared: each is safe for concurrent use,
// and costly to make for every request Codex compresses.
var (
	zstdDecoder = sync.OnceValues(func() (*zstd.Decoder, error) {
		return zstd.NewReader(nil, zstd.WithDecoderMaxMemory(maxDecodedBytes), zstd.WithDecoderConcurrency(0))
	})
	zstdEncoder = sync.OnceValues(func() (*zstd.Encoder, error) { return zstd.NewWriter(nil) })
)

// identity reads whose request it is from Codex's headers: the turn metadata
// it sends with every model request, else its session and thread headers.
func identity(header http.Header) Identity {
	var metadata struct {
		SessionID string `json:"session_id"`
		ThreadID  string `json:"thread_id"`
	}
	if raw := header.Get("X-Codex-Turn-Metadata"); raw != "" && json.Unmarshal([]byte(raw), &metadata) == nil && metadata.SessionID != "" {
		return Identity{SessionID: metadata.SessionID, ThreadID: metadata.ThreadID}
	}
	return Identity{SessionID: header.Get("Session-Id"), ThreadID: header.Get("Thread-Id")}
}

func loopbackHost(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	return h == "127.0.0.1" || h == "localhost" || h == "::1"
}

func scrub(s, token string) string {
	return strings.ReplaceAll(s, token, "<token>")
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

type logWriter func(string)

func (w logWriter) Write(p []byte) (int, error) {
	w(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Serve runs the server until ctx ends, or until no connection has been open
// for idle (never when idle is 0). Under launchd's socket activation an idle
// exit costs nothing: the next connection starts a new process, from the
// binary installed then.
func Serve(ctx context.Context, ln net.Listener, s *Server, idle time.Duration) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var mu sync.Mutex
	open, last := 0, time.Now()
	srv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		// Longer than the idle time Codex keeps a connection for, so the
		// server never closes one Codex is about to reuse.
		IdleTimeout: 5 * time.Minute,
		ErrorLog:    log.New(logWriter(func(line string) { s.logf("%s", scrub(line, string(s.token))) }), "", 0),
		ConnState: func(_ net.Conn, state http.ConnState) {
			mu.Lock()
			defer mu.Unlock()
			switch state {
			case http.StateNew:
				open++
			case http.StateClosed, http.StateHijacked:
				open--
				last = time.Now()
			}
		},
	}
	if idle > 0 {
		go func() {
			tick := time.NewTicker(min(idle, time.Minute))
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					mu.Lock()
					quiet := open == 0 && time.Since(last) >= idle
					mu.Unlock()
					if quiet {
						cancel()
						return
					}
				}
			}
		}()
	}
	go func() {
		<-ctx.Done()
		shutdown, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		_ = srv.Shutdown(shutdown)
	}()
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
