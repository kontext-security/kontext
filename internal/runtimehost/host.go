package runtimehost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/guard/app/server"
	guardhookruntime "github.com/kontext-security/kontext-cli/internal/guard/hookruntime"
	"github.com/kontext-security/kontext-cli/internal/guard/judge"
	"github.com/kontext-security/kontext-cli/internal/guard/judgeruntime"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/localruntime"
	"github.com/kontext-security/kontext-cli/internal/payloadcapture"
	"github.com/kontext-security/kontext-cli/internal/runtimecore"
)

type Options struct {
	AgentName                 string
	SessionID                 string
	CWD                       string
	DBPath                    string
	SocketPath                string
	DashboardAddr             string
	StartDashboard            bool
	AllowNonLoopbackDashboard bool
	JudgeConfigFromEnv        bool
	JudgeManagedDefault       bool
	JudgeDownloadProgress     judge.DownloadProgressHandler
	ProviderPolicies          []server.ProviderPolicyBinding
	EndpointID                string
	Mode                      guardhookruntime.Mode
	Diagnostic                diagnostic.Logger
	Out                       io.Writer
	SkipInitialSession        bool
	DisableAsyncIngest        bool
}

type Host struct {
	SessionID             string
	SessionDir            string
	SocketPath            string
	DBPath                string
	DashboardURL          string
	DashboardErr          error
	LocalJudgeStatus      string
	LocalJudgeEnabled     bool
	LocalJudgeUnavailable bool
	Mode                  guardhookruntime.Mode

	server           *server.Server
	closeStore       func() error
	closeJudge       func()
	runtimeService   *localruntime.Service
	dashboardServer  *http.Server
	sessionOpened    bool
	sessionCloseOnce bool
}

func Start(ctx context.Context, opts Options) (*Host, error) {
	if strings.TrimSpace(opts.AgentName) == "" {
		return nil, errors.New("runtime host requires agent name")
	}
	mode, err := ResolveMode(string(opts.Mode))
	if err != nil {
		return nil, err
	}
	sessionID := strings.TrimSpace(opts.SessionID)
	if sessionID == "" {
		sessionID = NewSessionID()
	}
	if err := validateSessionID(sessionID); err != nil {
		return nil, err
	}

	dbPath := strings.TrimSpace(opts.DBPath)
	usingDefaultDBPath := false
	if dbPath == "" {
		dbPath = DefaultDBPath()
		usingDefaultDBPath = true
	}
	if err := ensureRuntimeDataDir(filepath.Dir(dbPath), usingDefaultDBPath); err != nil {
		return nil, fmt.Errorf("create runtime data dir: %w", err)
	}

	closeJudge := func() {}
	var localJudge judge.Judge
	var judgeStatus string
	if opts.JudgeConfigFromEnv {
		judgeConfig, err := judgeruntime.ConfigFromEnv(dbPath, opts.JudgeManagedDefault)
		if err != nil {
			return nil, err
		}
		judgeConfig.DownloadProgress = opts.JudgeDownloadProgress
		localJudge, closeJudge, judgeStatus, err = judgeruntime.Configure(ctx, judgeConfig)
		if err != nil {
			return nil, err
		}
	}
	serverSessionID := sessionID
	if opts.SkipInitialSession {
		serverSessionID = ""
	}
	localServer, closeStore, err := server.OpenDefaultServerWithOptions(dbPath, server.Options{
		Judge:            localJudge,
		ProviderPolicies: opts.ProviderPolicies,
		EndpointID:       opts.EndpointID,
		CurrentSessionID: serverSessionID,
		Mode:             string(mode),
		RiskClassifier:   &server.RiskClassifierOptions{},
	})
	if err != nil {
		closeJudge()
		return nil, err
	}
	if err := os.Chmod(dbPath, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = closeStore()
		closeJudge()
		return nil, fmt.Errorf("secure runtime database: %w", err)
	}

	sessionDir := filepath.Join("/tmp", "kontext", sessionID)
	if err := createSessionDir(sessionDir); err != nil {
		_ = closeStore()
		closeJudge()
		return nil, err
	}
	socketPath := strings.TrimSpace(opts.SocketPath)
	if socketPath == "" {
		socketPath = filepath.Join(sessionDir, "kontext.sock")
	}

	host := &Host{
		SessionID:             sessionID,
		SessionDir:            sessionDir,
		SocketPath:            socketPath,
		DBPath:                dbPath,
		LocalJudgeStatus:      judgeStatus,
		LocalJudgeEnabled:     localJudge != nil,
		LocalJudgeUnavailable: judge.IsUnavailable(localJudge),
		Mode:                  mode,
		server:                localServer,
		closeStore:            closeStore,
		closeJudge:            closeJudge,
	}

	serviceSessionID := sessionID
	if opts.SkipInitialSession {
		serviceSessionID = ""
	}
	runtimeService, err := localruntime.NewService(localruntime.Options{
		SocketPath:  socketPath,
		Core:        localServer.RuntimeCore(),
		SessionID:   serviceSessionID,
		AgentName:   opts.AgentName,
		AsyncIngest: !opts.DisableAsyncIngest,
		Transform:   clientResultTransform(mode),
		Diagnostic:  opts.Diagnostic,
	})
	if err != nil {
		_ = host.Close(context.Background())
		return nil, fmt.Errorf("local runtime: %w", err)
	}
	if err := runtimeService.Start(ctx); err != nil {
		_ = host.Close(context.Background())
		return nil, fmt.Errorf("local runtime start: %w", err)
	}
	host.runtimeService = runtimeService

	cwd := opts.CWD
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	if !opts.SkipInitialSession {
		if _, err := localServer.RuntimeCore().OpenSession(ctx, runtimecore.Session{
			ID:         sessionID,
			Agent:      opts.AgentName,
			CWD:        cwd,
			Source:     runtimecore.SessionSourceWrapperOwned,
			ExternalID: sessionID,
		}); err != nil {
			_ = host.Close(context.Background())
			return nil, fmt.Errorf("open runtime session: %w", err)
		}
		host.sessionOpened = true
	}

	if opts.StartDashboard {
		addr, err := DashboardAddr(opts.DashboardAddr, opts.AllowNonLoopbackDashboard)
		if err != nil {
			_ = host.Close(context.Background())
			return nil, err
		}
		dashboardServer, dashboardURL, err := startDashboard(addr, localServer.Handler())
		if err != nil {
			host.DashboardErr = err
			if opts.Out != nil {
				fmt.Fprintf(opts.Out, "Local dashboard unavailable: %v\n", err)
			}
		} else {
			host.dashboardServer = dashboardServer
			host.DashboardURL = dashboardURL
		}
	}

	return host, nil
}

func clientResultTransform(mode guardhookruntime.Mode) func(hook.Event, hook.Result) hook.Result {
	if mode != guardhookruntime.ModeObserve {
		return nil
	}
	return func(event hook.Event, result hook.Result) hook.Result {
		result.Mode = string(mode)
		if result.Decision == "" {
			result.Decision = hook.DecisionAllow
		}
		if event.HookName.CanBlock() {
			decision := result.Decision
			if result.Reason == "" {
				result.Reason = "no reason provided"
			}
			result.Reason = "Kontext observe mode: would " + string(decision) + "; " + result.Reason
		}
		result.Decision = hook.DecisionAllow
		return result
	}
}

// SetPayloadCaptureMode forwards the org's payload-capture directive to the
// guard server's store. Safe on a nil host (no-op).
func (h *Host) SetPayloadCaptureMode(mode payloadcapture.Mode) {
	if h == nil || h.server == nil {
		return
	}
	h.server.SetPayloadCaptureMode(mode)
}

func (h *Host) Close(ctx context.Context) error {
	var errs []error
	if h == nil {
		return nil
	}
	if h.dashboardServer != nil {
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := h.dashboardServer.Shutdown(shutdownCtx)
		cancel()
		if err != nil {
			errs = append(errs, err)
		}
		h.dashboardServer = nil
	}
	if h.runtimeService != nil {
		if err := h.runtimeService.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
		h.runtimeService = nil
	}
	if h.sessionOpened && !h.sessionCloseOnce && h.server != nil {
		if err := h.server.RuntimeCore().CloseSession(context.Background(), h.SessionID); err != nil {
			errs = append(errs, err)
		}
		h.sessionCloseOnce = true
	}
	// Drain queued classifier records before the store and llama-server go
	// away, or in-flight verdicts are lost.
	if h.server != nil {
		h.server.CloseRiskClassifier()
	}
	if h.closeStore != nil {
		if err := h.closeStore(); err != nil {
			errs = append(errs, err)
		}
		h.closeStore = nil
	}
	if h.closeJudge != nil {
		h.closeJudge()
		h.closeJudge = nil
	}
	if h.SessionDir != "" {
		if err := os.RemoveAll(h.SessionDir); err != nil {
			errs = append(errs, err)
		}
		h.SessionDir = ""
	}
	return errors.Join(errs...)
}

func ResolveMode(value string) (guardhookruntime.Mode, error) {
	return guardhookruntime.ParseMode(value)
}

func NewSessionID() string {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err == nil {
		return hex.EncodeToString(bytes[:])
	}
	return strconv.FormatInt(time.Now().UnixNano(), 16)
}

func DefaultDBPath() string {
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "kontext", "guard.db")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".kontext", "guard.db")
	}
	return "kontext-guard.db"
}

func DashboardAddr(value string, allowNonLoopback bool) (string, error) {
	addr := strings.TrimSpace(value)
	if addr == "" {
		addr = server.DefaultAddr
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("dashboard address %q must be host:port: %w", addr, err)
	}
	if allowNonLoopback || isLoopbackHost(host) {
		return addr, nil
	}
	return "", fmt.Errorf("dashboard address %q is not loopback; use 127.0.0.1 or localhost", addr)
}

func startDashboard(addr string, handler http.Handler) (*http.Server, string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, "", fmt.Errorf("local dashboard listen on %s: %w", addr, err)
	}
	httpServer := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := httpServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "Local dashboard stopped: %v\n", err)
		}
	}()
	return httpServer, "http://" + ln.Addr().String(), nil
}

func createSessionDir(sessionDir string) error {
	if err := os.MkdirAll(filepath.Dir(sessionDir), 0o700); err != nil {
		return fmt.Errorf("create session parent dir: %w", err)
	}
	if err := os.Mkdir(sessionDir, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("runtime session directory already exists: %s", sessionDir)
		}
		return fmt.Errorf("create session dir: %w", err)
	}
	return nil
}

func ensureRuntimeDataDir(path string, private bool) error {
	if path == "." || path == "" {
		return nil
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	if !private {
		return nil
	}
	return os.Chmod(path, 0o700)
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func validateSessionID(sessionID string) error {
	if sessionID == "" {
		return errors.New("runtime session ID is required")
	}
	if sessionID != filepath.Base(sessionID) || strings.ContainsAny(sessionID, `/\`) {
		return fmt.Errorf("runtime session ID %q is not a safe path segment", sessionID)
	}
	if sessionID == "." || sessionID == ".." {
		return fmt.Errorf("runtime session ID %q is not a safe path segment", sessionID)
	}
	for i := 0; i < len(sessionID); i++ {
		c := sessionID[i]
		if (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' {
			continue
		}
		return fmt.Errorf("runtime session ID %q is not a safe path segment", sessionID)
	}
	return nil
}
