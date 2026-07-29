package runtimehost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kontext-security/kontext-cli/internal/cedarpolicy"
	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/guard/app/server"
	guardhookruntime "github.com/kontext-security/kontext-cli/internal/guard/hookruntime"
	"github.com/kontext-security/kontext-cli/internal/guard/judge"
	"github.com/kontext-security/kontext-cli/internal/guard/judgeruntime"
	"github.com/kontext-security/kontext-cli/internal/guard/riskclassifier"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/localruntime"
	"github.com/kontext-security/kontext-cli/internal/payloadcapture"
	"github.com/kontext-security/kontext-cli/internal/runtimecore"
)

type Options struct {
	AgentName             string
	SessionID             string
	CWD                   string
	DBPath                string
	SocketPath            string
	JudgeConfigFromEnv    bool
	JudgeManagedDefault   bool
	JudgeDownloadProgress judge.DownloadProgressHandler
	CedarPolicies         cedarpolicy.SnapshotProvider
	CedarEnforcement      server.CedarEnforcementSource
	Mode                  guardhookruntime.Mode
	Diagnostic            diagnostic.Logger
	SkipInitialSession    bool
	DisableAsyncIngest    bool
}

type Host struct {
	SessionID             string
	SessionDir            string
	SocketPath            string
	DBPath                string
	LocalJudgeStatus      string
	LocalJudgeEnabled     bool
	LocalJudgeUnavailable bool
	Mode                  guardhookruntime.Mode

	server           *server.Server
	closeStore       func() error
	closeJudge       func()
	runtimeService   *localruntime.Service
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
	if mode != guardhookruntime.ModeObserve && (opts.CedarPolicies == nil || opts.CedarEnforcement == server.CedarEnforcementOff) {
		return nil, errors.New("enforce and remote modes require a managed Cedar policy source")
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
	var judgeRuntime judgeruntime.Runtime
	if opts.JudgeConfigFromEnv {
		judgeConfig, err := judgeruntime.ConfigFromEnv(dbPath, opts.JudgeManagedDefault)
		if err != nil {
			return nil, err
		}
		judgeConfig.DownloadProgress = opts.JudgeDownloadProgress
		judgeRuntime, err = judgeruntime.ConfigureRuntime(ctx, judgeConfig)
		if err != nil {
			return nil, err
		}
		localJudge = judgeRuntime.Judge
		judgeStatus = judgeRuntime.Status
		if judgeRuntime.Close != nil {
			closeJudge = judgeRuntime.Close
		}
	}
	classifierOpts, err := riskClassifierOptions(judgeRuntime)
	if err != nil {
		closeJudge()
		return nil, err
	}
	serverSessionID := sessionID
	if opts.SkipInitialSession {
		serverSessionID = ""
	}
	localServer, closeStore, err := server.OpenDefaultServerWithOptions(dbPath, server.Options{
		Judge:            localJudge,
		CedarPolicies:    opts.CedarPolicies,
		CedarEnforcement: opts.CedarEnforcement,
		CurrentSessionID: serverSessionID,
		Mode:             string(mode),
		RiskClassifier:   classifierOpts,
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

	return host, nil
}

// riskClassifierOptions resolves the classifier's configuration. The SVM always
// runs; KONTEXT_RISK_CLASSIFIER_MODE decides whether the guardrail LLM runs off
// the hook path (default), on the decision path, or not at all. The LLM reuses
// whatever local llama-server the judge configuration brought up.
func riskClassifierOptions(judgeRuntime judgeruntime.Runtime) (*server.RiskClassifierOptions, error) {
	mode, err := riskclassifier.ParseMode(os.Getenv("KONTEXT_RISK_CLASSIFIER_MODE"))
	if err != nil {
		return nil, err
	}
	gate := riskclassifier.NewLLMGate()
	// An explicitly configured local mode is an override: a developer debugging
	// their own machine must not be flipped by an org refresh.
	if raw := strings.TrimSpace(os.Getenv("KONTEXT_RISK_CLASSIFIER_MODE")); raw != "" {
		gate.PinLocal(mode.UsesLLM())
	}
	return &server.RiskClassifierOptions{
		Mode:             mode,
		GuardrailBaseURL: judgeRuntime.BaseURL,
		GuardrailModel:   judgeRuntime.Model,
		Gate:             gate,
	}, nil
}

func clientResultTransform(mode guardhookruntime.Mode) func(hook.Event, hook.Result) hook.Result {
	switch mode {
	case guardhookruntime.ModeEnforce:
		// The whole pipeline is authoritative under a static enforce posture;
		// stamp results so hook edges recognize them as such.
		return func(event hook.Event, result hook.Result) hook.Result {
			result.Mode = string(guardhookruntime.ModeEnforce)
			return result
		}
	case guardhookruntime.ModeRemote:
		// The single remote posture rule lives in hookruntime; only decisions
		// the runtime already marked enforce (a Cedar decision applied under
		// an enforce rollout) are authoritative.
		return guardhookruntime.ApplyRemote
	default:
		return guardhookruntime.ObserveResult
	}
}

func (h *Host) SetPayloadCaptureConfiguration(config payloadcapture.RuntimeConfiguration) {
	if h == nil || h.server == nil {
		return
	}
	h.server.SetPayloadCaptureConfiguration(config)
}

// SetGuardrailLLMEnabled forwards the org's guardrail-LLM kill switch to the
// classifier. Safe on a nil host (no-op).
func (h *Host) SetGuardrailLLMEnabled(enabled bool) {
	if h == nil || h.server == nil {
		return
	}
	h.server.SetGuardrailLLMEnabled(enabled)
}

func (h *Host) Close(ctx context.Context) error {
	var errs []error
	if h == nil {
		return nil
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
