package runtimehost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/kontext-security/kontext/internal/cedarpolicy"
	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/guard/app/server"
	guardhookruntime "github.com/kontext-security/kontext/internal/guard/hookruntime"
	"github.com/kontext-security/kontext/internal/guard/stepsafety"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/localruntime"
	"github.com/kontext-security/kontext/internal/payloadcapture"
	"github.com/kontext-security/kontext/internal/runtimecore"
)

type Options struct {
	AgentName          string
	SessionID          string
	CWD                string
	DBPath             string
	SocketPath         string
	CedarPolicies      cedarpolicy.SnapshotProvider
	CedarEnforcement   server.CedarEnforcementSource
	Mode               guardhookruntime.Mode
	Diagnostic         diagnostic.Logger
	SkipInitialSession bool
	DisableAsyncIngest bool
	// AsyncDecisionRecording answers decision-gating hooks (PreToolUse) as
	// soon as the policy verdict is settled and runs every store write —
	// session upsert, annotation, decision row — in the background,
	// mirroring what AsyncIngest already does for non-blocking hooks.
	// Without it, a cold or contended guard.db routinely outlives the hook
	// client's budget, which reads as a dead daemon, and the call fails open
	// without a policy check. Close drains pending writes before the store
	// closes.
	AsyncDecisionRecording bool
}

type Host struct {
	SessionID  string
	SessionDir string
	SocketPath string
	DBPath     string
	Mode       guardhookruntime.Mode

	server           *server.Server
	closeStore       func() error
	closeStepSafety  func() error
	runtimeService   *localruntime.Service
	sessionOpened    bool
	sessionCloseOnce bool
	drainRecords     func(context.Context) error
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

	stepSafetyConfig, err := stepsafety.ConfigFromEnv(dbPath)
	if err != nil {
		return nil, err
	}
	stepSafety := stepsafety.New(ctx, stepSafetyConfig)
	closeStepSafety := func() error { return stepSafety.Close() }
	if stepSafety != nil {
		healthCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		health := stepSafety.Health(healthCtx)
		cancel()
		if health.Status != "ready" {
			diagnostic.LogAlways(opts.Diagnostic, "step-safety shadow unavailable (%s); calls will fail open\n", health.ErrorCode)
		}
	}
	serverSessionID := sessionID
	if opts.SkipInitialSession {
		serverSessionID = ""
	}
	var recorder *server.DeferredRecorder
	var deferRecord func(job func(context.Context) error) error
	// Merlin must never put inference on the hook response path, including
	// hosts whose caller did not explicitly request asynchronous recording.
	if opts.AsyncDecisionRecording || stepSafety != nil {
		recorder = server.NewDeferredRecorder(opts.Diagnostic)
		deferRecord = recorder.Submit
	}
	localServer, closeStore, err := server.OpenDefaultServerWithOptions(dbPath, server.Options{
		CedarPolicies:    opts.CedarPolicies,
		CedarEnforcement: opts.CedarEnforcement,
		CurrentSessionID: serverSessionID,
		Mode:             string(mode),
		RiskClassifier:   &server.RiskClassifierOptions{},
		StepSafety:       stepSafety,
		DeferRecord:      deferRecord,
	})
	if err != nil {
		_ = closeStepSafety()
		return nil, err
	}
	if err := os.Chmod(dbPath, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = closeStore()
		_ = closeStepSafety()
		return nil, fmt.Errorf("secure runtime database: %w", err)
	}

	sessionDir := filepath.Join(sessionRootDir(), sessionID)
	if err := createSessionDir(sessionDir); err != nil {
		_ = closeStore()
		_ = closeStepSafety()
		return nil, err
	}
	socketPath := strings.TrimSpace(opts.SocketPath)
	if socketPath == "" {
		socketPath = filepath.Join(sessionDir, "kontext.sock")
	}

	host := &Host{
		SessionID:       sessionID,
		SessionDir:      sessionDir,
		SocketPath:      socketPath,
		DBPath:          dbPath,
		Mode:            mode,
		server:          localServer,
		closeStore:      closeStore,
		closeStepSafety: closeStepSafety,
	}
	if recorder != nil {
		host.drainRecords = recorder.Drain
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

func (h *Host) Close(ctx context.Context) error {
	var errs []error
	if h == nil {
		return nil
	}
	if h.runtimeService != nil {
		if err := h.runtimeService.Shutdown(ctx); err != nil {
			// Admitted handlers may still be submitting audit work after their
			// responses. Preserve the recorder/store and allow Close to retry.
			return err
		}
		h.runtimeService = nil
	}
	// Deferred decision writes must land before the store closes underneath
	// them; runtimeService is already down, so no new work can arrive.
	if h.drainRecords != nil {
		if err := h.drainRecords(ctx); err != nil {
			return err
		}
		h.drainRecords = nil
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
	if h.closeStepSafety != nil {
		if err := h.closeStepSafety(); err != nil {
			errs = append(errs, err)
		}
		h.closeStepSafety = nil
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

// sessionRootDir returns the per-user parent of runtime session directories.
// On Unix it stays under /tmp with the uid as suffix, so socket paths stay
// short (sun_path is 104 bytes on macOS) and one user's directory cannot
// block another's. Windows has no /tmp and os.Getuid returns -1 there, so it
// uses os.TempDir, which is already per user (%LOCALAPPDATA%\Temp).
func sessionRootDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.TempDir(), "kontext")
	}
	return filepath.Join("/tmp", fmt.Sprintf("kontext-%d", os.Getuid()))
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
