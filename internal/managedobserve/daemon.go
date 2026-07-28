package managedobserve

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kontext-security/kontext-cli/internal/cedarpolicy"
	"github.com/kontext-security/kontext-cli/internal/claudemanaged"
	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/endpointconfig"
	"github.com/kontext-security/kontext-cli/internal/guard/app/server"
	guardhookruntime "github.com/kontext-security/kontext-cli/internal/guard/hookruntime"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext-cli/internal/installation"
	"github.com/kontext-security/kontext-cli/internal/managedconfig"
	"github.com/kontext-security/kontext-cli/internal/managedstream"
	"github.com/kontext-security/kontext-cli/internal/payloadcapture"
	"github.com/kontext-security/kontext-cli/internal/runtimehost"
)

type DaemonOptions struct {
	SocketPath              string
	DBPath                  string
	IdleTimeout             time.Duration
	StreamStatePath         string
	StreamInterval          time.Duration
	StreamHTTPClient        *http.Client
	CedarPolicyCachePath    string
	EndpointConfigCachePath string
	// PolicyRefreshInterval and PolicyHTTPClient apply to the Cedar policy
	// refresh loop (test knobs; zero values use defaults).
	PolicyRefreshInterval         time.Duration
	PolicyHTTPClient              *http.Client
	EndpointConfigRefreshInterval time.Duration
	EndpointConfigHTTPClient      *http.Client
	Diagnostic                    diagnostic.Logger
	// BinaryVersion is the CLI binary version, for startup logging and future
	// status reporting.
	BinaryVersion string
	// FallbackDeploymentVersion is reported to the ledger when no MDM
	// deployment-version marker exists (self-serve brew installs).
	FallbackDeploymentVersion string
	HomebrewUpdater           func(context.Context, managedconfig.LoadedConfig, diagnostic.Logger) <-chan struct{}
	BinaryWatchdog            func(context.Context, diagnostic.Logger) <-chan struct{}
}

var (
	managedSettingsDropInPath = claudemanaged.ManagedSettingsDropInPath
	managedSettingsFilePath   = claudemanaged.DefaultManagedSettingsPath()
)

func RunDaemon(ctx context.Context, opts DaemonOptions) error {
	binaryVersion := opts.BinaryVersion
	if binaryVersion == "" {
		binaryVersion = "dev"
	}
	logAlways(opts.Diagnostic, "managed-observe daemon %s (pid %d) started\n", binaryVersion, os.Getpid())

	loadedConfig, err := managedconfig.Load()
	if err != nil {
		if errors.Is(err, managedconfig.ErrNotManaged) {
			return err
		}
		return fmt.Errorf("load managed config: %w", err)
	}
	if expected := strings.TrimSpace(os.Getenv(EnvExpectedConfigScope)); expected != "" &&
		expected != string(loadedConfig.Scope) {
		// An MDM config appeared after this agent was installed (system scope
		// outranks user scope). Park instead of serving the wrong config —
		// exiting would just make launchd KeepAlive restart-loop us.
		fmt.Fprintf(os.Stderr,
			"managed config scope is %q but this agent was installed for %q — parking; run `kontext setup --uninstall` to remove this agent\n",
			loadedConfig.Scope, expected)
		<-ctx.Done()
		return nil
	}
	if err := requireManagedHooksForLegacyCowork(loadedConfig.Config); err != nil {
		return err
	}
	loadedConfig = migrateSelfServeModeToRemote(loadedConfig, opts.Diagnostic)
	installationState, err := installation.EnsureFile(installationPathForScope(loadedConfig.Scope))
	if err != nil {
		return fmt.Errorf("ensure installation identity: %w", err)
	}

	dbPath := opts.DBPath
	if dbPath == "" {
		dbPath = DefaultDBPath()
	}

	_, err = managedconfig.ResolveInstallToken(ctx, loadedConfig.Config.Credentials.InstallTokenRef)
	if err != nil {
		// Leave a breadcrumb: under launchd this exit is otherwise invisible
		// (doctor would only see "daemon: not running" with no cause). A
		// locked login keychain at boot is the typical trigger.
		if breadcrumbErr := WriteStartupError(dbPath, err.Error()); breadcrumbErr != nil {
			opts.Diagnostic.Printf("write startup-error breadcrumb: %v\n", breadcrumbErr)
		}
		return fmt.Errorf("resolve install token: %w", err)
	}
	// Token resolved — clear any stale startup breadcrumb from a prior boot.
	if previous := LoadAuthError(dbPath); previous != nil && previous.Kind == "startup" {
		if err := ClearAuthError(dbPath); err != nil {
			opts.Diagnostic.Printf("clear startup-error breadcrumb: %v\n", err)
		}
	}

	socketPath := opts.SocketPath
	if socketPath == "" {
		socketPath = DefaultSocketPath()
	}
	if err := EnsureSocketDir(socketPath); err != nil {
		return fmt.Errorf("prepare managed observe socket dir: %w", err)
	}
	if err := cleanupStaleSessions(ctx, dbPath, idleTimeoutOrDefault(opts.IdleTimeout)); err != nil {
		opts.Diagnostic.Printf("managed observe cleanup: %v\n", err)
	}

	// The deployment-level mode from managed.json drives every hook edge:
	// observe records would-decisions, enforce returns real denies, remote
	// defers to the fetched policy deployment's rollout mode so the posture
	// can be flipped from the dashboard without touching the install.
	mode, err := guardhookruntime.ParseMode(loadedConfig.Config.Mode)
	if err != nil {
		return fmt.Errorf("parse managed mode: %w", err)
	}
	cedarEnforcement := server.CedarEnforcementOff
	switch mode {
	case guardhookruntime.ModeEnforce:
		cedarEnforcement = server.CedarEnforcementStatic
	case guardhookruntime.ModeRemote:
		cedarEnforcement = server.CedarEnforcementRemote
	}

	cedarCachePath := opts.CedarPolicyCachePath
	if cedarCachePath == "" {
		cedarCachePath = cedarpolicy.DefaultCachePathForDB(dbPath)
	}
	cedarCache := cedarpolicy.NewCache(cedarCachePath, 0)
	if err := cedarCache.Load(); err != nil {
		cedarCache.MarkInvalid(err)
		opts.Diagnostic.Printf("cedar policy cache load: %v\n", err)
	}
	cedarClient, err := cedarpolicy.NewClient(loadedConfig.Config.CloudURL, opts.PolicyHTTPClient)
	if err != nil {
		return fmt.Errorf("configure cedar policy client: %w", err)
	}
	endpointConfigCachePath := opts.EndpointConfigCachePath
	if endpointConfigCachePath == "" {
		endpointConfigCachePath = endpointconfig.DefaultCachePathForDB(dbPath)
	}
	endpointConfigCache := endpointconfig.NewCache(endpointConfigCachePath)
	if err := endpointConfigCache.Load(); err != nil {
		endpointConfigCache.MarkInvalid(err)
		opts.Diagnostic.Printf("endpoint configuration cache load: %v\n", err)
	}
	endpointConfigClient, err := endpointconfig.NewClient(loadedConfig.Config.CloudURL, opts.EndpointConfigHTTPClient)
	if err != nil {
		return fmt.Errorf("configure endpoint configuration client: %w", err)
	}

	host, err := runtimehost.Start(ctx, runtimehost.Options{
		AgentName:          managedconfig.Agent,
		DBPath:             dbPath,
		SocketPath:         socketPath,
		CedarPolicies:      cedarCache,
		CedarEnforcement:   cedarEnforcement,
		Mode:               mode,
		Diagnostic:         opts.Diagnostic,
		SkipInitialSession: true,
		// Async ingest: non-blocking hooks (PostToolUse, session lifecycle)
		// are acked immediately and written in the background. Synchronous
		// writes queue on the store's single SQLite connection, and under a
		// concurrent subagent burst that queueing blew the hook connection
		// deadline — Claude Code timed the hook out and the event was lost
		// (ENG-474). Decision-gating hooks (PreToolUse, UserPromptSubmit)
		// stay synchronous, and Shutdown drains pending writes.
	})
	if err != nil {
		return err
	}
	defer host.Close(context.Background())
	if err := WriteDaemonStatus(dbPath, binaryVersion); err != nil {
		opts.Diagnostic.Printf("write daemon-status breadcrumb: %v\n", err)
	}

	// Persisted endpoint configuration is conditional state only. Capture stays
	// at the privacy-safe default until this process receives a confirming 200
	// or matching 304 from the independent configuration endpoint.
	host.SetPayloadCaptureConfiguration(captureConfiguration(endpointConfigCache.Current()))

	policyCtx, stopPolicyRefresh := context.WithCancel(ctx)
	defer stopPolicyRefresh()
	cedarRefresher := cedarpolicy.Refresher{
		Client: cedarClient,
		Cache:  cedarCache,
		TokenSource: func(refreshCtx context.Context) (string, error) {
			loaded, err := managedconfig.Load()
			if err != nil {
				return "", err
			}
			return managedconfig.ResolveInstallToken(refreshCtx, loaded.Config.Credentials.InstallTokenRef)
		},
		InstallationID: installationState.InstallationID,
		Interval:       opts.PolicyRefreshInterval,
	}
	go cedarRefresher.Run(policyCtx)
	endpointConfigRefresher := endpointconfig.Refresher{
		Client: endpointConfigClient,
		Cache:  endpointConfigCache,
		TokenSource: func(refreshCtx context.Context) (string, error) {
			loaded, err := managedconfig.Load()
			if err != nil {
				return "", err
			}
			return managedconfig.ResolveInstallToken(refreshCtx, loaded.Config.Credentials.InstallTokenRef)
		},
		InstallationID: installationState.InstallationID,
		Interval:       opts.EndpointConfigRefreshInterval,
		OnChanged: func(snapshot endpointconfig.Snapshot) {
			host.SetPayloadCaptureConfiguration(captureConfiguration(snapshot))
		},
	}
	go endpointConfigRefresher.Run(policyCtx)

	streamCtx, stopStream := context.WithCancel(ctx)
	defer stopStream()
	streamErr := make(chan error, 1)
	go func() {
		streamErr <- runManagedStream(streamCtx, opts, dbPath, installationState.InstallationID)
	}()

	startUpdater := opts.HomebrewUpdater
	if startUpdater == nil {
		startUpdater = startHomebrewUpdater
	}
	upgraded := startUpdater(ctx, loadedConfig, opts.Diagnostic)

	startWatchdog := opts.BinaryWatchdog
	if startWatchdog == nil {
		startWatchdog = startBinaryWatchdog
	}
	binaryReplaced := startWatchdog(ctx, opts.Diagnostic)

	idleTimeout := opts.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = DefaultIdleTimeout()
	}
	cleanup := time.NewTicker(cleanupInterval(idleTimeout))
	defer cleanup.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case _, ok := <-upgraded:
			if ok {
				return nil
			}
			upgraded = nil
		case _, ok := <-binaryReplaced:
			if ok {
				return nil
			}
			binaryReplaced = nil
		case err := <-streamErr:
			if err != nil {
				logAlways(opts.Diagnostic, "managed stream exited: %v\n", err)
				return fmt.Errorf("managed stream failed: %w", err)
			}
			return nil
		case <-cleanup.C:
			if err := cleanupStaleSessions(ctx, dbPath, idleTimeout); err != nil {
				opts.Diagnostic.Printf("managed observe cleanup: %v\n", err)
			}
		}
	}
}

func captureConfiguration(snapshot endpointconfig.Snapshot) payloadcapture.RuntimeConfiguration {
	return payloadcapture.SafeRuntimeConfiguration(payloadcapture.RuntimeConfiguration{
		ConfiguredMode: snapshot.Configured.PayloadCaptureMode,
		EffectiveMode:  snapshot.Config.PayloadCaptureMode,
		ConfigIdentity: snapshot.ConfigIdentity,
		Confirmed:      snapshot.Confirmed,
		FallbackReason: snapshot.FallbackReason,
	})
}

func requireManagedHooksForLegacyCowork(cfg managedconfig.Config) error {
	if !cfg.LegacyCoworkEnabled {
		return nil
	}
	foundHooks := false
	for _, path := range []string{managedSettingsDropInPath, managedSettingsFilePath} {
		state, err := managedObserveHooksState(path)
		if err != nil {
			return fmt.Errorf("check Claude Code managed hooks for cowork_enabled: %w", err)
		}
		if state.disabled {
			return fmt.Errorf("cowork_enabled is set but Claude Code hooks are disabled at %s; remove disableAllHooks before starting managed observe", path)
		}
		if state.hasHooks {
			foundHooks = true
		}
	}
	if foundHooks {
		return nil
	}
	return fmt.Errorf("cowork_enabled is set but Claude Code managed hooks are missing at %s or %s; run `kontext setup` or install the managed-settings drop-in before starting managed observe", managedSettingsDropInPath, managedSettingsFilePath)
}

type managedObserveHooksStatus struct {
	disabled bool
	hasHooks bool
}

func managedObserveHooksState(path string) (managedObserveHooksStatus, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return managedObserveHooksStatus{}, nil
	}
	if err != nil {
		return managedObserveHooksStatus{}, err
	}
	return managedObserveHooksStatus{
		disabled: claudemanaged.DisablesAllHooks(data),
		hasHooks: claudemanaged.HasManagedObserveHooks(data),
	}, nil
}

// deploymentVersionWithFallback resolves the version reported with each
// ledger batch: the MDM package marker wins; brew installs have none and
// report the CLI's own version instead. Evaluated per flush so a package
// update under a running daemon is picked up.
func deploymentVersionWithFallback(fallback string) func() string {
	return func() string {
		if v := managedconfig.DeploymentVersion(); v != "" {
			return v
		}
		return fallback
	}
}

// installationPathForScope ties identity scope to config scope: a system
// (MDM) config never reads a user identity and vice versa. The env override
// (KONTEXT_INSTALLATION_STATE, honored by PathFromEnv) always wins, and the
// enterprise default is byte-identical to the pre-self-serve behavior.
func installationPathForScope(scope managedconfig.Scope) string {
	if strings.TrimSpace(os.Getenv(installation.EnvPath)) != "" {
		return installation.PathFromEnv()
	}
	if scope == managedconfig.ScopeUser {
		if path := installation.UserPath(); path != "" {
			return path
		}
	}
	return installation.PathFromEnv()
}

func loadManagedConfig(ctx context.Context) (managedconfig.LoadedConfig, string, error) {
	loadedConfig, err := managedconfig.Load()
	if err != nil {
		if errors.Is(err, managedconfig.ErrNotManaged) {
			return managedconfig.LoadedConfig{}, "", err
		}
		return managedconfig.LoadedConfig{}, "", fmt.Errorf("load managed config: %w", err)
	}
	installToken, err := managedconfig.ResolveInstallToken(ctx, loadedConfig.Config.Credentials.InstallTokenRef)
	if err != nil {
		return managedconfig.LoadedConfig{}, "", fmt.Errorf("resolve install token: %w", err)
	}
	return loadedConfig, installToken, nil
}

func runManagedStream(ctx context.Context, opts DaemonOptions, dbPath, installationID string) error {
	interval := opts.StreamInterval
	if interval == 0 {
		interval = managedstream.DefaultIntervalFromEnv()
	}
	var consecutiveAuthFailures, consecutiveFlushFailures int
	flush := func() {
		err := flushManagedStream(ctx, opts, dbPath, installationID)
		if err == nil {
			consecutiveAuthFailures = 0
			consecutiveFlushFailures = 0
			return
		}
		opts.Diagnostic.Printf("managed stream flush: %v\n", err)
		status, ok := managedstream.AuthFailureStatus(err)
		if ok {
			consecutiveFlushFailures = 0
			consecutiveAuthFailures++
			if managedstream.ShouldReportAuthFailure(consecutiveAuthFailures) {
				writeStreamAuthFailure(opts, dbPath, status)
			}
			return
		}
		consecutiveAuthFailures = 0
		consecutiveFlushFailures++
		if managedstream.ShouldReportFailure(consecutiveFlushFailures) {
			logAlways(opts.Diagnostic, "managed stream flush failing (%d consecutive): %v\n", consecutiveFlushFailures, err)
		}
	}
	flush()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			flush()
		}
	}
}

func flushManagedStream(ctx context.Context, opts DaemonOptions, dbPath, installationID string) error {
	loadedConfig, installToken, err := loadManagedConfig(ctx)
	if err != nil {
		return fmt.Errorf("managed stream config reload: %w", err)
	}
	if err := managedstream.Flush(ctx, managedstream.Options{
		DBPath:            dbPath,
		StatePath:         opts.StreamStatePath,
		CloudURL:          loadedConfig.Config.CloudURL,
		InstallationID:    installationID,
		InstallToken:      installToken,
		DeviceLabel:       loadedConfig.Config.Device.Label,
		UserEmail:         loadedConfig.Config.Device.UserEmail,
		DeploymentVersion: deploymentVersionWithFallback(opts.FallbackDeploymentVersion),
		HTTPClient:        opts.StreamHTTPClient,
		Diagnostic:        opts.Diagnostic,
		OnFlushSuccess: func() {
			if err := ClearAuthError(dbPath); err != nil {
				opts.Diagnostic.Printf("clear auth-error breadcrumb: %v\n", err)
			}
		},
	}); err != nil {
		return err
	}
	return nil
}

func writeStreamAuthFailure(opts DaemonOptions, dbPath string, status int) {
	// Unconditional stderr (Diagnostic is env-gated and would be silent under
	// launchd) plus a breadcrumb for `kontext doctor`.
	target := "hosted API"
	if loadedConfig, err := managedconfig.Load(); err == nil && strings.TrimSpace(loadedConfig.Config.CloudURL) != "" {
		target = loadedConfig.Config.CloudURL
	}
	fmt.Fprintf(os.Stderr,
		"Kontext install token rejected by %s (HTTP %d). It may have been revoked — run `kontext setup` with a new token from the dashboard.\n",
		target, status)
	if err := WriteAuthError(dbPath, status); err != nil {
		opts.Diagnostic.Printf("write auth-error breadcrumb: %v\n", err)
	}
}

func idleTimeoutOrDefault(idleTimeout time.Duration) time.Duration {
	if idleTimeout == 0 {
		return DefaultIdleTimeout()
	}
	return idleTimeout
}

func cleanupStaleSessions(ctx context.Context, dbPath string, idleTimeout time.Duration) error {
	store, err := sqlite.OpenStore(dbPath)
	if err != nil {
		return err
	}
	defer store.Close()
	return store.CloseStaleDaemonObservedSessions(ctx, time.Now().UTC().Add(-idleTimeout))
}

func cleanupInterval(idleTimeout time.Duration) time.Duration {
	interval := idleTimeout / 2
	if interval <= 0 {
		return time.Nanosecond
	}
	return interval
}

// migrateSelfServeModeToRemote rewrites a self-serve (user-scope) managed
// config still carrying the pre-remote "observe" default to "remote", so the
// policy deployment's rollout mode controls the posture without a reinstall.
// Only user-scope configs are touched: those were written by `kontext setup`
// with the era's default, not by an admin choosing a static pin. MDM
// (system-scope) and env-override configs are an explicit posture choice and
// are never rewritten. Migration failure is not fatal — the daemon runs with
// the config it loaded and retries on next start.
func migrateSelfServeModeToRemote(loaded managedconfig.LoadedConfig, log diagnostic.Logger) managedconfig.LoadedConfig {
	if loaded.Scope != managedconfig.ScopeUser || loaded.Config.Mode != managedconfig.Mode {
		return loaded
	}
	if err := managedconfig.RewriteMode(loaded, managedconfig.ModeRemote); err != nil {
		log.Printf("migrate self-serve managed mode to remote: %v\n", err)
		return loaded
	}
	logAlways(log, "migrated self-serve managed mode %q -> %q\n", managedconfig.Mode, managedconfig.ModeRemote)
	reloaded, err := managedconfig.LoadFile(loaded.Path)
	if err != nil {
		log.Printf("reload managed config after mode migration: %v\n", err)
		return loaded
	}
	reloaded.Scope = loaded.Scope
	return reloaded
}
