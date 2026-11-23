// Package coworksensor runs the bounded, internal Cowork EDR prototype. It
// reuses the CLI's hook runtime and ledger uploader without the device daemon's
// enforcement, compaction, discovery, transcript or model workers.
package coworksensor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kontext-security/kontext/internal/guard/app/server"
	guardhookruntime "github.com/kontext-security/kontext/internal/guard/hookruntime"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/localruntime"
	"github.com/kontext-security/kontext/internal/managedstream"
	"github.com/kontext-security/kontext/internal/runtimehost"
)

type Config struct {
	CloudURL       string `json:"cloud_url"`
	TokenFile      string `json:"token_file"`
	InstallationID string `json:"installation_id"`
	UserEmail      string `json:"user_email,omitempty"`
	StateDir       string `json:"state_dir"`
	RuntimeDir     string `json:"runtime_dir"`
	// AllowHTTPLoopback is exclusively for an isolated local API test.
	AllowHTTPLoopback bool          `json:"allow_http_loopback,omitempty"`
	HTTPClient        *http.Client  `json:"-"`
	Interval          time.Duration `json:"-"`
}

func privateFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("%s must be a regular file accessible only to its owner", path)
	}
	return os.ReadFile(path)
}

func Load(path string) (Config, error) {
	data, err := privateFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read sensor config: %w", err)
	}
	var cfg Config
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode sensor config: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return Config{}, errors.New("sensor config must contain one JSON object")
	}
	return cfg, cfg.validate()
}

func (cfg Config) validate() error {
	u, err := url.Parse(cfg.CloudURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("sensor cloud_url must be an HTTPS API origin")
	}
	loopback := u.Hostname() == "localhost"
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		loopback = ip.IsLoopback()
	}
	if u.Scheme != "https" && !(cfg.AllowHTTPLoopback && u.Scheme == "http" && loopback) {
		return errors.New("sensor cloud_url requires HTTPS (HTTP loopback is only for a local API test)")
	}
	encoded := strings.TrimPrefix(cfg.InstallationID, "ins_")
	decoded, decodeErr := base64.RawURLEncoding.DecodeString(encoded)
	if !strings.HasPrefix(cfg.InstallationID, "ins_") || len(encoded) != 32 || decodeErr != nil || len(decoded) != 24 {
		return errors.New("sensor installation_id must be a generated installation id")
	}
	for _, path := range []string{cfg.TokenFile, cfg.StateDir, cfg.RuntimeDir} {
		if !filepath.IsAbs(path) {
			return errors.New("sensor token, state and runtime paths must be absolute")
		}
	}
	return nil
}

// FilterRequest exposes only Cowork lifecycle/tool hooks. Never trust a session
// user to give the privileged service a transcript or other file to read.
func FilterRequest(req *localruntime.EvaluateRequest) error {
	if req.Type == localruntime.CapabilitiesRequestType {
		return nil
	}
	if req.Type != "evaluate" {
		return errors.New("only hook evaluation is supported")
	}
	if req.SessionID == "" || len(req.SessionID) > 256 {
		return errors.New("a bounded session id is required")
	}
	switch hook.HookName(req.HookEvent) {
	case hook.HookSessionStart, hook.HookSessionEnd, hook.HookPreToolUse, hook.HookPostToolUse, hook.HookPostToolUseFailed:
	default:
		return errors.New("unsupported sensor hook")
	}
	req.Agent = "cowork"
	req.TranscriptPath = ""
	req.AgentTranscriptPath = ""
	req.UserRequest = ""
	req.ToolSchemas = nil
	req.CodexProxy = nil
	req.Browser = nil
	return nil
}

func Run(ctx context.Context, cfg Config, version string, log io.Writer) error {
	if runtime.GOOS != "linux" {
		return errors.New("the Cowork sensor runs inside the Linux VM")
	}
	return run(ctx, cfg, version, log)
}

func run(ctx context.Context, cfg Config, version string, log io.Writer) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	tokenBytes, err := privateFile(cfg.TokenFile)
	if err != nil {
		return fmt.Errorf("read private test credential: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return errors.New("test credential is empty")
	}
	if err := os.MkdirAll(cfg.StateDir, 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.RuntimeDir, 0755); err != nil {
		return err
	}
	readyPath := filepath.Join(cfg.RuntimeDir, "ready.json")
	if err := os.Remove(readyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	defer os.Remove(readyPath)
	dbPath := filepath.Join(cfg.StateDir, "guard.db")
	host, err := runtimehost.Start(ctx, runtimehost.Options{
		AgentName: "cowork", DBPath: dbPath,
		SocketPath: filepath.Join(cfg.RuntimeDir, "sensor.sock"), SocketMode: 0666,
		RequestFilter: FilterRequest, Mode: guardhookruntime.ModeObserve,
		CedarEnforcement: server.CedarEnforcementOff, SkipInitialSession: true,
		DisableStepSafety: true,
	})
	if err != nil {
		return fmt.Errorf("start sensor runtime: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = host.Close(c)
		}
	}()
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	stream := managedstream.Options{
		DBPath: dbPath, StatePath: filepath.Join(cfg.StateDir, "stream.json"),
		CloudURL: cfg.CloudURL, InstallToken: token, InstallationID: cfg.InstallationID,
		DeviceLabel: "Cowork EDR internal ARM64 test", UserEmail: cfg.UserEmail,
		CLIVersion: version, HTTPClient: client, HeartbeatInterval: time.Nanosecond,
	}
	flush := func(flushCtx context.Context) error { return managedstream.FlushLedger(flushCtx, stream) }
	if err := flush(ctx); err != nil {
		return fmt.Errorf("test workspace did not accept sensor startup: %w", err)
	}
	ready, _ := json.Marshal(map[string]any{"mode": "observe", "version": version, "installation_id": cfg.InstallationID, "pid": os.Getpid()})
	if err := os.WriteFile(readyPath, append(ready, '\n'), 0644); err != nil {
		return err
	}
	fmt.Fprintln(log, "Cowork sensor ready: observe-only; test workspace accepted startup; model, compaction, proxy, discovery and transcript recovery disabled")
	interval := cfg.Interval
	if interval == 0 {
		interval = 3 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			end, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := host.Close(end); err != nil {
				return err
			}
			closed = true
			return flush(end)
		case <-ticker.C:
			if err := flush(ctx); err != nil {
				fmt.Fprintln(log, "Cowork sensor upload failed; retaining activity for retry")
			}
		}
	}
}
