package judgeruntime

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kontext-security/kontext-cli/internal/guard/judge"
	"github.com/kontext-security/kontext-cli/internal/profile"
)

type Config struct {
	URL              string
	Model            string
	Timeout          time.Duration
	Managed          bool
	ServerBin        string
	ModelPath        string
	HFRepo           string
	HFFile           string
	HFRevision       string
	CacheDir         string
	Port             int
	StartupTimeout   time.Duration
	DownloadProgress judge.DownloadProgressHandler
}

// ConfigFromEnv resolves the local model from the environment. Managed mode is
// opt-in only: nothing defaults it on, because the only caller that used to —
// the retired `kontext start` wrapper — managed a llama-server child on the
// user's behalf, and no remaining path should download a model unprompted.
func ConfigFromEnv(dbPath string) (Config, error) {
	timeout, err := envDuration("KONTEXT_JUDGE_TIMEOUT", judge.DefaultTimeout)
	if err != nil {
		return Config{}, err
	}
	managed, err := envBoolDefault("KONTEXT_JUDGE_MANAGED", false)
	if err != nil {
		return Config{}, err
	}
	port, err := envInt("KONTEXT_JUDGE_PORT", judge.DefaultLlamaServerPort)
	if err != nil {
		return Config{}, err
	}
	startupTimeout, err := envDuration("KONTEXT_JUDGE_STARTUP_TIMEOUT", judge.DefaultLlamaServerStartupTimeout)
	if err != nil {
		return Config{}, err
	}
	return Config{
		URL:            os.Getenv("KONTEXT_JUDGE_URL"),
		Model:          os.Getenv("KONTEXT_JUDGE_MODEL"),
		Timeout:        timeout,
		Managed:        managed,
		ServerBin:      envString("KONTEXT_JUDGE_SERVER_BIN", judge.DefaultLlamaServerBinary),
		ModelPath:      os.Getenv("KONTEXT_JUDGE_MODEL_PATH"),
		HFRepo:         os.Getenv("KONTEXT_JUDGE_HF_REPO"),
		HFFile:         os.Getenv("KONTEXT_JUDGE_HF_FILE"),
		HFRevision:     os.Getenv("KONTEXT_JUDGE_HF_REVISION"),
		CacheDir:       ResolvedCacheDir(os.Getenv("KONTEXT_JUDGE_CACHE_DIR"), dbPath),
		Port:           port,
		StartupTimeout: startupTimeout,
	}, nil
}

// Runtime is a configured local judge plus the endpoint it talks to. The
// endpoint is reused by the observe-mode risk classifier's guardrail model, so
// both signals share one llama-server process.
type Runtime struct {
	Judge   judge.Judge
	Close   func()
	Status  string
	BaseURL string
	Model   string
}

func Configure(ctx context.Context, cfg Config) (judge.Judge, func(), string, error) {
	runtime, err := ConfigureRuntime(ctx, cfg)
	return runtime.Judge, runtime.Close, runtime.Status, err
}

// ConfigureRuntime resolves the local judge and reports the endpoint serving
// it. A nil Judge with a nil error means no judge was requested.
func ConfigureRuntime(ctx context.Context, cfg Config) (Runtime, error) {
	closeFn := func() {}
	if cfg.Managed {
		return configureManaged(ctx, cfg)
	}
	if strings.TrimSpace(cfg.URL) == "" && strings.TrimSpace(cfg.Model) == "" {
		return Runtime{Close: closeFn}, nil
	}
	if strings.TrimSpace(cfg.URL) == "" || strings.TrimSpace(cfg.Model) == "" {
		return Runtime{Close: closeFn}, fmt.Errorf("--judge-url and --judge-model must be set together")
	}
	if err := ValidateLocalURL(cfg.URL); err != nil {
		return Runtime{Close: closeFn}, err
	}
	localJudge, err := judge.NewOpenAICompatibleJudge(judge.HTTPOptions{
		BaseURL: cfg.URL,
		Model:   cfg.Model,
		Timeout: cfg.Timeout,
	})
	if err != nil {
		return Runtime{Close: closeFn}, err
	}
	return Runtime{
		Judge:   localJudge,
		Close:   closeFn,
		Status:  fmt.Sprintf("%s at %s", cfg.Model, cfg.URL),
		BaseURL: cfg.URL,
		Model:   cfg.Model,
	}, nil
}

func configureManaged(ctx context.Context, cfg Config) (Runtime, error) {
	closeFn := func() {}
	modelPath := strings.TrimSpace(cfg.ModelPath)
	modelName := strings.TrimSpace(cfg.Model)
	if modelPath == "" && LooksLikeGGUFPath(modelName) {
		modelPath = modelName
		modelName = ""
	}
	hfRepo := strings.TrimSpace(cfg.HFRepo)
	hfFile := strings.TrimSpace(cfg.HFFile)
	if modelPath == "" && hfRepo == "" {
		hfRepo = judge.DefaultLlamaServerHFRepo
		if hfFile == "" {
			hfFile = judge.DefaultLlamaServerHFFile
		}
	}
	if modelName == "" {
		modelName = ManagedModelName(modelPath, hfRepo, hfFile)
	}
	host, port, baseURL, err := ManagedListenConfig(cfg.URL, cfg.Port)
	if err != nil {
		return Runtime{Close: closeFn}, err
	}
	server, err := judge.StartLlamaServer(ctx, judge.LlamaServerOptions{
		BinaryPath:       cfg.ServerBin,
		ModelPath:        modelPath,
		HFRepo:           hfRepo,
		HFFile:           hfFile,
		HFRevision:       cfg.HFRevision,
		CacheDir:         cfg.CacheDir,
		Host:             host,
		Port:             port,
		StartupTimeout:   cfg.StartupTimeout,
		DownloadProgress: cfg.DownloadProgress,
	})
	if err != nil {
		unavailable := judge.UnavailableJudge{
			Runtime: judge.DefaultLlamaServerRuntime,
			Model:   modelName,
			Kind:    judge.FailureUnavailable,
			Err:     err,
		}
		return Runtime{
			Judge:  unavailable,
			Close:  closeFn,
			Status: fmt.Sprintf("%s unavailable (%v)", modelName, err),
			Model:  modelName,
		}, nil
	}
	closeFn = func() {
		_ = server.Stop()
	}
	localJudge, err := judge.NewOpenAICompatibleJudge(judge.HTTPOptions{
		BaseURL: baseURL,
		Model:   modelName,
		Runtime: judge.DefaultLlamaServerRuntime,
		Timeout: cfg.Timeout,
	})
	if err != nil {
		closeFn()
		return Runtime{Close: func() {}}, err
	}
	return Runtime{
		Judge:   localJudge,
		Close:   closeFn,
		Status:  fmt.Sprintf("%s at %s (%s)", modelName, baseURL, judge.DefaultLlamaServerRuntime),
		BaseURL: baseURL,
		Model:   modelName,
	}, nil
}

func ManagedListenConfig(rawURL string, port int) (string, int, string, error) {
	if port <= 0 {
		port = judge.DefaultLlamaServerPort
	}
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return judge.DefaultLlamaServerHost, port, managedBaseURL(judge.DefaultLlamaServerHost, port), nil
	}
	if err := ValidateLocalURL(rawURL); err != nil {
		return "", 0, "", err
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", 0, "", fmt.Errorf("parse judge URL: %w", err)
	}
	if parsed.Scheme != "http" {
		return "", 0, "", fmt.Errorf("managed judge URL must use http")
	}
	host := parsed.Hostname()
	if host == "" {
		return "", 0, "", fmt.Errorf("managed judge URL must include host")
	}
	if parsed.Port() != "" {
		parsedPort, err := strconv.Atoi(parsed.Port())
		if err != nil || parsedPort <= 0 {
			return "", 0, "", fmt.Errorf("managed judge URL has invalid port %q", parsed.Port())
		}
		port = parsedPort
	}
	return host, port, managedBaseURL(host, port), nil
}

func ValidateLocalURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("parse judge URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("judge URL must use http or https")
	}
	switch strings.ToLower(parsed.Hostname()) {
	case "localhost", "127.0.0.1", "::1":
		return nil
	default:
		return fmt.Errorf("judge URL must point to localhost")
	}
}

func LooksLikeGGUFPath(value string) bool {
	value = strings.TrimSpace(value)
	return strings.HasSuffix(strings.ToLower(value), ".gguf") || strings.Contains(value, string(filepath.Separator))
}

func ManagedModelName(modelPath, hfRepo, hfFile string) string {
	if strings.TrimSpace(hfRepo) != "" {
		return strings.TrimSpace(hfRepo)
	}
	if strings.TrimSpace(modelPath) != "" {
		return filepath.Base(modelPath)
	}
	if strings.TrimSpace(hfFile) != "" {
		return strings.TrimSpace(hfFile)
	}
	return "local-judge"
}

func ResolvedCacheDir(cacheDir, dbPath string) string {
	if strings.TrimSpace(cacheDir) != "" {
		return cacheDir
	}
	return defaultCacheDir(dbPath)
}

func managedBaseURL(host string, port int) string {
	return (&url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(host, strconv.Itoa(port)),
	}).String()
}

func defaultCacheDir(dbPath string) string {
	if dbPath != "" {
		// Model weights are machine-scoped, not workspace-scoped: hundreds of
		// megabytes, identical for every workspace. When the database sits inside
		// a profile, the cache is hoisted to the shared root so switching or
		// adding a profile does not trigger a re-download. Databases outside the
		// profiles tree (`kontext guard`) keep the original layout.
		if shared := profile.SharedDir(filepath.Dir(dbPath), profile.ModelCacheDirName); shared != "" {
			return shared
		}
		return filepath.Join(filepath.Dir(dbPath), profile.ModelCacheDirName)
	}
	if dir, err := os.UserCacheDir(); err == nil && dir != "" {
		return filepath.Join(dir, "kontext", "judge")
	}
	return filepath.Join(".", "judge-models")
}

func envString(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envBoolDefault(key string, fallback bool) (bool, error) {
	if value := os.Getenv(key); value != "" {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return false, fmt.Errorf("%s must be a boolean: %w", key, err)
		}
		return parsed, nil
	}
	return fallback, nil
}

func envInt(key string, fallback int) (int, error) {
	if value := os.Getenv(key); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return 0, fmt.Errorf("%s must be an integer: %w", key, err)
		}
		return parsed, nil
	}
	return fallback, nil
}

func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	if value := os.Getenv(key); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return 0, fmt.Errorf("%s must be a duration: %w", key, err)
		}
		return parsed, nil
	}
	return fallback, nil
}
