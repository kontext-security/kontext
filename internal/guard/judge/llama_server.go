package judge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultLlamaServerRuntime         = "llama-server"
	DefaultLlamaServerBinary          = "llama-server"
	DefaultLlamaServerHost            = "127.0.0.1"
	DefaultLlamaServerPort            = 18080
	DefaultLlamaServerStartupTimeout  = 30 * time.Second
	DefaultLlamaServerHFRepo          = "Qwen/Qwen3-0.6B-GGUF"
	DefaultLlamaServerHFFile          = "Qwen3-0.6B-Q8_0.gguf"
	DefaultLlamaServerHFRevision      = "main"
	DefaultLlamaServerDownloadTimeout = 10 * time.Minute
)

type LlamaServerOptions struct {
	BinaryPath       string
	ModelPath        string
	HFRepo           string
	HFFile           string
	HFRevision       string
	CacheDir         string
	Host             string
	Port             int
	StartupTimeout   time.Duration
	HTTPClient       *http.Client
	Stdout           io.Writer
	Stderr           io.Writer
	DownloadProgress DownloadProgressHandler
}

type LlamaServer struct {
	baseURL string
	cancel  context.CancelFunc
	wait    chan error
	cmd     *exec.Cmd
}

type DownloadProgressEvent string

const (
	DownloadProgressCacheCheck DownloadProgressEvent = "cache_check"
	DownloadProgressCacheHit   DownloadProgressEvent = "cache_hit"
	DownloadProgressStart      DownloadProgressEvent = "download_start"
	DownloadProgressUpdate     DownloadProgressEvent = "download_update"
	DownloadProgressDone       DownloadProgressEvent = "download_done"
	DownloadProgressError      DownloadProgressEvent = "download_error"
)

type DownloadProgress struct {
	Event        DownloadProgressEvent
	CurrentBytes int64
	TotalBytes   int64
	Err          error
}

type DownloadProgressHandler func(DownloadProgress)

func StartLlamaServer(ctx context.Context, opts LlamaServerOptions) (*LlamaServer, error) {
	opts = normalizeLlamaServerOptions(opts)
	binaryPath, err := exec.LookPath(opts.BinaryPath)
	if err != nil {
		return nil, fmt.Errorf("find %s: %w", opts.BinaryPath, err)
	}
	if err := ensureLlamaServerPortAvailable(opts.Host, opts.Port); err != nil {
		return nil, err
	}
	modelPath, err := ResolveLlamaServerModel(ctx, opts)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(modelPath); err != nil {
		return nil, fmt.Errorf("stat judge model %q: %w", modelPath, err)
	}

	childCtx, cancel := context.WithCancel(ctx)
	args := BuildLlamaServerArgs(LlamaServerOptions{
		ModelPath: modelPath,
		Host:      opts.Host,
		Port:      opts.Port,
	})
	cmd := exec.CommandContext(childCtx, binaryPath, args...)
	cmd.Stdout = opts.Stdout
	cmd.Stderr = opts.Stderr
	if cmd.Stdout == nil {
		cmd.Stdout = io.Discard
	}
	if cmd.Stderr == nil {
		cmd.Stderr = io.Discard
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start %s: %w", opts.BinaryPath, err)
	}

	server := &LlamaServer{
		baseURL: llamaServerBaseURL(opts.Host, opts.Port),
		cancel:  cancel,
		wait:    make(chan error, 1),
		cmd:     cmd,
	}
	go func() {
		server.wait <- cmd.Wait()
	}()
	if err := server.waitHealthy(ctx, opts); err != nil {
		_ = server.Stop()
		return nil, err
	}
	return server, nil
}

func ensureLlamaServerPortAvailable(host string, port int) error {
	listener, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("llama-server port %s:%d is unavailable: %w", host, port, err)
	}
	return listener.Close()
}

func llamaServerBaseURL(host string, port int) string {
	return (&url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(host, strconv.Itoa(port)),
	}).String()
}

func ResolveLlamaServerModel(ctx context.Context, opts LlamaServerOptions) (string, error) {
	opts = normalizeLlamaServerOptions(opts)
	modelPath := strings.TrimSpace(opts.ModelPath)
	if modelPath != "" {
		return modelPath, nil
	}
	repo := strings.TrimSpace(opts.HFRepo)
	file := strings.TrimSpace(opts.HFFile)
	revision := strings.TrimSpace(opts.HFRevision)
	if repo == "" || file == "" {
		return "", errors.New("judge model path or Hugging Face repo/file is required")
	}
	cachedPath, err := CachedHFModelPath(opts.CacheDir, repo, revision, file)
	if err != nil {
		return "", err
	}
	emitDownloadProgress(opts.DownloadProgress, DownloadProgress{
		Event: DownloadProgressCacheCheck,
	})
	if info, err := os.Stat(cachedPath); err == nil {
		size := info.Size()
		emitDownloadProgress(opts.DownloadProgress, DownloadProgress{
			Event:        DownloadProgressCacheHit,
			CurrentBytes: size,
			TotalBytes:   size,
		})
		return cachedPath, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err := downloadHFModel(ctx, opts.HTTPClient, repo, revision, file, cachedPath, opts.DownloadProgress); err != nil {
		return "", err
	}
	return cachedPath, nil
}

func BuildLlamaServerArgs(opts LlamaServerOptions) []string {
	opts = normalizeLlamaServerOptions(opts)
	return []string{
		"--model", strings.TrimSpace(opts.ModelPath),
		"--host", opts.Host,
		"--port", strconv.Itoa(opts.Port),
	}
}

func CachedHFModelPath(cacheDir, repo, revision, file string) (string, error) {
	cacheDir = strings.TrimSpace(cacheDir)
	if cacheDir == "" {
		cacheDir = defaultJudgeCacheDir()
	}
	repo = strings.TrimSpace(repo)
	revision = strings.TrimSpace(revision)
	if revision == "" {
		revision = DefaultLlamaServerHFRevision
	}
	file = strings.TrimSpace(file)
	if repo == "" || file == "" {
		return "", errors.New("Hugging Face repo and file are required")
	}
	if strings.Contains(repo, "..") {
		return "", fmt.Errorf("invalid Hugging Face repo %q", repo)
	}
	if strings.Contains(revision, "..") {
		return "", fmt.Errorf("invalid Hugging Face revision %q", revision)
	}
	cleanRevision := filepath.Clean(revision)
	if filepath.IsAbs(cleanRevision) || cleanRevision == "." || strings.HasPrefix(cleanRevision, ".."+string(filepath.Separator)) || cleanRevision == ".." {
		return "", fmt.Errorf("invalid Hugging Face revision %q", revision)
	}
	cleanFile := filepath.Clean(file)
	if filepath.IsAbs(cleanFile) || cleanFile == "." || strings.HasPrefix(cleanFile, ".."+string(filepath.Separator)) || cleanFile == ".." {
		return "", fmt.Errorf("invalid Hugging Face file %q", file)
	}
	repoParts := strings.Split(repo, "/")
	parts := append([]string{cacheDir, "huggingface"}, repoParts...)
	parts = append(parts, cleanRevision)
	parts = append(parts, cleanFile)
	return filepath.Join(parts...), nil
}

func (s *LlamaServer) BaseURL() string {
	if s == nil {
		return ""
	}
	return s.baseURL
}

func (s *LlamaServer) Stop() error {
	if s == nil {
		return nil
	}
	s.cancel()
	select {
	case err := <-s.wait:
		if err == nil {
			return nil
		}
		if errors.Is(err, context.Canceled) {
			return nil
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil
		}
		return err
	case <-time.After(3 * time.Second):
		if s.cmd != nil && s.cmd.Process != nil {
			_ = s.cmd.Process.Kill()
		}
		return errors.New("timed out stopping llama-server")
	}
}

func (s *LlamaServer) waitHealthy(ctx context.Context, opts LlamaServerOptions) error {
	timeout := opts.StartupTimeout
	if timeout <= 0 {
		timeout = DefaultLlamaServerStartupTimeout
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 500 * time.Millisecond}
	}
	healthCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-s.wait:
			s.wait <- err
			if err == nil {
				return errors.New("llama-server exited before becoming healthy")
			}
			return fmt.Errorf("llama-server exited before becoming healthy: %w", err)
		default:
		}
		req, err := http.NewRequestWithContext(healthCtx, http.MethodGet, s.baseURL+"/v1/models", nil)
		if err == nil {
			resp, err := client.Do(req)
			if err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					return nil
				}
			}
		}
		select {
		case <-healthCtx.Done():
			return fmt.Errorf("llama-server health check timed out after %s", timeout)
		case <-ticker.C:
		}
	}
}

func normalizeLlamaServerOptions(opts LlamaServerOptions) LlamaServerOptions {
	if strings.TrimSpace(opts.BinaryPath) == "" {
		opts.BinaryPath = DefaultLlamaServerBinary
	}
	if strings.TrimSpace(opts.Host) == "" {
		opts.Host = DefaultLlamaServerHost
	}
	if opts.Port <= 0 {
		opts.Port = DefaultLlamaServerPort
	}
	if strings.TrimSpace(opts.HFRevision) == "" {
		opts.HFRevision = DefaultLlamaServerHFRevision
	}
	if opts.StartupTimeout <= 0 {
		opts.StartupTimeout = DefaultLlamaServerStartupTimeout
	}
	return opts
}

func downloadHFModel(ctx context.Context, client *http.Client, repo, revision, file, targetPath string, progress DownloadProgressHandler) error {
	if client == nil {
		client = &http.Client{Timeout: DefaultLlamaServerDownloadTimeout}
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, hfResolveURL(repo, revision, file), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "kontext-guard")
	resp, err := client.Do(req)
	if err != nil {
		wrapped := fmt.Errorf("download judge model: %w", err)
		emitDownloadProgress(progress, DownloadProgress{Event: DownloadProgressError, Err: wrapped})
		return wrapped
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := fmt.Errorf("download judge model returned %s", resp.Status)
		emitDownloadProgress(progress, DownloadProgress{Event: DownloadProgressError, Err: err})
		return err
	}
	totalBytes := resp.ContentLength
	if totalBytes < 0 {
		totalBytes = 0
	}
	emitDownloadProgress(progress, DownloadProgress{
		Event:      DownloadProgressStart,
		TotalBytes: totalBytes,
	})
	tmp, err := os.CreateTemp(filepath.Dir(targetPath), filepath.Base(targetPath)+".*.tmp")
	if err != nil {
		emitDownloadProgress(progress, DownloadProgress{Event: DownloadProgressError, Err: err})
		return err
	}
	tmpPath := tmp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tmpPath)
		}
	}()
	reader := &progressReader{
		reader: resp.Body,
		onProgress: func(current int64) {
			emitDownloadProgress(progress, DownloadProgress{
				Event:        DownloadProgressUpdate,
				CurrentBytes: current,
				TotalBytes:   totalBytes,
			})
		},
	}
	written, err := io.Copy(tmp, reader)
	if err != nil {
		err = closeAndRemoveTemp(tmp, tmpPath, err)
		removeTemp = false
		emitDownloadProgress(progress, DownloadProgress{Event: DownloadProgressError, Err: err})
		return err
	}
	if err := tmp.Close(); err != nil {
		err = errors.Join(err, os.Remove(tmpPath))
		removeTemp = false
		emitDownloadProgress(progress, DownloadProgress{Event: DownloadProgressError, Err: err})
		return err
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		err = errors.Join(err, os.Remove(tmpPath))
		removeTemp = false
		emitDownloadProgress(progress, DownloadProgress{Event: DownloadProgressError, Err: err})
		return err
	}
	removeTemp = false
	emitDownloadProgress(progress, DownloadProgress{
		Event:        DownloadProgressDone,
		CurrentBytes: written,
		TotalBytes:   written,
	})
	return nil
}

func closeAndRemoveTemp(tmp *os.File, path string, cause error) error {
	return errors.Join(cause, tmp.Close(), os.Remove(path))
}

type progressReader struct {
	reader     io.Reader
	current    int64
	onProgress func(int64)
}

func (r *progressReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.current += int64(n)
		if r.onProgress != nil {
			r.onProgress(r.current)
		}
	}
	return n, err
}

func emitDownloadProgress(progress DownloadProgressHandler, event DownloadProgress) {
	if progress != nil {
		progress(event)
	}
}

func hfResolveURL(repo, revision, file string) string {
	if strings.TrimSpace(revision) == "" {
		revision = DefaultLlamaServerHFRevision
	}
	return "https://huggingface.co/" + escapePath(repo) + "/resolve/" + escapePath(revision) + "/" + escapePath(file)
}

func escapePath(value string) string {
	parts := strings.Split(value, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func defaultJudgeCacheDir() string {
	if dir, err := os.UserCacheDir(); err == nil && dir != "" {
		return filepath.Join(dir, "kontext", "judge")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".kontext", "judge")
	}
	return filepath.Join(".", ".kontext", "judge")
}
