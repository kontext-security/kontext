package judge

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestBuildLlamaServerArgsUsesLocalModel(t *testing.T) {
	got := BuildLlamaServerArgs(LlamaServerOptions{
		ModelPath: "/models/qwen.gguf",
		Host:      "127.0.0.1",
		Port:      18081,
	})
	// --ctx-size is explicit: llama-server's default allocates its full trained
	// context per slot, which measured 5.1 GB RSS for a 0.6B model.
	want := []string{"--model", "/models/qwen.gguf", "--host", "127.0.0.1", "--port", "18081",
		"--ctx-size", strconv.Itoa(DefaultLlamaServerContextSize)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
}

func TestStartLlamaServerMissingBinary(t *testing.T) {
	modelPath := writeTestModel(t)
	_, err := StartLlamaServer(context.Background(), LlamaServerOptions{
		BinaryPath: "kontext-missing-llama-server",
		ModelPath:  modelPath,
	})
	if err == nil {
		t.Fatal("StartLlamaServer() error = nil, want missing binary error")
	}
	if !strings.Contains(err.Error(), "find kontext-missing-llama-server") {
		t.Fatalf("err = %v, want missing binary", err)
	}
}

func TestStartLlamaServerMissingBinaryDoesNotDownloadModel(t *testing.T) {
	downloaded := false
	_, err := StartLlamaServer(context.Background(), LlamaServerOptions{
		BinaryPath: "kontext-missing-llama-server",
		CacheDir:   t.TempDir(),
		HFRepo:     "Qwen/Qwen3-0.6B-GGUF",
		HFFile:     "Qwen3-0.6B-Q8_0.gguf",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			downloaded = true
			return http.DefaultTransport.RoundTrip(req)
		})},
	})
	if err == nil {
		t.Fatal("StartLlamaServer() error = nil, want missing binary error")
	}
	if downloaded {
		t.Fatal("model download started before checking llama-server binary")
	}
}

func TestStartLlamaServerRejectsOccupiedPort(t *testing.T) {
	modelPath := writeTestModel(t)
	binaryPath := writeFakeLlamaServer(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	_, err = StartLlamaServer(context.Background(), LlamaServerOptions{
		BinaryPath: binaryPath,
		ModelPath:  modelPath,
		Port:       port,
	})
	if err == nil {
		t.Fatal("StartLlamaServer() error = nil, want occupied port rejection")
	}
	if !strings.Contains(err.Error(), "llama-server port 127.0.0.1:") {
		t.Fatalf("err = %v, want occupied port error", err)
	}
}

// testLlamaServerStartupTimeout is deliberately generous. The fake
// llama-server re-execs the test binary, which can take seconds to serve its
// first request when the rest of the suite is running in parallel, and a tight
// budget here only buys a flaky "health check timed out" failure. The health
// loop returns as soon as the fake is up, so a large budget costs nothing on a
// healthy run.
const testLlamaServerStartupTimeout = 30 * time.Second

// testLlamaServerStopTimeout is long enough that a Stop() which actually waits
// for its deadline is unmistakable next to normal startup jitter.
const testLlamaServerStopTimeout = 10 * time.Second

func TestStartLlamaServerHealthCheckAndStop(t *testing.T) {
	modelPath := writeTestModel(t)
	binaryPath := writeFakeLlamaServer(t)
	port := freeTCPPort(t)
	server, err := StartLlamaServer(context.Background(), LlamaServerOptions{
		BinaryPath:     binaryPath,
		ModelPath:      modelPath,
		Port:           port,
		StartupTimeout: testLlamaServerStartupTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	if server.BaseURL() != "http://127.0.0.1:"+strconv.Itoa(port) {
		t.Fatalf("BaseURL() = %q", server.BaseURL())
	}
	if err := server.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestStartLlamaServerEarlyExitDoesNotWaitForStopTimeout(t *testing.T) {
	modelPath := writeTestModel(t)
	binaryPath := writeFakeExitingLlamaServer(t)
	start := time.Now()
	_, err := StartLlamaServer(context.Background(), LlamaServerOptions{
		BinaryPath:     binaryPath,
		ModelPath:      modelPath,
		Port:           freeTCPPort(t),
		StartupTimeout: testLlamaServerStartupTimeout,
		StopTimeout:    testLlamaServerStopTimeout,
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("StartLlamaServer() error = nil, want early exit error")
	}
	// The startup path must notice the dead child itself rather than idle until
	// the health deadline, and the Stop() it then runs must observe the same
	// exit status instead of blocking until the stop deadline. Both are timeouts
	// far longer than the process spawn jitter that dominates a healthy run, so
	// the bound stays meaningful on a loaded machine.
	if !strings.Contains(err.Error(), "exited before becoming healthy") {
		t.Fatalf("err = %v, want early exit error", err)
	}
	if elapsed >= testLlamaServerStopTimeout {
		t.Fatalf("early exit took %s, want well under the %s stop timeout", elapsed, testLlamaServerStopTimeout)
	}
}

func TestCachedHFModelPathRejectsTraversal(t *testing.T) {
	if _, err := CachedHFModelPath(t.TempDir(), "Qwen/Qwen3-0.6B-GGUF", "main", "../model.gguf"); err == nil {
		t.Fatal("CachedHFModelPath() error = nil, want traversal rejection")
	}
}

func TestCachedHFModelPathIncludesRevision(t *testing.T) {
	got, err := CachedHFModelPath("/cache", "Qwen/Qwen3-0.6B-GGUF", "refs/pr/1", "Qwen3-0.6B-Q8_0.gguf")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join("/cache", "huggingface", "Qwen", "Qwen3-0.6B-GGUF", "refs/pr/1", "Qwen3-0.6B-Q8_0.gguf")
	if got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
}

func TestResolveLlamaServerModelUsesCachedFile(t *testing.T) {
	cacheDir := t.TempDir()
	want := writeCachedTestHFModel(t, cacheDir, []byte("gguf"))
	var events []DownloadProgress
	got, err := ResolveLlamaServerModel(context.Background(), LlamaServerOptions{
		CacheDir: cacheDir,
		HFRepo:   "Qwen/Qwen3-0.6B-GGUF",
		HFFile:   "Qwen3-0.6B-Q8_0.gguf",
		DownloadProgress: func(event DownloadProgress) {
			events = append(events, event)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("model path = %q, want %q", got, want)
	}
	if len(events) != 2 || events[0].Event != DownloadProgressCacheCheck || events[1].Event != DownloadProgressCacheHit {
		t.Fatalf("events = %+v, want cache check + hit", events)
	}
}

func TestResolveLlamaServerModelDownloadsToCache(t *testing.T) {
	cacheDir := t.TempDir()
	got, err := resolveTestHFModel(t, cacheDir, "main", nil, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Qwen/Qwen3-0.6B-GGUF/resolve/main/Qwen3-0.6B-Q8_0.gguf" {
			t.Fatalf("download path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte("gguf"))
	})
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(bytes) != "gguf" {
		t.Fatalf("cached bytes = %q, want gguf", bytes)
	}
}

func TestResolveLlamaServerModelEmitsDownloadProgress(t *testing.T) {
	tests := []struct {
		name           string
		handler        http.HandlerFunc
		wantErr        bool
		wantStartTotal int64
	}{
		{
			name: "known content length",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "4")
				_, _ = w.Write([]byte("gguf"))
			},
			wantStartTotal: 4,
		},
		{
			name: "unknown content length",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Del("Content-Length")
				w.(http.Flusher).Flush()
				_, _ = w.Write([]byte("gguf"))
			},
		},
		{
			name: "http failure",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "nope", http.StatusBadGateway)
			},
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cacheDir := t.TempDir()
			wantPath, err := CachedHFModelPath(cacheDir, "Qwen/Qwen3-0.6B-GGUF", "main", "Qwen3-0.6B-Q8_0.gguf")
			if err != nil {
				t.Fatal(err)
			}
			var events []DownloadProgress
			_, err = resolveTestHFModel(t, cacheDir, "main", func(event DownloadProgress) {
				events = append(events, event)
			}, test.handler)
			if test.wantErr {
				if err == nil {
					t.Fatal("ResolveLlamaServerModel() error = nil, want failure")
				}
				if _, statErr := os.Stat(wantPath); !os.IsNotExist(statErr) {
					t.Fatalf("final model stat err = %v, want not exist", statErr)
				}
				if !hasProgressEvent(events, DownloadProgressError) {
					t.Fatalf("events = %+v, want error event", events)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			assertDownloadProgress(t, events, test.wantStartTotal)
		})
	}
}

func TestDownloadHFModelEmitsDownloadErrorWhenTempFileCannotBeCreated(t *testing.T) {
	cacheDir := t.TempDir()
	readOnlyDir := filepath.Join(cacheDir, "readonly")
	if err := os.MkdirAll(readOnlyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(readOnlyDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(readOnlyDir, 0o755) })
	if probe, err := os.CreateTemp(readOnlyDir, "probe"); err == nil {
		_ = probe.Close()
		_ = os.Remove(probe.Name())
		t.Skip("filesystem allows writes to chmod 0555 directory")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("gguf"))
	}))
	t.Cleanup(server.Close)
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	var events []DownloadProgress
	err = downloadHFModel(context.Background(), rewriteHFClient(target), "Qwen/Qwen3-0.6B-GGUF", "main", "Qwen3-0.6B-Q8_0.gguf", filepath.Join(readOnlyDir, "model.gguf"), func(event DownloadProgress) {
		events = append(events, event)
	})
	if err == nil {
		t.Fatal("downloadHFModel() error = nil, want temp file failure")
	}
	if !hasProgressEvent(events, DownloadProgressError) {
		t.Fatalf("events = %+v, want error event", events)
	}
}

func TestResolveLlamaServerModelDownloadsCustomRevision(t *testing.T) {
	cacheDir := t.TempDir()
	got, err := resolveTestHFModel(t, cacheDir, "refs/pr/1", nil, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Qwen/Qwen3-0.6B-GGUF/resolve/refs/pr/1/Qwen3-0.6B-Q8_0.gguf" {
			t.Fatalf("download path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte("gguf"))
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, filepath.Join("Qwen3-0.6B-GGUF", "refs/pr/1", "Qwen3-0.6B-Q8_0.gguf")) {
		t.Fatalf("cached path = %q, want revision included", got)
	}
}

func TestUnavailableJudgeFailsWithMetadata(t *testing.T) {
	localJudge := UnavailableJudge{Runtime: DefaultLlamaServerRuntime, Model: "qwen", Err: os.ErrNotExist}
	_, err := localJudge.Decide(context.Background(), Input{})
	if FailureKind(err) != FailureUnavailable {
		t.Fatalf("FailureKind(err) = %q, want unavailable", FailureKind(err))
	}
	if metadata := localJudge.Metadata(); metadata.Runtime != DefaultLlamaServerRuntime || metadata.Model != "qwen" {
		t.Fatalf("metadata = %+v", metadata)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func writeCachedTestHFModel(t *testing.T, cacheDir string, contents []byte) string {
	t.Helper()
	path, err := CachedHFModelPath(cacheDir, "Qwen/Qwen3-0.6B-GGUF", "main", "Qwen3-0.6B-Q8_0.gguf")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func resolveTestHFModel(t *testing.T, cacheDir string, revision string, progress DownloadProgressHandler, handler http.HandlerFunc) (string, error) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return ResolveLlamaServerModel(context.Background(), LlamaServerOptions{
		CacheDir:         cacheDir,
		HFRepo:           "Qwen/Qwen3-0.6B-GGUF",
		HFFile:           "Qwen3-0.6B-Q8_0.gguf",
		HFRevision:       revision,
		HTTPClient:       rewriteHFClient(target),
		DownloadProgress: progress,
	})
}

func rewriteHFClient(target *url.URL) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		rewritten := req.Clone(req.Context())
		rewritten.URL.Scheme = target.Scheme
		rewritten.URL.Host = target.Host
		return http.DefaultTransport.RoundTrip(rewritten)
	})}
}

func hasProgressEvent(events []DownloadProgress, want DownloadProgressEvent) bool {
	for _, event := range events {
		if event.Event == want {
			return true
		}
	}
	return false
}

func assertDownloadProgress(t *testing.T, events []DownloadProgress, wantStartTotal int64) {
	t.Helper()
	if !hasProgressEvent(events, DownloadProgressStart) || !hasProgressEvent(events, DownloadProgressUpdate) || !hasProgressEvent(events, DownloadProgressDone) {
		t.Fatalf("events = %+v, want start/update/done", events)
	}
	for _, event := range events {
		if event.Event == DownloadProgressStart && event.TotalBytes != wantStartTotal {
			t.Fatalf("start total bytes = %d, want %d", event.TotalBytes, wantStartTotal)
		}
	}
}

func TestFakeLlamaServerProcess(t *testing.T) {
	if os.Getenv("KONTEXT_FAKE_LLAMA_SERVER") != "1" {
		return
	}
	args := os.Args
	port := ""
	for i, arg := range args {
		if arg == "--" && i+1 < len(args) {
			port = args[i+1]
			break
		}
	}
	if port == "" {
		os.Exit(2)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"fake"}]}`))
	})
	if err := http.ListenAndServe("127.0.0.1:"+port, mux); err != nil {
		os.Exit(1)
	}
}

func writeTestModel(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "model.gguf")
	if err := os.WriteFile(path, []byte("gguf"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFakeLlamaServer(t *testing.T) string {
	t.Helper()
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "llama-server")
	script := `#!/bin/sh
port=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--port" ]; then
    shift
    port="$1"
  fi
  shift
done
KONTEXT_FAKE_LLAMA_SERVER=1 exec ` + shellQuote(testBinary) + ` -test.run=TestFakeLlamaServerProcess -- "$port"
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFakeExitingLlamaServer(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "llama-server")
	script := "#!/bin/sh\nexit 42\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}
