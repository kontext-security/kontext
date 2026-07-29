package startupui

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/guard/judge"
)

func TestRendererNonTTYPrintsStableProgressLines(t *testing.T) {
	var out bytes.Buffer
	renderer := NewWithTTY(&out, false)

	renderer.Header()
	renderer.HandleDownloadProgress(judge.DownloadProgress{Event: judge.DownloadProgressCacheCheck})
	renderer.HandleDownloadProgress(judge.DownloadProgress{Event: judge.DownloadProgressStart, TotalBytes: 1000})
	renderer.HandleDownloadProgress(judge.DownloadProgress{Event: judge.DownloadProgressUpdate, CurrentBytes: 500, TotalBytes: 1000})
	renderer.HandleDownloadProgress(judge.DownloadProgress{Event: judge.DownloadProgressDone, CurrentBytes: 1000, TotalBytes: 1000})
	renderer.LocalJudgeReady(true, false)

	got := out.String()
	if strings.Contains(got, "\r") {
		t.Fatalf("non-TTY output contains carriage return: %q", got)
	}
	for _, want := range []string{
		"Kontext • Starting local guard",
		"Checking local model cache...",
		"Downloading local judge model...",
		"Progress: 500 B / 1.0 KB (50%)",
		"✓ Local judge model ready",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output = %q, want %q", got, want)
		}
	}
	if strings.Contains(got, "http://127.0.0.1:18080") || strings.Contains(got, "(llama-server)") {
		t.Fatalf("output leaked local judge internals: %q", got)
	}
	if strings.Contains(got, "Qwen/Qwen3-0.6B-GGUF") {
		t.Fatalf("output leaked model name: %q", got)
	}
}

func TestRendererTTYRedrawsProgressLine(t *testing.T) {
	var out bytes.Buffer
	renderer := NewWithTTY(&out, true)

	renderer.HandleDownloadProgress(judge.DownloadProgress{Event: judge.DownloadProgressCacheCheck})
	renderer.HandleDownloadProgress(judge.DownloadProgress{Event: judge.DownloadProgressStart, TotalBytes: 1000})
	renderer.HandleDownloadProgress(judge.DownloadProgress{Event: judge.DownloadProgressUpdate, CurrentBytes: 1000, TotalBytes: 1000})

	got := out.String()
	if !strings.Contains(got, "\r") {
		t.Fatalf("TTY output = %q, want carriage return", got)
	}
	if !strings.Contains(got, "✓ Model cache checked") || !strings.Contains(got, "100%") {
		t.Fatalf("TTY output = %q, want cache checked and percent", got)
	}
}

func TestRendererTTYClearsCacheCheckBeforeJudgeSummary(t *testing.T) {
	var out bytes.Buffer
	renderer := NewWithTTY(&out, true)

	renderer.HandleDownloadProgress(judge.DownloadProgress{Event: judge.DownloadProgressCacheCheck})
	renderer.LocalJudgeReady(true, true)

	got := out.String()
	if !strings.Contains(got, "\r") {
		t.Fatalf("TTY output = %q, want carriage return", got)
	}
	if !strings.Contains(got, "✗ Local judge unavailable\n") {
		t.Fatalf("TTY output = %q, want local judge unavailable on a clean line", got)
	}
	if strings.Contains(got, "Checking local model cache...✗ Local judge unavailable") {
		t.Fatalf("TTY output did not clear active cache line: %q", got)
	}
}

func TestRendererDownloadErrorHidesRawFailure(t *testing.T) {
	var out bytes.Buffer
	renderer := NewWithTTY(&out, false)

	renderer.HandleDownloadProgress(judge.DownloadProgress{
		Event: judge.DownloadProgressError,
		Err:   errors.New("get https://huggingface.co/Qwen/Qwen3-0.6B-GGUF: connection refused"),
	})

	got := out.String()
	if !strings.Contains(got, "✗ Failed to download local judge model") {
		t.Fatalf("output = %q, want generic download failure", got)
	}
	for _, leaked := range []string{"https://huggingface.co", "Qwen/Qwen3-0.6B-GGUF", "connection refused"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("output leaked raw failure %q: %q", leaked, got)
		}
	}
}

func TestRendererModeOnlyPrintsEnforce(t *testing.T) {
	var out bytes.Buffer
	renderer := NewWithTTY(&out, false)

	renderer.Mode("observe")
	renderer.Mode("enforce")

	got := out.String()
	if strings.Contains(got, "observe") {
		t.Fatalf("output = %q, want default observe mode hidden", got)
	}
	if !strings.Contains(got, "✓ Mode: enforce (blocking enabled)") {
		t.Fatalf("output = %q, want enforce mode visible", got)
	}
}

func TestRendererRecordsWriteError(t *testing.T) {
	wantErr := errors.New("closed pipe")
	renderer := NewWithTTY(failingWriter{err: wantErr}, false)

	renderer.Header()

	if !errors.Is(renderer.Err(), wantErr) {
		t.Fatalf("Err() = %v, want %v", renderer.Err(), wantErr)
	}
}

func TestLocalJudgeSummary(t *testing.T) {
	tests := []struct {
		name        string
		enabled     bool
		unavailable bool
		want        string
	}{
		{name: "disabled", enabled: false, want: "disabled"},
		{name: "unavailable", enabled: true, unavailable: true, want: "unavailable"},
		{name: "ready", enabled: true, want: "ready"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := LocalJudgeSummary(test.enabled, test.unavailable)
			if got != test.want {
				t.Fatalf("LocalJudgeSummary() = %q, want %q", got, test.want)
			}
		})
	}
}

type failingWriter struct {
	err error
}

func (w failingWriter) Write([]byte) (int, error) {
	return 0, w.err
}
