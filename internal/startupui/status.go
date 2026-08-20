package startupui

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/kontext-security/kontext/internal/guard/judge"
	"github.com/mattn/go-isatty"
)

const (
	terminalLineWidth       = 100
	appendProgressBytesStep = 256 * 1000 * 1000
)

type downloadProgressRenderMode uint8

const (
	downloadProgressUpdate downloadProgressRenderMode = iota
	downloadProgressFinal
)

type Renderer struct {
	out                io.Writer
	tty                bool
	err                error
	activeLine         bool
	downloadStarted    time.Time
	lastTTYUpdate      time.Time
	lastPercentBucket  int64
	lastByteCheckpoint int64
	downloadComplete   bool
}

func New(out io.Writer) *Renderer {
	return NewWithTTY(out, isTerminal(out))
}

func NewWithTTY(out io.Writer, tty bool) *Renderer {
	if out == nil {
		out = io.Discard
	}
	return &Renderer{out: out, tty: tty, lastPercentBucket: -1}
}

func (r *Renderer) Err() error {
	if r == nil {
		return nil
	}
	return r.err
}

func (r *Renderer) Header() {
	r.line("Kontext • Starting local guard")
	r.line("")
}

func (r *Renderer) HandleDownloadProgress(event judge.DownloadProgress) {
	switch event.Event {
	case judge.DownloadProgressCacheCheck:
		if r.tty {
			r.replaceLine("Checking local model cache...")
			return
		}
		r.line("Checking local model cache...")
	case judge.DownloadProgressCacheHit:
		if r.tty {
			r.clearActiveLine()
		}
	case judge.DownloadProgressStart:
		if r.tty {
			r.finishActiveLine("✓ Model cache checked")
			r.line("• Downloading local judge model")
		} else {
			r.line("Downloading local judge model...")
		}
		r.downloadStarted = time.Now()
		r.lastTTYUpdate = time.Time{}
		r.lastPercentBucket = -1
		r.lastByteCheckpoint = 0
	case judge.DownloadProgressUpdate:
		r.renderDownloadProgress(event, downloadProgressUpdate)
	case judge.DownloadProgressDone:
		r.renderDownloadProgress(event, downloadProgressFinal)
		r.downloadComplete = true
		elapsed := time.Since(r.downloadStarted).Round(time.Second)
		if elapsed < 0 {
			elapsed = 0
		}
		r.printf("✓ Downloaded local judge model (%s in %s)\n", formatBytes(event.CurrentBytes), formatDuration(elapsed))
	case judge.DownloadProgressError:
		if r.tty {
			r.finishActiveLine("")
		}
		if event.Err != nil {
			r.line("✗ Failed to download local judge model")
			r.line("  Check your connection, then run `kontext guard start` again.")
		}
	}
}

func (r *Renderer) LocalJudgeReady(enabled bool, unavailable bool) {
	if r.tty {
		r.clearActiveLine()
	}
	switch LocalJudgeSummary(enabled, unavailable) {
	case "disabled":
		r.line("✓ Local judge disabled")
		return
	case "unavailable":
		r.line("✗ Local judge unavailable")
		return
	}
	if r.downloadComplete {
		r.line("✓ Local judge model ready")
		return
	}
	r.line("✓ Local judge ready")
}

func LocalJudgeSummary(enabled bool, unavailable bool) string {
	if !enabled {
		return "disabled"
	}
	if unavailable {
		return "unavailable"
	}
	return "ready"
}

func (r *Renderer) Mode(mode string) {
	if mode == "enforce" {
		r.line("✓ Mode: enforce (blocking enabled)")
	}
}

func (r *Renderer) LocalSessionReady() {
	r.line("✓ Local session ready")
}

func (r *Renderer) Launching(agent string) {
	r.printf("\nLaunching %s...\n\n", agent)
}

func (r *Renderer) renderDownloadProgress(event judge.DownloadProgress, mode downloadProgressRenderMode) {
	if event.CurrentBytes <= 0 {
		return
	}
	if r.downloadStarted.IsZero() {
		r.downloadStarted = time.Now()
	}
	if r.tty {
		now := time.Now()
		if mode != downloadProgressFinal && !r.lastTTYUpdate.IsZero() && now.Sub(r.lastTTYUpdate) < 120*time.Millisecond {
			return
		}
		r.lastTTYUpdate = now
		r.replaceLine("  " + r.progressText(event))
		if mode == downloadProgressFinal {
			r.finishActiveLine("")
		}
		return
	}
	if !r.shouldPrintAppendProgress(event, mode) {
		return
	}
	if event.TotalBytes > 0 {
		r.printf("Progress: %s / %s (%d%%)\n", formatBytes(event.CurrentBytes), formatBytes(event.TotalBytes), percent(event.CurrentBytes, event.TotalBytes))
		return
	}
	r.printf("Progress: %s downloaded\n", formatBytes(event.CurrentBytes))
}

func (r *Renderer) progressText(event judge.DownloadProgress) string {
	elapsed := time.Since(r.downloadStarted)
	speed := 0.0
	if elapsed > 0 {
		speed = float64(event.CurrentBytes) / elapsed.Seconds()
		if speed < 0 {
			speed = 0
		}
	}
	if event.TotalBytes > 0 {
		remaining := event.TotalBytes - event.CurrentBytes
		eta := time.Duration(0)
		if speed > 0 && remaining > 0 {
			eta = time.Duration(float64(remaining)/speed) * time.Second
		}
		return fmt.Sprintf("%s / %s  %d%%  %s/s  ETA %s", formatBytes(event.CurrentBytes), formatBytes(event.TotalBytes), percent(event.CurrentBytes, event.TotalBytes), formatBytes(int64(speed)), formatDuration(eta))
	}
	return fmt.Sprintf("%s downloaded  %s/s", formatBytes(event.CurrentBytes), formatBytes(int64(speed)))
}

func (r *Renderer) shouldPrintAppendProgress(event judge.DownloadProgress, mode downloadProgressRenderMode) bool {
	if mode == downloadProgressFinal {
		return true
	}
	if event.TotalBytes > 0 {
		pct := percent(event.CurrentBytes, event.TotalBytes)
		bucket := pct / 10
		if bucket > r.lastPercentBucket {
			r.lastPercentBucket = bucket
			return true
		}
		return false
	}
	if event.CurrentBytes-r.lastByteCheckpoint >= appendProgressBytesStep {
		r.lastByteCheckpoint = event.CurrentBytes
		return true
	}
	return false
}

func (r *Renderer) replaceLine(text string) {
	r.writeTerminalLine(text, false)
	r.activeLine = true
}

func (r *Renderer) finishActiveLine(text string) {
	if !r.activeLine {
		if text != "" {
			r.line(text)
		}
		return
	}
	if text == "" {
		r.writeTerminalLine("", false)
	} else {
		r.writeTerminalLine(text, true)
	}
	r.activeLine = false
}

func (r *Renderer) clearActiveLine() {
	if !r.activeLine {
		return
	}
	r.writeTerminalLine("", false)
	r.activeLine = false
}

func (r *Renderer) writeTerminalLine(text string, newline bool) {
	if newline {
		r.printf("\r%-*s\n", terminalLineWidth, text)
		return
	}
	r.printf("\r%-*s\r", terminalLineWidth, text)
}

func (r *Renderer) line(text string) {
	_, err := fmt.Fprintln(r.out, text)
	r.recordWrite(err)
}

func (r *Renderer) printf(format string, args ...any) {
	_, err := fmt.Fprintf(r.out, format, args...)
	r.recordWrite(err)
}

func (r *Renderer) recordWrite(err error) {
	if err != nil && r.err == nil {
		r.err = err
	}
}

func formatBytes(bytes int64) string {
	if bytes < 0 {
		bytes = 0
	}
	units := []string{"B", "KB", "MB", "GB", "TB"}
	value := float64(bytes)
	unit := 0
	for value >= 1000 && unit < len(units)-1 {
		value /= 1000
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d %s", bytes, units[unit])
	}
	return fmt.Sprintf("%.1f %s", value, units[unit])
}

func percent(current, total int64) int64 {
	if total <= 0 || current <= 0 {
		return 0
	}
	pct := current * 100 / total
	if pct > 100 {
		return 100
	}
	return pct
}

func formatDuration(duration time.Duration) string {
	if duration < 0 {
		duration = 0
	}
	seconds := int64(duration.Round(time.Second).Seconds())
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	minutes := seconds / 60
	seconds = seconds % 60
	if minutes < 60 {
		return fmt.Sprintf("%dm%02ds", minutes, seconds)
	}
	hours := minutes / 60
	minutes = minutes % 60
	return fmt.Sprintf("%dh%02dm", hours, minutes)
}

func isTerminal(out io.Writer) bool {
	file, ok := out.(*os.File)
	return ok && isatty.IsTerminal(file.Fd())
}
