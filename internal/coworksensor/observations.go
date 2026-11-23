package coworksensor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
)

// Observation is derived from a real tool_use/tool_result pair in the mounted
// transcript. No synthetic PreToolUse or policy verdict is created.
type Observation struct {
	Source     string    `json:"source"`
	SessionID  string    `json:"session_id"`
	ToolUseID  string    `json:"tool_use_id"`
	ToolName   string    `json:"tool_name"`
	Command    string    `json:"command"`
	Failed     bool      `json:"failed"`
	ObservedAt time.Time `json:"observed_at"`
}

func (o Observation) validate() error {
	if _, err := uuid.Parse(o.SessionID); err != nil {
		return errors.New("invalid session id")
	}
	if o.Source != "cowork.vm_mounted_transcript" || o.ToolName != "mcp__workspace__bash" || len(o.ToolUseID) == 0 || len(o.ToolUseID) > 128 || len(o.Command) == 0 || len(o.Command) > 65536 || o.ObservedAt.IsZero() || o.ObservedAt.After(time.Now().Add(time.Minute)) {
		return errors.New("invalid bounded VM transcript observation")
	}
	return nil
}

func serveObservations(ctx context.Context, cfg Config, version string) (func(), error) {
	path := filepath.Join(cfg.RuntimeDir, "observations.sock")
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0666); err != nil {
		listener.Close()
		return nil, err
	}
	store, err := sqlite.OpenStore(filepath.Join(cfg.StateDir, "guard.db"))
	if err != nil {
		listener.Close()
		return nil, err
	}
	var mu sync.Mutex
	var received int
	var last string
	boot, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"installation_id": cfg.InstallationID, "version": version, "mode": "observe", "pid": os.Getpid(), "boot_id": strings.TrimSpace(string(boot)), "source": "cowork.vm_mounted_transcript", "attachment": "explicit session-side collector required", "acknowledged_messages": received, "last_action_id": last})
	})
	mux.HandleFunc("POST /observations", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
		var o Observation
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if err := d.Decode(&o); err != nil {
			http.Error(w, "invalid observation", 400)
			return
		}
		var extra any
		if d.Decode(&extra) != io.EOF || o.validate() != nil {
			http.Error(w, "invalid observation", 400)
			return
		}
		id, err := store.SaveCoworkTranscriptObservation(r.Context(), o.SessionID, o.ToolUseID, o.Command, o.Failed, o.ObservedAt)
		if err != nil {
			http.Error(w, "observation persistence failed", 500)
			return
		}
		mu.Lock()
		received++
		last = id
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"action_id": id, "installation_id": cfg.InstallationID, "capture_source": o.Source})
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
	done := make(chan struct{})
	go func() { defer close(done); _ = srv.Serve(listener) }()
	stop := context.AfterFunc(ctx, func() { _ = srv.Close() })
	return func() { stop(); _ = srv.Close(); <-done; _ = store.Close(); _ = os.Remove(path) }, nil
}

// Status queries the running VM process rather than trusting a ready file.
func Status(ctx context.Context, socket string, out io.Writer) error {
	client := observationClient(socket)
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://sensor/status", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("VM daemon status unavailable")
	}
	_, err = io.Copy(out, io.LimitReader(resp.Body, 8192))
	return err
}

func observationClient(socket string) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func postObservation(ctx context.Context, client *http.Client, o Observation) (string, error) {
	body, err := json.Marshal(o)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://sensor/observations", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("VM daemon rejected observation")
	}
	var ack struct {
		ActionID       string `json:"action_id"`
		InstallationID string `json:"installation_id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&ack); err != nil {
		return "", err
	}
	if ack.ActionID == "" || ack.InstallationID == "" {
		return "", errors.New("missing observation acknowledgement")
	}
	return ack.ActionID, nil
}
