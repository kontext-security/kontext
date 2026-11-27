package managedobserve

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/hermetic"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/localruntime"
)

func TestTurnEndAsksForAnUploadOnlyWhenATurnOrSessionEnds(t *testing.T) {
	for _, tt := range []struct {
		name hook.HookName
		want bool
	}{
		{hook.HookStop, true},
		{hook.HookSessionEnd, true},
		{hook.HookSessionStart, false},
		{hook.HookUserPromptSubmit, false},
		{hook.HookPreToolUse, false},
		{hook.HookPostToolUse, false},
		// A subagent ending is not the turn ending: its Stop follows.
		{hook.HookSubagentStop, false},
	} {
		t.Run(string(tt.name), func(t *testing.T) {
			turn := newTurnEnd()
			turn.observe(hook.Event{HookName: tt.name})
			select {
			case <-turn.now:
				if !tt.want {
					t.Fatal("asked for an upload")
				}
			default:
				if tt.want {
					t.Fatal("did not ask for an upload")
				}
			}
		})
	}
}

func TestTurnEndRequestsCoalesce(t *testing.T) {
	turn := newTurnEnd()
	for range 5 {
		turn.observe(hook.Event{HookName: hook.HookStop})
	}
	<-turn.now
	select {
	case <-turn.now:
		t.Fatal("five turn ends in a row asked for more than one upload")
	default:
	}
}

func TestTurnEndWaitsForRecordsStillBeingWritten(t *testing.T) {
	var pending atomic.Int64
	pending.Store(3)
	turn := newTurnEnd()
	turn.pending = func() int { return int(pending.Load()) }
	turn.settle = 10 * time.Second

	done := make(chan struct{})
	go func() {
		defer close(done)
		turn.wait(context.Background())
	}()
	select {
	case <-done:
		t.Fatal("wait returned while records were still being written")
	case <-time.After(60 * time.Millisecond):
	}
	pending.Store(0)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("wait did not return once the records were written")
	}
}

func TestTurnEndWaitIsBounded(t *testing.T) {
	turn := newTurnEnd()
	turn.pending = func() int { return 1 }
	turn.settle = 30 * time.Millisecond

	done := make(chan struct{})
	go func() {
		defer close(done)
		turn.wait(context.Background())
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("wait outlived its settle time for a record that never lands")
	}
}

// turnEndCloud keeps the body of every upload, so a test can tell which
// upload carried a tool call.
type turnEndCloud struct {
	enrolmentCloud
	mu      sync.Mutex
	uploads [][]byte
}

func (c *turnEndCloud) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "authorization-ledger") {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.uploads = append(c.uploads, body)
		c.mu.Unlock()
	}
	c.enrolmentCloud.ServeHTTP(w, r)
}

// carried reports whether an upload so far names the tool call.
func (c *turnEndCloud) carried(toolUseID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, body := range c.uploads {
		if bytes.Contains(body, []byte(toolUseID)) {
			return true
		}
	}
	return false
}

// The upload timer never fires in this test, so the turn's tool call can only
// reach the cloud because the turn ended. A post alone proves nothing: an
// upload that left the tool call on disk would also be a post.
func TestTurnEndUploadsWithoutWaitingForTheTick(t *testing.T) {
	cloud := &turnEndCloud{enrolmentCloud: enrolmentCloud{alwaysEnrolled: true}}
	ctx, cancel := context.WithCancel(context.Background())
	dir := daemonDir(t)
	server := httptest.NewTLSServer(cloud)
	t.Cleanup(server.Close)
	writeTestManagedConfigWithCloudURL(t, filepath.Join(dir, "managed.json"), server.URL)
	writeTestInstallation(t, filepath.Join(dir, "installation.json"))
	socketPath := filepath.Join(hermetic.SocketDir(t), "kontext.sock")

	errCh := make(chan error, 1)
	go func() {
		errCh <- RunDaemon(ctx, DaemonOptions{
			SocketPath:                    socketPath,
			DBPath:                        filepath.Join(dir, "guard.db"),
			IdleTimeout:                   time.Hour,
			StreamInterval:                time.Hour,
			StreamHTTPClient:              server.Client(),
			PolicyRefreshInterval:         time.Hour,
			PolicyHTTPClient:              server.Client(),
			EndpointConfigRefreshInterval: time.Hour,
			EndpointConfigHTTPClient:      server.Client(),
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("RunDaemon() error = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("RunDaemon did not stop")
		}
	})

	// The daemon uploads once as it starts.
	waitForPosts(t, &cloud.enrolmentCloud)
	time.Sleep(200 * time.Millisecond)
	afterStart := cloud.posts.Load()

	client := localruntime.NewClient(socketPath)
	client.Timeout = testRuntimeTimeout
	send := func(name hook.HookName, toolUseID string) {
		t.Helper()
		event := hook.Event{SessionID: "turn-end-session", Agent: "claude", HookName: name, CWD: "/tmp/project"}
		if toolUseID != "" {
			event.ToolName, event.ToolUseID = "Read", toolUseID
		}
		if _, err := client.Process(context.Background(), event); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	send(hook.HookPreToolUse, "turn-end-1")
	send(hook.HookPostToolUse, "turn-end-1")

	// A tool call alone waits for the timer.
	time.Sleep(300 * time.Millisecond)
	if got := cloud.posts.Load(); got != afterStart {
		t.Fatalf("posts = %d after a tool call, want %d: only the timer or a turn end uploads", got, afterStart)
	}
	if cloud.carried("turn-end-1") {
		t.Fatal("the tool call reached the cloud before the turn ended, with the timer an hour away")
	}

	send(hook.HookStop, "")
	deadline := time.Now().Add(10 * time.Second)
	for !cloud.carried("turn-end-1") {
		if time.Now().After(deadline) {
			t.Fatalf("the turn's tool call did not reach the cloud after the turn ended, with the timer an hour away: %d uploads since the start, none with it", cloud.posts.Load()-afterStart)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
