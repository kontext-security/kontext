package managedobserve

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/cedareval"
	"github.com/kontext-security/kontext/internal/cedarpolicy"
	"github.com/kontext-security/kontext/internal/hermetic"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/localruntime"
)

const (
	forbidAllPolicy = `@id("forbid-all") forbid(principal, action, resource);`
	forbidAllSchema = `namespace Kontext {
  entity Endpoint;
  entity Agent;
  entity Tool;
  action "ToolUse" appliesTo {
    principal: [Endpoint],
    resource: [Tool],
    context: {}
  };
}`
	policyUnauthorizedBody = `{"responseVersion":2,"requestContractVersion":2,"state":"unauthorized"}`
	policyStepTimeout      = 15 * time.Second
)

// policyCloud parks every policy read until the test answers it. The next read
// arriving proves the daemon finished handling the previous answer, so each
// probe sees exactly the state that answer produced.
type policyCloud struct {
	t        *testing.T
	body     []byte
	identity string
	arrived  chan string
	replies  chan int
}

func newPolicyCloud(t *testing.T) *policyCloud {
	t.Helper()
	principal := cedareval.EvaluationPrincipal{
		EntityType: cedareval.EndpointEntityTypeV2,
		EntityID:   "ins_0123456789abcdefghijklmnopqrstuv",
	}
	policyHash := cedareval.ComputePolicyHash(forbidAllPolicy)
	schemaHash := cedareval.ComputeSchemaHash(forbidAllSchema)
	const catalog = "b28108efc334761c791b00953e51e682568faa911be4c5c9c14bab48e987b13d"
	identity, err := cedareval.ComputeDeploymentIdentityV2(cedareval.DeploymentIdentityV2Input{
		ResponseVersion:        cedarpolicy.ResponseVersion,
		RequestContractVersion: cedarpolicy.RequestContractVersion,
		PolicySetSourceHash:    policyHash,
		SchemaHash:             schemaHash,
		ToolCatalogDigest:      catalog,
		RolloutMode:            string(cedareval.RolloutModeEnforce),
		EvaluationPrincipal:    principal,
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(cedarpolicy.Deployment{
		ResponseVersion:        cedarpolicy.ResponseVersion,
		RequestContractVersion: cedarpolicy.RequestContractVersion,
		PolicySet:              cedarpolicy.PolicySet{Source: forbidAllPolicy, SourceHash: policyHash},
		Schema:                 cedarpolicy.Schema{Source: forbidAllSchema, Hash: schemaHash},
		ToolCatalogDigest:      catalog,
		RolloutMode:            cedareval.RolloutModeEnforce,
		EvaluationPrincipal:    principal,
		DeploymentIdentity:     identity,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &policyCloud{t: t, body: body, identity: identity, arrived: make(chan string), replies: make(chan int)}
}

func (c *policyCloud) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasSuffix(r.URL.Path, "/policy") {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	select {
	case c.arrived <- r.Header.Get("If-None-Match"):
	case <-r.Context().Done():
		return
	}
	var status int
	select {
	case status = <-c.replies:
	case <-r.Context().Done():
		return
	}
	w.Header().Set("ETag", `"`+c.identity+`"`)
	switch status {
	case http.StatusOK:
		_, _ = w.Write(c.body)
	case http.StatusUnauthorized:
		w.WriteHeader(status)
		_, _ = w.Write([]byte(policyUnauthorizedBody))
	default:
		w.WriteHeader(status)
	}
}

// awaitRead waits for the daemon's next policy read and returns its conditional header.
func (c *policyCloud) awaitRead() string {
	c.t.Helper()
	select {
	case conditional := <-c.arrived:
		return conditional
	case <-time.After(policyStepTimeout):
		c.t.Fatal("the daemon made no policy read")
		return ""
	}
}

// answer replies to the parked read and returns once the daemon has handled it.
func (c *policyCloud) answer(status int) string {
	c.t.Helper()
	select {
	case c.replies <- status:
	case <-time.After(policyStepTimeout):
		c.t.Fatal("no policy read is waiting for an answer")
	}
	return c.awaitRead()
}

type policyDaemon struct {
	t          *testing.T
	cloud      *policyCloud
	server     *httptest.Server
	dir        string
	socketPath string
	probes     int
	stop       func()
}

func startPolicyDaemon(t *testing.T, mode string) *policyDaemon {
	t.Helper()
	cloud := newPolicyCloud(t)
	server := httptest.NewTLSServer(cloud)
	t.Cleanup(server.Close)
	dir := daemonDir(t)
	configPath := filepath.Join(dir, "managed.json")
	writeTestManagedConfigWithCloudURL(t, configPath, server.URL)
	config, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	config = bytes.Replace(config, []byte(`"mode": "observe"`), []byte(`"mode": "`+mode+`"`), 1)
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	writeTestInstallation(t, filepath.Join(dir, "installation.json"))
	daemon := &policyDaemon{
		t: t, cloud: cloud, server: server, dir: dir,
		socketPath: filepath.Join(hermetic.SocketDir(t), "kontext.sock"),
	}
	daemon.start()
	return daemon
}

// start runs a daemon over the same state directory, as a process restart does.
func (d *policyDaemon) start() {
	d.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- RunDaemon(ctx, DaemonOptions{
			SocketPath:                    d.socketPath,
			DBPath:                        filepath.Join(d.dir, "guard.db"),
			IdleTimeout:                   time.Hour,
			StreamHTTPClient:              d.server.Client(),
			PolicyRefreshInterval:         20 * time.Millisecond,
			PolicyHTTPClient:              d.server.Client(),
			EndpointConfigRefreshInterval: time.Hour,
			EndpointConfigHTTPClient:      d.server.Client(),
		})
	}()
	stopped := false
	d.stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				d.t.Fatalf("RunDaemon() error = %v", err)
			}
		case <-time.After(policyStepTimeout):
			d.t.Fatal("RunDaemon did not stop")
		}
	}
	d.t.Cleanup(d.stop)
	d.cloud.awaitRead()
	waitForSocket(d.t, d.socketPath, errCh)
}

func (d *policyDaemon) restart() {
	d.t.Helper()
	d.stop()
	d.start()
}

func (d *policyDaemon) cachePath() string {
	return cedarpolicy.DefaultCachePathForDB(filepath.Join(d.dir, "guard.db"))
}

// expect sends a real PreToolUse hook over the daemon socket and checks the decision.
func (d *policyDaemon) expect(step string, want hook.Decision, wantReasonCode string) {
	d.t.Helper()
	d.probes++
	client := localruntime.NewClient(d.socketPath)
	client.Timeout = testRuntimeTimeout
	result, err := client.Process(context.Background(), hook.Event{
		SessionID: fmt.Sprintf("policy-401-%d", d.probes),
		Agent:     "claude",
		HookName:  hook.HookPreToolUse,
		ToolName:  "Read",
		CWD:       "/tmp/project",
	})
	if err != nil {
		d.t.Fatalf("%s: Process() error = %v", step, err)
	}
	d.t.Logf("%-46s %-6s %s", step, result.Decision, result.ReasonCode)
	if result.Decision != want || (wantReasonCode != "" && result.ReasonCode != wantReasonCode) {
		d.t.Fatalf("%s: decision = %q reason_code = %q (%s), want %q %q", step, result.Decision, result.ReasonCode, result.Reason, want, wantReasonCode)
	}
}

func notReady() string { return string(cedareval.ReasonEnforcementNotReady) }

func forEachEnforcingMode(t *testing.T, run func(t *testing.T, mode string)) {
	for _, mode := range []string{"enforce", "remote"} {
		t.Run(mode, func(t *testing.T) { run(t, mode) })
	}
}

func TestPolicy401StreakUnderForbidAllEnforcement(t *testing.T) {
	forEachEnforcingMode(t, func(t *testing.T, mode string) {
		d := startPolicyDaemon(t, mode)
		cloud := d.cloud
		wantConditional := `"` + cloud.identity + `"`

		cloud.answer(http.StatusOK)
		d.expect("policy installed, before any 401", hook.DecisionDeny, "")
		persisted, err := os.ReadFile(d.cachePath())
		if err != nil {
			t.Fatal(err)
		}

		cloud.answer(http.StatusUnauthorized)
		d.expect("401 1 of 3", hook.DecisionDeny, "")
		conditional := cloud.answer(http.StatusUnauthorized)
		d.expect("401 2 of 3", hook.DecisionDeny, "")
		if conditional != wantConditional {
			t.Fatalf("conditional header after held 401s = %q, want %q", conditional, wantConditional)
		}
		afterHold, err := os.ReadFile(d.cachePath())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(persisted, afterHold) {
			t.Fatalf("held 401s rewrote the persisted policy:\nbefore %s\nafter  %s", persisted, afterHold)
		}

		cloud.answer(http.StatusNotModified)
		d.expect("304 after a partial streak", hook.DecisionDeny, "")

		cloud.answer(http.StatusUnauthorized)
		d.expect("401 1 of 3 again, count was reset", hook.DecisionDeny, "")
		cloud.answer(http.StatusUnauthorized)
		d.expect("401 2 of 3 again", hook.DecisionDeny, "")
		cloud.answer(http.StatusUnauthorized)
		d.expect("401 3 of 3, threshold reached", hook.DecisionAllow, notReady())

		cloud.answer(http.StatusUnauthorized)
		d.expect("401 after the drop", hook.DecisionAllow, notReady())

		if conditional := cloud.answer(http.StatusNotModified); conditional != wantConditional {
			t.Fatalf("conditional header after the drop = %q, want %q", conditional, wantConditional)
		}
		d.expect("304 after the drop restores the policy", hook.DecisionDeny, "")
	})
}

func TestPolicy401StreakIgnoresOutagesBetweenRejections(t *testing.T) {
	d := startPolicyDaemon(t, "enforce")
	d.cloud.answer(http.StatusOK)

	d.cloud.answer(http.StatusUnauthorized)
	d.expect("401 1 of 3", hook.DecisionDeny, "")
	d.cloud.answer(http.StatusInternalServerError)
	d.expect("500 neither counts nor resets", hook.DecisionDeny, "")
	d.cloud.answer(http.StatusUnauthorized)
	d.expect("401 2 of 3", hook.DecisionDeny, "")
	d.cloud.answer(http.StatusUnauthorized)
	d.expect("401 3 of 3 across the outage", hook.DecisionAllow, notReady())
}

// Each start reads the policy at once, so a daemon that keeps restarting still
// reaches the threshold within three reads.
func TestPolicy401StreakSurvivesDaemonRestarts(t *testing.T) {
	forEachEnforcingMode(t, func(t *testing.T, mode string) {
		d := startPolicyDaemon(t, mode)
		d.cloud.answer(http.StatusOK)
		d.expect("policy installed", hook.DecisionDeny, "")

		d.cloud.answer(http.StatusUnauthorized)
		d.expect("401 1 of 3", hook.DecisionDeny, "")

		d.restart()
		d.cloud.answer(http.StatusUnauthorized)
		d.expect("restart, 401 2 of 3", hook.DecisionDeny, "")

		d.restart()
		d.cloud.answer(http.StatusUnauthorized)
		d.expect("restart, 401 3 of 3", hook.DecisionAllow, notReady())

		d.restart()
		d.cloud.answer(http.StatusInternalServerError)
		d.expect("restart keeps the drop", hook.DecisionAllow, notReady())
	})
}

func TestPolicy401ResetSurvivesDaemonRestart(t *testing.T) {
	d := startPolicyDaemon(t, "enforce")
	d.cloud.answer(http.StatusOK)
	d.cloud.answer(http.StatusUnauthorized)
	d.cloud.answer(http.StatusUnauthorized)
	d.expect("401 2 of 3", hook.DecisionDeny, "")
	d.cloud.answer(http.StatusNotModified)

	d.restart()
	d.cloud.answer(http.StatusUnauthorized)
	d.expect("restart after a reset, 401 1 of 3", hook.DecisionDeny, "")
	d.cloud.answer(http.StatusUnauthorized)
	d.expect("401 2 of 3", hook.DecisionDeny, "")
}
