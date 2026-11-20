package browserevents

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/fsperm"
)

var testExtension = Extension{Version: "0.1.0", Browser: "chrome", Profile: "p7Hq2vXkLm9s"}

func visit(requests int, first, last string) IndexedRecord {
	return IndexedRecord{Record: Record{Kind: KindVisit, Day: "2026-11-20", App: "chatgpt", AppName: "ChatGPT",
		Provider: "OpenAI", Surface: "web", Host: "chatgpt.com", FirstSeen: first, LastSeen: last, Requests: requests}}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := openStore(filepath.Join(t.TempDir(), "browser-activity.json"), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Bind(Binding("https://app.kontext.dev", "ins_0123456789abcdefghijklmnopqrstuv", "workspace-a")); err != nil {
		t.Fatal(err)
	}
	return s
}

func testNow() time.Time { return time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC) }

func TestReplaysAndOutOfOrderSnapshotsNeverLowerADay(t *testing.T) {
	s := openTestStore(t)
	for _, r := range []IndexedRecord{
		visit(5, "2026-11-20T08:00:00Z", "2026-11-20T10:00:00Z"),
		visit(3, "2026-11-20T09:00:00Z", "2026-11-20T09:30:00Z"), // older snapshot, late
		visit(5, "2026-11-20T08:00:00Z", "2026-11-20T10:00:00Z"), // replay
	} {
		if _, err := s.Apply(testExtension, []IndexedRecord{r}); err != nil {
			t.Fatal(err)
		}
	}
	p := s.Pending(10)
	if len(p.Records) != 1 {
		t.Fatalf("pending = %+v", p.Records)
	}
	got := p.Records[0]
	if got.Requests != 5 || got.FirstSeen != "2026-11-20T08:00:00Z" || got.LastSeen != "2026-11-20T10:00:00Z" {
		t.Fatalf("merged = %+v", got)
	}
}

func TestBrowsersAndProfilesKeepTheirOwnRows(t *testing.T) {
	s := openTestStore(t)
	edge := testExtension
	edge.Browser = "edge"
	other := testExtension
	other.Profile = "qQ1234567890"
	for _, ext := range []Extension{testExtension, edge, other} {
		if _, err := s.Apply(ext, []IndexedRecord{visit(1, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")}); err != nil {
			t.Fatal(err)
		}
	}
	if s.Len() != 3 {
		t.Fatalf("rows = %d, want 3", s.Len())
	}
}

func TestARowThatChangedInFlightIsSentAgain(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Apply(testExtension, []IndexedRecord{visit(1, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
	inFlight := s.Pending(10)
	_, _ = s.Apply(testExtension, []IndexedRecord{visit(2, "2026-11-20T08:00:00Z", "2026-11-20T08:05:00Z")})
	if err := s.Ack(inFlight); err != nil {
		t.Fatal(err)
	}
	if p := s.Pending(10); len(p.Records) != 1 || p.Records[0].Requests != 2 {
		t.Fatalf("pending after ack = %+v", p.Records)
	}
	_ = s.Ack(s.Pending(10))
	if p := s.Pending(10); len(p.Records) != 0 {
		t.Fatalf("still pending: %+v", p.Records)
	}
}

func TestOldDaysArePrunedAndRefused(t *testing.T) {
	s := openTestStore(t)
	old := visit(1, "2026-11-01T08:00:00Z", "2026-11-01T08:00:00Z")
	old.Record.Day = "2026-11-01"
	rejected, err := s.Apply(testExtension, []IndexedRecord{old})
	if err != nil {
		t.Fatal(err)
	}
	if len(rejected) != 1 || s.Len() != 0 {
		t.Fatalf("rejected = %+v, rows = %d", rejected, s.Len())
	}
}

func TestTheStoreFileIsTheUsersOnlyAndSurvivesARestart(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Apply(testExtension, []IndexedRecord{visit(4, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
	info, err := os.Stat(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if private, err := fsperm.PrivateFile(s.path, info); err != nil || !private {
		t.Fatalf("store file is not private to its owner (mode %v, err %v)", info.Mode().Perm(), err)
	}
	again, err := openStore(s.path, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if p := again.Pending(10); len(p.Records) != 1 || p.Records[0].Requests != 4 {
		t.Fatalf("after restart = %+v", p.Records)
	}
}

func TestHandlerAnswersHelloAndRecords(t *testing.T) {
	s := openTestStore(t)
	changed := 0
	h := &Handler{Store: s, CaptureMode: func() string { return CaptureFull }, Changed: func() { changed++ }}
	var hello Settings
	_ = json.Unmarshal(h.Answer(context.Background(), json.RawMessage(`{"contract":1,"type":"hello","extension":{"version":"0.1.0","browser":"chrome","profile":"p7Hq2vXkLm9s"}}`)), &hello)
	if hello.Type != TypeSettings || hello.CaptureMode != CaptureFull || hello.Paused || hello.Rejected == nil {
		t.Fatalf("hello answer = %+v", hello)
	}
	data, err := os.ReadFile(filepath.Join(fixtures, "valid", "records.json"))
	if err != nil {
		t.Fatal(err)
	}
	var answer Settings
	_ = json.Unmarshal(h.Answer(context.Background(), data), &answer)
	if answer.Accepted != 2 || len(answer.Rejected) != 0 || changed != 1 {
		t.Fatalf("records answer = %+v, changed = %d", answer, changed)
	}
}

func TestHandlerDefaultsToTheMostRestrictiveMode(t *testing.T) {
	h := &Handler{Store: openTestStore(t), CaptureMode: func() string { return "" }}
	var answer Settings
	_ = json.Unmarshal(h.Answer(context.Background(), json.RawMessage(`{"contract":1,"type":"hello","extension":{"version":"0.1.0","browser":"chrome","profile":"p7Hq2vXkLm9s"}}`)), &answer)
	if answer.CaptureMode != CaptureCommands {
		t.Fatalf("mode = %q", answer.CaptureMode)
	}
}

func TestHandlerNamesAnotherContract(t *testing.T) {
	h := &Handler{Store: openTestStore(t)}
	got := string(h.Answer(context.Background(), json.RawMessage(`{"contract":2,"type":"hello"}`)))
	if got != `{"contract":1,"type":"error","error":"unsupported_contract"}` {
		t.Fatalf("answer = %s", got)
	}
}

func newTestSender(t *testing.T, s *Store, handler http.HandlerFunc) (*Sender, *[]CloudBatch) {
	t.Helper()
	var batches []CloudBatch
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != IngestPath || r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("request %s with %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		body, _ := io.ReadAll(r.Body)
		var batch CloudBatch
		_ = json.Unmarshal(body, &batch)
		batches = append(batches, batch)
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	// The rows were recorded under this sender's enrollment.
	s.binding = Binding(server.URL, "ins_AbCdEfGhIjKlMnOpQrStUvWxYz012345", "tok")
	return &Sender{Store: s, BaseURL: server.URL, InstallationID: "ins_AbCdEfGhIjKlMnOpQrStUvWxYz012345",
		Tokens: func(context.Context) (string, error) { return "tok", nil }, HTTP: server.Client()}, &batches
}

func TestSenderAcksABatchTheCloudAnswered(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Apply(testExtension, []IndexedRecord{visit(2, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
	sender, batches := newTestSender(t, s, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"accepted":0,"rejected":[{"index":0,"reason":"requests above the cap"}]}`)
	})
	outcome, err := sender.SendOnce(context.Background())
	if outcome != Sent || err != nil {
		t.Fatalf("outcome = %v, err = %v", outcome, err)
	}
	if len(*batches) != 1 || (*batches)[0].Schema != CloudSchema || (*batches)[0].Records[0].Browser != "chrome" {
		t.Fatalf("batches = %+v", *batches)
	}
	// Rejected records are dropped, not retried.
	if outcome, _ := sender.SendOnce(context.Background()); outcome != Nothing {
		t.Fatalf("second send = %v, want Nothing", outcome)
	}
}

func TestSenderKeepsRowsWhenTheCloudCannotTakeThem(t *testing.T) {
	for status, want := range map[int]Outcome{404: NotFound, 429: Retry, 503: Retry, 401: Refused} {
		s := openTestStore(t)
		_, _ = s.Apply(testExtension, []IndexedRecord{visit(2, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
		sender, _ := newTestSender(t, s, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })
		outcome, _ := sender.SendOnce(context.Background())
		if outcome != want {
			t.Errorf("status %d: outcome = %v, want %v", status, outcome, want)
		}
		if len(s.Pending(10).Records) != 1 {
			t.Errorf("status %d: rows were dropped", status)
		}
	}
}

func TestBackoffGrowsToItsCap(t *testing.T) {
	if backoff(1) != SendDelay || backoff(2) != 2*SendDelay || backoff(20) != MaxBackoff {
		t.Fatalf("backoff = %v %v %v", backoff(1), backoff(2), backoff(20))
	}
	if !strings.Contains(IngestPath, "browser-activity") {
		t.Fatal("ingest path")
	}
}

func TestASnapshotWhoseSaveFailedIsSavedOnItsRetry(t *testing.T) {
	s := openTestStore(t)
	path := s.path
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s.path = filepath.Join(blocker, "browser-activity.json")
	snapshot := []IndexedRecord{visit(3, "2026-11-20T08:00:00Z", "2026-11-20T09:00:00Z")}
	if _, err := s.Apply(testExtension, snapshot); err == nil {
		t.Fatal("save into a file succeeded")
	}
	s.path = path
	if _, err := s.Apply(testExtension, snapshot); err != nil {
		t.Fatal(err)
	}
	again, err := openStore(path, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if again.Len() != 1 {
		t.Fatalf("the retried snapshot is not on disk: %d rows", again.Len())
	}
}

func TestExpiredDaysLeaveTheDiskWhenTheStoreOpens(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.Apply(testExtension, []IndexedRecord{visit(1, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")}); err != nil {
		t.Fatal(err)
	}
	later := func() time.Time { return testNow().Add(KeepDays * 24 * time.Hour) }
	if _, err := openStore(s.path, later); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "chatgpt") {
		t.Fatalf("an expired day is still on disk: %s", data)
	}
}

func TestMessagesCannotPostponeASend(t *testing.T) {
	start := testNow()
	plan := sendPlan{due: start.Add(SendDelay)}
	for i := 1; i <= 10; i++ {
		plan.changed(start.Add(time.Duration(i) * 10 * time.Second))
	}
	if want := start.Add(SendDelay); !plan.due.Equal(want) {
		t.Fatalf("due = %v, want %v", plan.due, want)
	}
	plan.after(Nothing, start)
	if !plan.changed(start.Add(time.Minute)) || !plan.due.Equal(start.Add(time.Minute+SendDelay)) {
		t.Fatalf("a change after an idle send did not bring it forward: %v", plan.due)
	}
}

func TestChangesDoNotCutA404OrFailureWait(t *testing.T) {
	start := testNow()
	plan := sendPlan{}
	plan.after(NotFound, start)
	if plan.changed(start.Add(time.Minute)) || !plan.due.Equal(start.Add(NotFoundBackoff)) {
		t.Fatalf("a change cut the 404 wait: %v", plan.due)
	}
	plan.after(Retry, start)
	if plan.changed(start.Add(time.Second)) || !plan.due.Equal(start.Add(backoff(1))) {
		t.Fatalf("a change cut the failure wait: %v", plan.due)
	}
	plan.after(Sent, start)
	if plan.holding || plan.failures != 0 {
		t.Fatalf("a sent batch kept the wait: %+v", plan)
	}
}

func TestRowsNeverLeaveUnderAnotherEnrollment(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.Apply(testExtension, []IndexedRecord{visit(2, "2026-11-20T08:00:00Z", "2026-11-20T09:00:00Z")}); err != nil {
		t.Fatal(err)
	}
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		bodies = append(bodies, r.Header.Get("Authorization")+" "+string(data))
		_, _ = w.Write([]byte(`{"accepted":1,"rejected":[]}`))
	}))
	defer server.Close()
	token := "workspace-a"
	sender := &Sender{Store: s, BaseURL: server.URL, InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		Tokens: func(context.Context) (string, error) { return token, nil }, HTTP: server.Client(), now: testNow}
	// The first row was recorded under workspace A's enrollment.
	s.binding = Binding(server.URL, sender.InstallationID, token)
	// Workspace A's rows go with workspace A's token.
	if outcome, err := sender.SendOnce(context.Background()); outcome != Sent || err != nil {
		t.Fatalf("first send = %v, %v", outcome, err)
	}
	if _, err := s.Apply(testExtension, []IndexedRecord{visit(5, "2026-11-20T08:00:00Z", "2026-11-20T10:00:00Z")}); err != nil {
		t.Fatal(err)
	}
	// Another workspace's token at the same address: the pending row is dropped, not sent.
	token = "workspace-b"
	if outcome, _ := sender.SendOnce(context.Background()); outcome != Nothing {
		t.Fatalf("send under a new enrollment = %v, want Nothing", outcome)
	}
	if len(bodies) != 1 || !strings.HasPrefix(bodies[0], "Bearer workspace-a ") {
		t.Fatalf("requests = %q", bodies)
	}
	again, err := openStore(s.path, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if again.Len() != 0 {
		t.Fatalf("rows of the old enrollment are still on disk: %d", again.Len())
	}
}

func TestFailedUploadsWarnFirstThenHourly(t *testing.T) {
	var warnings int
	sender := &Sender{Warnf: func(string, ...any) { warnings++ }}
	start := testNow()
	for i, at := range []time.Duration{0, time.Minute, 30 * time.Minute, WarnEvery, WarnEvery + time.Minute} {
		sender.warn(i+1, start.Add(at), io.EOF)
	}
	if warnings != 2 {
		t.Fatalf("warnings = %d, want the first and one an hour later", warnings)
	}
}

func TestAnUnboundStoreTakesNoRecords(t *testing.T) {
	s, err := openStore(filepath.Join(t.TempDir(), "browser-activity.json"), testNow)
	if err != nil {
		t.Fatal(err)
	}
	rejected, err := s.Apply(testExtension, []IndexedRecord{visit(1, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
	if err != nil || len(rejected) != 1 || s.Len() != 0 {
		t.Fatalf("rejected = %+v, rows = %d, err = %v", rejected, s.Len(), err)
	}
	if rejected[0].Reason != "daemon is not enrolled yet" {
		t.Fatalf("reason = %q", rejected[0].Reason)
	}
}

func TestTheSenderBindsAnUnboundStore(t *testing.T) {
	s, err := openStore(filepath.Join(t.TempDir(), "browser-activity.json"), testNow)
	if err != nil {
		t.Fatal(err)
	}
	sender := &Sender{Store: s, BaseURL: "https://app.kontext.dev", InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		Tokens: func(context.Context) (string, error) { return "tok", nil }}
	if outcome, err := sender.SendOnce(context.Background()); outcome != Nothing || err != nil {
		t.Fatalf("outcome = %v, err = %v", outcome, err)
	}
	if !s.Bound() {
		t.Fatal("the store is still unbound")
	}
}

func TestAnAnswerThatDoesNotAccountForTheBatchMarksNothingSent(t *testing.T) {
	for _, answer := range []string{`{}`, `null`, `{"accepted":0,"rejected":[]}`, `{"accepted":1,"rejected":[{"index":0,"reason":"x"}]}`} {
		s := openTestStore(t)
		_, _ = s.Apply(testExtension, []IndexedRecord{visit(2, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
		sender, _ := newTestSender(t, s, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, answer) })
		if outcome, err := sender.SendOnce(context.Background()); outcome != Retry || err == nil {
			t.Errorf("%s: outcome = %v, err = %v, want Retry", answer, outcome, err)
		}
		if len(s.Pending(10).Records) != 1 {
			t.Errorf("%s: the row was marked sent", answer)
		}
	}
}

func TestATooLargeBatchIsHalvedAndATooLargeRowDropped(t *testing.T) {
	s := openTestStore(t)
	for _, app := range []string{"chatgpt", "claude", "gemini", "perplexity"} {
		r := visit(1, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")
		r.Record.App = app
		_, _ = s.Apply(testExtension, []IndexedRecord{r})
	}
	sender, batches := newTestSender(t, s, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	})
	var sizes []int
	for range 3 {
		before := len(*batches)
		outcome, _ := sender.SendOnce(context.Background())
		sizes = append(sizes, len((*batches)[before].Records))
		if len(sizes) < 3 && outcome != Retry {
			t.Fatalf("send %d: outcome = %v, want Retry", len(sizes), outcome)
		}
		if len(sizes) == 3 && outcome != Sent {
			t.Fatalf("a single oversized row: outcome = %v, want Sent", outcome)
		}
	}
	if sizes[0] != 4 || sizes[1] != 2 || sizes[2] != 1 {
		t.Fatalf("batch sizes = %v, want 4, 2, 1", sizes)
	}
	if left := len(s.Pending(10).Records); left != 3 {
		t.Fatalf("%d rows left, want the 3 behind the dropped one", left)
	}
}

func TestAPruneWithNothingToSendStillLeavesTheDisk(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Apply(testExtension, []IndexedRecord{visit(1, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
	sender, _ := newTestSender(t, s, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"accepted":1,"rejected":[]}`)
	})
	if outcome, err := sender.SendOnce(context.Background()); outcome != Sent || err != nil {
		t.Fatalf("outcome = %v, err = %v", outcome, err)
	}
	s.now = func() time.Time { return testNow().Add(KeepDays * 24 * time.Hour) }
	if outcome, err := sender.SendOnce(context.Background()); outcome != Nothing || err != nil {
		t.Fatalf("outcome = %v, err = %v, want Nothing", outcome, err)
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "chatgpt") {
		t.Fatalf("an expired, already sent day is still on disk: %s", data)
	}
}

func TestADamagedStoreWithNullRowsOpens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "browser-activity.json")
	if err := os.WriteFile(path, []byte(`{"binding":"b","rows":{"x":null}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := openStore(path, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if s.Len() != 0 {
		t.Fatalf("rows = %d", s.Len())
	}
}

func TestAnOlderSnapshotKeepsTheNewerMetadata(t *testing.T) {
	s := openTestStore(t)
	upgraded := Extension{Version: "0.2.0", Browser: testExtension.Browser, Profile: testExtension.Profile}
	newer := visit(5, "2026-11-20T08:00:00Z", "2026-11-20T10:00:00Z")
	newer.Record.Host = "chat.openai.com"
	health := func(observed string) IndexedRecord {
		return IndexedRecord{Record: Record{Kind: KindHealth, ConnectedSince: "2026-11-20T07:00:00Z", ObservedAt: observed}}
	}
	_, _ = s.Apply(upgraded, []IndexedRecord{newer, health("2026-11-20T10:00:00Z")})
	older := visit(3, "2026-11-20T08:00:00Z", "2026-11-20T09:00:00Z")
	_, _ = s.Apply(testExtension, []IndexedRecord{older, health("2026-11-20T09:00:00Z")})
	for _, r := range s.Pending(10).Records {
		if r.ExtensionVersion != "0.2.0" {
			t.Errorf("%s: version = %s, want the newer 0.2.0", r.Kind, r.ExtensionVersion)
		}
		if r.Kind == KindVisit && r.Host != "chat.openai.com" {
			t.Errorf("visit host = %s, want the newer snapshot's", r.Host)
		}
	}
}

func TestWithoutAStoreTheHandlerAnswersUnavailable(t *testing.T) {
	answer := (&Handler{}).Answer(context.Background(), json.RawMessage(`{"contract":1,"type":"hello","extension":{"version":"0.1.0","browser":"chrome","profile":"p7Hq2vXkLm9s"}}`))
	if !strings.Contains(string(answer), `"error":"unavailable"`) {
		t.Fatalf("answer = %s", answer)
	}
}

func TestTheBatchGrowsBackAfterA413(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Apply(testExtension, []IndexedRecord{visit(1, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
	sender, _ := newTestSender(t, s, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"accepted":1,"rejected":[]}`)
	})
	sender.limit = 1
	if outcome, err := sender.SendOnce(context.Background()); outcome != Sent || err != nil {
		t.Fatalf("outcome = %v, err = %v", outcome, err)
	}
	if sender.limit != 2 {
		t.Fatalf("limit = %d after a success, want 2", sender.limit)
	}
}
