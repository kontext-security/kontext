package browserevents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
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

// asApp makes r a visit to another catalog app, with that app's own names
// and first host.
func asApp(r IndexedRecord, id string) IndexedRecord {
	app := catalog[id]
	r.Record.App, r.Record.AppName, r.Record.Provider = app.ID, app.Name, app.Provider
	r.Record.Host = strings.TrimPrefix(app.Hosts[0], "*.")
	if r.Record.Host != app.Hosts[0] {
		r.Record.Host = "team." + r.Record.Host
	}
	return r
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
		if _, err := s.Apply(testExtension, s.Enrollment(), []IndexedRecord{r}); err != nil {
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
		if _, err := s.Apply(ext, s.Enrollment(), []IndexedRecord{visit(1, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")}); err != nil {
			t.Fatal(err)
		}
	}
	if s.Len() != 3 {
		t.Fatalf("rows = %d, want 3", s.Len())
	}
}

func TestARowThatChangedInFlightIsSentAgain(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{visit(1, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
	inFlight := s.Pending(10)
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{visit(2, "2026-11-20T08:00:00Z", "2026-11-20T08:05:00Z")})
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
	applied, err := s.Apply(testExtension, s.Enrollment(), []IndexedRecord{old})
	rejected := applied.Rejected
	if err != nil {
		t.Fatal(err)
	}
	if len(rejected) != 1 || s.Len() != 0 {
		t.Fatalf("rejected = %+v, rows = %d", rejected, s.Len())
	}
}

func TestTheStoreFileIsTheUsersOnlyAndSurvivesARestart(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{visit(4, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
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
	_ = json.Unmarshal(h.Answer(context.Background(), json.RawMessage(`{"contract":2,"type":"hello","extension":{"version":"0.1.0","browser":"chrome","profile":"p7Hq2vXkLm9s"}}`)), &hello)
	if hello.Type != TypeSettings || hello.CaptureMode != CaptureFull || hello.Paused || hello.Rejected == nil {
		t.Fatalf("hello answer = %+v", hello)
	}
	// The extension reads accounts only for a daemon that says it takes them.
	if !slices.Contains(hello.RecordKinds, KindAccount) {
		t.Fatalf("record kinds = %v, want the account kind", hello.RecordKinds)
	}
	data, err := os.ReadFile(filepath.Join(fixtures, "valid", "records.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The fixture's visit was recorded under this store's enrollment.
	data = []byte(strings.Replace(string(data), "3f9a1c2b7d4e6f80", hello.Enrollment, 1))
	var answer Settings
	_ = json.Unmarshal(h.Answer(context.Background(), data), &answer)
	if answer.Accepted != 2 || len(answer.Rejected) != 0 || changed != 1 {
		t.Fatalf("records answer = %+v, changed = %d", answer, changed)
	}
}

// Records counted under one enrollment are refused under another: the
// extension's cumulative snapshot from workspace A must not reach B. The
// answer names the current enrollment, so the extension switches to it.
func TestAVisitRecordedForAnotherEnrollmentIsRefused(t *testing.T) {
	s := openTestStore(t)
	h := &Handler{Store: s}
	data, err := os.ReadFile(filepath.Join(fixtures, "valid", "records.json"))
	if err != nil {
		t.Fatal(err)
	}
	var answer Settings
	_ = json.Unmarshal(h.Answer(context.Background(), data), &answer)
	if answer.Accepted != 0 || len(answer.Rejected) != 2 || answer.Enrollment != s.Enrollment() {
		t.Fatalf("answer = %+v", answer)
	}
	if s.Len() != 0 {
		t.Fatal("a record from another enrollment was kept")
	}
	missing := strings.Replace(string(data), `"enrollment": "3f9a1c2b7d4e6f80",`, "", 1)
	if got := string(h.Answer(context.Background(), json.RawMessage(missing))); !strings.Contains(got, ErrorInvalidMessage) {
		t.Fatalf("records without an enrollment id: %s", got)
	}
}

func TestHandlerDefaultsToTheMostRestrictiveMode(t *testing.T) {
	h := &Handler{Store: openTestStore(t), CaptureMode: func() string { return "" }}
	var answer Settings
	_ = json.Unmarshal(h.Answer(context.Background(), json.RawMessage(`{"contract":2,"type":"hello","extension":{"version":"0.1.0","browser":"chrome","profile":"p7Hq2vXkLm9s"}}`)), &answer)
	if answer.CaptureMode != CaptureCommands {
		t.Fatalf("mode = %q", answer.CaptureMode)
	}
}

func TestHandlerNamesAnotherContract(t *testing.T) {
	h := &Handler{Store: openTestStore(t)}
	got := string(h.Answer(context.Background(), json.RawMessage(`{"contract":1,"type":"hello"}`)))
	if got != `{"contract":2,"type":"error","error":"unsupported_contract"}` {
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
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{visit(2, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
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

// The endpoint's clock runs ahead of the cloud's: the cloud refuses the
// account as in the future. The row stays pending and goes again after its
// own backoff, growing with each refusal, and meanwhile the rows behind it
// are sent, even when it fills a batch on its own.
func TestARowAheadOfTheCloudsClockIsSentAgain(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{
		visit(2, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z"),
		account(AccountPersonal, "2026-11-20T09:00:00Z"),
	})
	ahead := true
	var batches *[]CloudBatch
	var sender *Sender
	sender, batches = newTestSender(t, s, func(w http.ResponseWriter, _ *http.Request) {
		batch := (*batches)[len(*batches)-1]
		var rejected []string
		for i, record := range batch.Records {
			if ahead && record.Kind == KindAccount {
				rejected = append(rejected, fmt.Sprintf(`{"index":%d,"reason":"account observed_at in the future"}`, i))
			}
		}
		_, _ = fmt.Fprintf(w, `{"accepted":%d,"rejected":[%s]}`, len(batch.Records)-len(rejected), strings.Join(rejected, ","))
	})
	clock := testNow()
	sender.now = func() time.Time { return clock }
	// One record per batch: the account comes first and fills it.
	sender.limit = 1
	send := func(want Outcome) {
		t.Helper()
		if outcome, err := sender.SendOnce(context.Background()); outcome != want {
			t.Fatalf("send = %v, %v, want %v", outcome, err, want)
		}
	}
	kinds := func() []string {
		var got []string
		for _, b := range *batches {
			for _, r := range b.Records {
				got = append(got, r.Kind)
			}
		}
		return got
	}
	send(Sent) // the account, refused
	send(Sent) // the visit behind it, taken
	send(Nothing)
	if due, ok := sender.heldDue(); !ok || !due.Equal(clock.Add(SendDelay)) {
		t.Fatalf("held due = %v, %v, want %v", due, ok, clock.Add(SendDelay))
	}
	// Its wait is over: refused again, it waits twice as long.
	clock = clock.Add(SendDelay)
	send(Sent)
	if due, _ := sender.heldDue(); !due.Equal(clock.Add(2 * SendDelay)) {
		t.Fatalf("held due = %v, want %v", due, clock.Add(2*SendDelay))
	}
	send(Nothing)
	// The clocks agree: taken, and not sent again.
	ahead = false
	clock = clock.Add(2 * SendDelay)
	send(Sent)
	send(Nothing)
	if got := kinds(); !slices.Equal(got, []string{KindAccount, KindVisit, KindAccount, KindAccount}) {
		t.Fatalf("sent = %v", got)
	}
	if _, ok := sender.heldDue(); ok {
		t.Fatal("a row is still held")
	}
}

// A tab in use updates the row the cloud refused as in the future, with a
// later time still: the update does not cut its wait short, and the next
// refusal waits longer. A wait that ends before the next send is planned
// still brings that send forward.
func TestAnUpdatedRowAheadOfTheCloudKeepsItsWait(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{account(AccountPersonal, "2026-11-20T09:00:00Z")})
	var batches *[]CloudBatch
	var sender *Sender
	sender, batches = newTestSender(t, s, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"accepted":0,"rejected":[{"index":0,"reason":"account observed_at in the future"}]}`)
	})
	clock := testNow()
	sender.now = func() time.Time { return clock }
	send := func(want Outcome) {
		t.Helper()
		if outcome, err := sender.SendOnce(context.Background()); outcome != want {
			t.Fatalf("send = %v, %v, want %v", outcome, err, want)
		}
	}
	send(Sent) // refused: waits SendDelay
	clock = clock.Add(SendDelay / 2)
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{account(AccountPersonal, "2026-11-20T09:30:00Z")})
	send(Nothing)
	if len(*batches) != 1 {
		t.Fatalf("the updated row went before its wait ended: %d batches", len(*batches))
	}
	due, ok := sender.heldDue()
	if !ok || !due.Equal(testNow().Add(SendDelay)) {
		t.Fatalf("held due = %v, %v, want %v", due, ok, testNow().Add(SendDelay))
	}
	// The wait ends before the next send is planned: it is still due then.
	clock = clock.Add(SendDelay)
	if again, ok := sender.heldDue(); !ok || !again.Equal(due) {
		t.Fatalf("held due after its wait = %v, %v, want %v", again, ok, due)
	}
	send(Sent) // refused a second time: waits twice as long
	if due, _ := sender.heldDue(); !due.Equal(clock.Add(2 * SendDelay)) {
		t.Fatalf("held due = %v, want %v", due, clock.Add(2*SendDelay))
	}
}

// A hold names the binding it was refused under: the same key under another
// binding, or a later binding of the same store, is another row.
func TestAHoldBelongsToItsBinding(t *testing.T) {
	record := CloudRecord{Record: account(AccountPersonal, "2026-11-20T09:00:00Z").Record}
	h := heldRow{binding: "a", generation: 1, latest: latestTime(record)}
	if !h.covers("a", 1, record) {
		t.Fatal("the hold does not cover its own row")
	}
	if h.covers("b", 1, record) || h.covers("a", 2, record) {
		t.Fatal("the hold covers a row of another binding")
	}
	earlier := record
	earlier.ObservedAt = "2026-11-20T08:00:00Z"
	if h.covers("a", 1, earlier) {
		t.Fatal("the hold covers the row once its time is earlier")
	}
}

func TestSenderKeepsRowsWhenTheCloudCannotTakeThem(t *testing.T) {
	for status, want := range map[int]Outcome{404: NotFound, 429: Retry, 503: Retry, 401: Refused} {
		s := openTestStore(t)
		_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{visit(2, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
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
	if _, err := s.Apply(testExtension, s.Enrollment(), snapshot); err == nil {
		t.Fatal("save into a file succeeded")
	}
	s.path = path
	if _, err := s.Apply(testExtension, s.Enrollment(), snapshot); err != nil {
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
	if _, err := s.Apply(testExtension, s.Enrollment(), []IndexedRecord{visit(1, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")}); err != nil {
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
	if _, err := s.Apply(testExtension, s.Enrollment(), []IndexedRecord{visit(2, "2026-11-20T08:00:00Z", "2026-11-20T09:00:00Z")}); err != nil {
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
	if _, err := s.Apply(testExtension, s.Enrollment(), []IndexedRecord{visit(5, "2026-11-20T08:00:00Z", "2026-11-20T10:00:00Z")}); err != nil {
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
	applied, err := s.Apply(testExtension, s.Enrollment(), []IndexedRecord{visit(1, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
	rejected := applied.Rejected
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
		_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{visit(2, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
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
	for _, app := range []string{"chatgpt", "claude", "gemini", "lovable"} {
		r := visit(1, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")
		r = asApp(r, app)
		_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{r})
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
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{visit(1, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
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
	_, _ = s.Apply(upgraded, s.Enrollment(), []IndexedRecord{newer, health("2026-11-20T10:00:00Z")})
	older := visit(3, "2026-11-20T08:00:00Z", "2026-11-20T09:00:00Z")
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{older, health("2026-11-20T09:00:00Z")})
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
	answer := (&Handler{}).Answer(context.Background(), json.RawMessage(`{"contract":2,"type":"hello","extension":{"version":"0.1.0","browser":"chrome","profile":"p7Hq2vXkLm9s"}}`))
	if !strings.Contains(string(answer), `"error":"unavailable"`) {
		t.Fatalf("answer = %s", answer)
	}
}

func TestTheBatchGrowsBackAfterA413(t *testing.T) {
	s := openTestStore(t)
	for _, app := range []string{"chatgpt", "claude"} {
		r := visit(1, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")
		r = asApp(r, app)
		_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{r})
	}
	calls := 0
	sender, _ := newTestSender(t, s, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		_, _ = io.WriteString(w, `{"accepted":1,"rejected":[]}`)
	})
	if outcome, _ := sender.SendOnce(context.Background()); outcome != Retry {
		t.Fatalf("after a 413: outcome = %v, want Retry", outcome)
	}
	if sender.limit != 1 {
		t.Fatalf("limit = %d after a 413 on 2 rows, want 1", sender.limit)
	}
	if outcome, err := sender.SendOnce(context.Background()); outcome != Sent || err != nil {
		t.Fatalf("outcome = %v, err = %v", outcome, err)
	}
	if sender.limit != 2 {
		t.Fatalf("limit = %d after a success, want 2", sender.limit)
	}
}

// Rows in a file without a binding cannot say which workspace recorded them,
// so they are not given to the enrollment the store is bound to next.
func TestRowsWithoutABindingAreNotRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "browser-activity.json")
	file := `{"rows":{"chrome|p7Hq2vXkLm9s|health":{"record":{"browser":"chrome","profile":"p7Hq2vXkLm9s","extension_version":"0.1.0","kind":"health","connected_since":"2026-11-20T08:00:00Z","observed_at":"2026-11-20T09:00:00Z"},"version":1,"sent":0}}}`
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := openStore(path, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Bind("current"); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 0 {
		t.Fatalf("an unbound row was kept for the current enrollment: %d rows", s.Len())
	}
}

func TestTheHealthOfAProfileNotSeenForAWeekExpires(t *testing.T) {
	s := openTestStore(t)
	health := IndexedRecord{Record: Record{Kind: KindHealth, ConnectedSince: "2026-11-01T08:00:00Z", ObservedAt: "2026-11-12T11:00:00Z"}}
	fresh := IndexedRecord{Index: 1, Record: Record{Kind: KindHealth, ConnectedSince: "2026-11-20T08:00:00Z", ObservedAt: "2026-11-20T11:00:00Z"}}
	other := testExtension
	other.Profile = "freshProfile1"
	if _, err := s.Apply(testExtension, s.Enrollment(), []IndexedRecord{health}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Apply(other, s.Enrollment(), []IndexedRecord{fresh}); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 1 {
		t.Fatalf("rows = %d, want only the profile seen this week", s.Len())
	}
}

func TestTheEnrollmentIdChangesWithTheBindingAndHidesIt(t *testing.T) {
	s, err := openStore(filepath.Join(t.TempDir(), "browser-activity.json"), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if s.Enrollment() != "" {
		t.Fatal("an unbound store has an enrollment id")
	}
	a := Binding("https://app.kontext.dev", "ins_0123456789abcdefghijklmnopqrstuv", "workspace-a")
	_, _ = s.Bind(a)
	first := s.Enrollment()
	_, _ = s.Bind(Binding("https://app.kontext.dev", "ins_0123456789abcdefghijklmnopqrstuv", "workspace-b"))
	second := s.Enrollment()
	if len(first) != 16 || len(second) != 16 || first == second || strings.Contains(a, first) {
		t.Fatalf("enrollment ids %q and %q", first, second)
	}
	handler := &Handler{Store: s}
	answer := handler.Answer(context.Background(), json.RawMessage(`{"contract":2,"type":"hello","extension":{"version":"0.1.0","browser":"chrome","profile":"p7Hq2vXkLm9s"}}`))
	if !strings.Contains(string(answer), `"enrollment":"`+second+`"`) {
		t.Fatalf("hello answer without the enrollment: %s", answer)
	}
}

// A stored row the contract no longer allows is dropped alone; the valid
// rows of its batch are still sent.
func TestAnInvalidStoredRowDoesNotTakeItsBatchWithIt(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{visit(2, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
	bad := visit(3, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")
	bad = asApp(bad, "claude")
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{bad})
	for _, r := range s.rows {
		if r.Record.App == "claude" {
			r.Record.AppName = "a stored name: no longer allowed?"
		}
	}
	sender, batches := newTestSender(t, s, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"accepted":1,"rejected":[]}`)
	})
	if outcome, err := sender.SendOnce(context.Background()); outcome != Sent || err != nil {
		t.Fatalf("outcome = %v, err = %v", outcome, err)
	}
	if len(*batches) != 1 || len((*batches)[0].Records) != 1 || (*batches)[0].Records[0].App != "chatgpt" {
		t.Fatalf("batches = %+v", *batches)
	}
	if outcome, _ := sender.SendOnce(context.Background()); outcome != Nothing {
		t.Fatalf("second send = %v, want Nothing", outcome)
	}
}

// A redirect would carry the batch and installation id elsewhere.
func TestTheSenderDoesNotFollowRedirects(t *testing.T) {
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the batch followed a redirect")
	}))
	t.Cleanup(elsewhere.Close)
	s := openTestStore(t)
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{visit(2, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
	sender, _ := newTestSender(t, s, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+IngestPath, http.StatusTemporaryRedirect)
	})
	if outcome, _ := sender.SendOnce(context.Background()); outcome != Refused {
		t.Fatalf("outcome = %v, want Refused", outcome)
	}
	if len(s.Pending(10).Records) != 1 {
		t.Fatal("rows were dropped")
	}
}

func TestAStoreThatIsNotAFileIsRefusedWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "browser-activity.json")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := openStore(path, testNow); err == nil {
		t.Fatal("a folder opened as the store")
	}
}

func TestTwoDatabasesInOneFolderKeepTheirOwnStores(t *testing.T) {
	dir := filepath.Join("data")
	a := DefaultStorePath(filepath.Join(dir, "guard.db"))
	b := DefaultStorePath(filepath.Join(dir, "other.db"))
	c := DefaultStorePath(filepath.Join(dir, "guard.sqlite"))
	if a == b || a == c || filepath.Dir(a) != dir || filepath.Base(a) != "guard.db.browser-activity.json" {
		t.Fatalf("store paths %q, %q and %q", a, b, c)
	}
}

func TestALongExtensionVersionIsRefused(t *testing.T) {
	long := `{"contract":2,"type":"hello","extension":{"version":"1.0.` + strings.Repeat("0", 64) + `","browser":"chrome","profile":"p7Hq2vXkLm9s"}}`
	if _, err := DecodeMessage([]byte(long)); err == nil {
		t.Fatal("a 70-character version was taken")
	}
}

func account(accountType, observed string) IndexedRecord {
	return IndexedRecord{Record: Record{Kind: KindAccount, Day: "2026-11-20", App: "chatgpt",
		AccountType: accountType, ObservedAt: observed}}
}

// The account fixture goes through the handler into the store and on to a
// batch the cloud schema takes. Each type seen on a day keeps its row, so a
// personal account used after a company one stays visible, and an older
// observation of a type replayed late changes nothing.
func TestAccountsKeepEachTypeSeenOnADay(t *testing.T) {
	s := openTestStore(t)
	h := &Handler{Store: s}
	data, err := os.ReadFile(filepath.Join(fixtures, "valid", "records-account.json"))
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), "3f9a1c2b7d4e6f80", s.Enrollment(), 1))
	var answer Settings
	_ = json.Unmarshal(h.Answer(context.Background(), data), &answer)
	if answer.Accepted != 4 || len(answer.Rejected) != 0 {
		t.Fatalf("answer = %+v", answer)
	}
	for _, r := range []IndexedRecord{account(AccountPersonal, "2026-11-20T11:30:00Z"), account(AccountCompany, "2026-11-20T08:00:00Z")} {
		if _, err := s.Apply(testExtension, s.Enrollment(), []IndexedRecord{r}); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]string{}
	p := s.Pending(10)
	for _, r := range p.Records {
		seen[r.App+"|"+r.AccountType] = r.ObservedAt
	}
	want := map[string]string{
		"chatgpt|company":  "2026-11-20T09:14:40Z",
		"chatgpt|personal": "2026-11-20T11:30:00Z",
		"chatgpt|none":     "2026-11-20T11:00:00Z",
		"claude|personal":  "2026-11-20T10:02:11Z",
		"claude|unknown":   "2026-11-20T12:00:00Z",
	}
	if len(p.Records) != len(want) {
		t.Fatalf("pending = %+v", p.Records)
	}
	for key, at := range want {
		if seen[key] != at {
			t.Fatalf("%s observed at %q, want %q (pending %+v)", key, seen[key], at, p.Records)
		}
	}
	batch := CloudBatch{Schema: CloudSchema, InstallationID: "ins_0123456789abcdefghijklmnopqrstuv", SentAt: "2026-11-20T12:00:00Z", Records: p.Records}
	if err := batch.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAnAccountRecordedForAnotherEnrollmentIsRefused(t *testing.T) {
	s := openTestStore(t)
	rejected, err := s.Apply(testExtension, "0000000000000000", []IndexedRecord{account(AccountCompany, "2026-11-20T09:00:00Z")})
	if err != nil {
		t.Fatal(err)
	}
	if len(rejected.Rejected) != 1 || s.Len() != 0 {
		t.Fatalf("rejected = %+v, rows = %d", rejected, s.Len())
	}
}

// An account is the type alone. A record with any other key, an address or
// a plan above all, is refused whole, and so is a field of the wrong type.
func TestAnAccountCarriesOnlyItsType(t *testing.T) {
	ok := `{"kind":"account","day":"2026-11-20","app":"claude","account_type":"personal","observed_at":"2026-11-20T09:00:00Z"`
	for name, record := range map[string]string{
		"host":         ok + `,"host":"claude.ai"}`,
		"tenant host":  strings.Replace(ok, `"claude"`, `"n8n-cloud"`, 1) + `,"host":"acme.app.n8n.cloud"}`,
		"unknown app":  strings.Replace(ok, `"claude"`, `"acme-corp"`, 1) + `}`,
		"address":      ok + `,"email":"jane@example.com"}`,
		"domain":       ok + `,"email_domain":"example.com"}`,
		"plan":         ok + `,"plan":"paid"}`,
		"null extra":   ok + `,"name":null}`,
		"type as list": strings.Replace(ok, `"personal"`, `["personal"]`, 1) + `}`,
		"plan as type": strings.Replace(ok, `"personal"`, `"paid"`, 1) + `}`,
	} {
		valid, rejected, err := DecodeRecords(json.RawMessage(`[` + record + `]`))
		if err != nil || len(valid) != 0 || len(rejected) != 1 {
			t.Errorf("%s: valid = %+v, rejected = %+v, err = %v", name, valid, rejected, err)
		}
	}
	if valid, _, err := DecodeRecords(json.RawMessage(`[` + ok + `}]`)); err != nil || len(valid) != 1 {
		t.Fatalf("the plain account: %+v, %v", valid, err)
	}
	visit := visit(1, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z").Record
	visit.AccountType = AccountPersonal
	if err := visit.Validate(); err == nil {
		t.Fatal("a visit carrying an account type validated")
	}
}

// The newest account observation of a type wins its day, so one from a clock
// running ahead would hide the true ones after it. It is refused.
func TestAnAccountFromAheadOfTheClockIsRefused(t *testing.T) {
	s := openTestStore(t)
	ahead := account(AccountCompany, testNow().Add(MaxClockAhead+time.Minute).UTC().Format(time.RFC3339))
	ahead.Record.Day = testNow().UTC().Format(time.DateOnly)
	applied, err := s.Apply(testExtension, s.Enrollment(), []IndexedRecord{ahead})
	if err != nil || len(applied.Rejected) != 1 || s.Len() != 0 {
		t.Fatalf("applied = %+v, rows = %d, err = %v", applied, s.Len(), err)
	}
}

// A health row stamped far in the future would never expire, so it is refused.
func TestAHealthRowFromTheFutureIsRefused(t *testing.T) {
	s := openTestStore(t)
	future := IndexedRecord{Record: Record{Kind: KindHealth, ConnectedSince: "2026-11-20T07:00:00Z",
		ObservedAt: testNow().Add(48 * time.Hour).Format(time.RFC3339)}}
	applied, err := s.Apply(testExtension, s.Enrollment(), []IndexedRecord{future})
	if err != nil || len(applied.Rejected) != 1 || s.Len() != 0 {
		t.Fatalf("applied = %+v, rows = %d, err = %v", applied, s.Len(), err)
	}
}

// Messages are a share of the requests, merge by their maximum, and are
// never more than the requests: every send is a POST.
func TestVisitMessagesKeepTheirMaximumAndStayWithinRequests(t *testing.T) {
	s := openTestStore(t)
	// 1, then 3, then a late 1: a store that keeps the first count, or one
	// that takes a stale replay, ends on 1.
	early := visit(2, "2026-11-20T08:00:00Z", "2026-11-20T08:30:00Z")
	early.Record.Messages = 1
	first := visit(5, "2026-11-20T08:00:00Z", "2026-11-20T10:00:00Z")
	first.Record.Messages = 3
	late := visit(4, "2026-11-20T08:00:00Z", "2026-11-20T09:00:00Z")
	late.Record.Messages = 1
	for _, r := range []IndexedRecord{early, first, late} {
		if _, err := s.Apply(testExtension, s.Enrollment(), []IndexedRecord{r}); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.Pending(10).Records[0].Messages; got != 3 {
		t.Fatalf("messages = %d, want 3", got)
	}
	tooMany := visit(2, "2026-11-20T08:00:00Z", "2026-11-20T09:00:00Z").Record
	tooMany.Messages = 3
	if err := tooMany.Validate(); err == nil {
		t.Fatal("more messages than requests validated")
	}
	health := Record{Kind: KindHealth, ConnectedSince: "2026-11-20T08:00:00Z", ObservedAt: "2026-11-20T09:00:00Z", Messages: 1}
	if err := health.Validate(); err == nil {
		t.Fatal("health carrying messages validated")
	}
}

// A present messages count of the wrong type is refused, not read as zero.
func TestAVisitWithAMalformedMessageCountIsRefused(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(fixtures, "valid", "records-visit-messages.json"))
	if err != nil {
		t.Fatal(err)
	}
	var message struct {
		Records []map[string]any `json:"records"`
	}
	if err := json.Unmarshal(data, &message); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []any{"3", 1.5, nil, true} {
		record := message.Records[1]
		if record["kind"] != KindVisit {
			t.Fatalf("fixture record = %v", record)
		}
		record["messages"] = bad
		raw, _ := json.Marshal([]any{record})
		valid, rejected, err := DecodeRecords(raw)
		if err != nil || len(valid) != 0 || len(rejected) != 1 {
			t.Errorf("messages %v: valid = %d, rejected = %+v, err = %v", bad, len(valid), rejected, err)
		}
	}
}

// JSON Schema counts 3.0 and 3e0 as integers, so the daemon reads them as 3.
func TestAnIntegralMessageCountInAnyNotationIsRead(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(fixtures, "valid", "records-visit-messages.json"))
	if err != nil {
		t.Fatal(err)
	}
	var message struct {
		Records []map[string]json.RawMessage `json:"records"`
	}
	if err := json.Unmarshal(data, &message); err != nil {
		t.Fatal(err)
	}
	for _, notation := range []string{"1.0", "1e0"} {
		record := message.Records[1]
		record["messages"] = json.RawMessage(notation)
		raw, _ := json.Marshal([]any{record})
		valid, rejected, err := DecodeRecords(raw)
		if err != nil || len(valid) != 1 || len(rejected) != 0 || valid[0].Record.Messages != 1 {
			t.Errorf("messages %s: valid = %+v, rejected = %+v, err = %v", notation, valid, rejected, err)
		}
	}
	// A number that only rounds to an integer is not one, and neither is a
	// huge exponent.
	for _, notation := range []string{"1.0000000000000001", "1e1000000000", "2147483648", "1.5e0"} {
		record := message.Records[1]
		record["messages"] = json.RawMessage(notation)
		raw, _ := json.Marshal([]any{record})
		valid, rejected, err := DecodeRecords(raw)
		if err != nil || len(valid) != 0 || len(rejected) != 1 {
			t.Errorf("messages %s: valid = %+v, rejected = %+v, err = %v", notation, valid, rejected, err)
		}
	}
	for notation, want := range map[string]int{"5e-0": 5, "0e-65": 0, "1." + strings.Repeat("0", 80): 1, "120e-1": 12, "-0.0": 0, "2147483647": math.MaxInt32} {
		if n, ok := exactInteger(notation); !ok || n != want {
			t.Errorf("%s = %d, %v, want %d", notation, n, ok, want)
		}
	}
}

// A hello rebinds the store first, so an enrollment change made while there
// was nothing to send is advertised at once, and no record of the new
// workspace is taken under the old id.
func TestAHelloSeesAnEnrollmentChangeAtOnce(t *testing.T) {
	s := openTestStore(t)
	before := s.Enrollment()
	token := "workspace-b"
	sender := &Sender{Store: s, BaseURL: "https://app.kontext.dev", InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		Tokens: func(context.Context) (string, error) { return token, nil }}
	h := &Handler{Store: s, Refresh: func(ctx context.Context) error {
		_, err := sender.Rebind(ctx)
		return err
	}}
	var answer Settings
	_ = json.Unmarshal(h.Answer(context.Background(), json.RawMessage(`{"contract":2,"type":"hello","extension":{"version":"0.1.0","browser":"chrome","profile":"p7Hq2vXkLm9s"}}`)), &answer)
	if answer.Enrollment == "" || answer.Enrollment == before || answer.Enrollment != s.Enrollment() {
		t.Fatalf("hello answered %q, store %q, before %q", answer.Enrollment, s.Enrollment(), before)
	}
}

// A stored row the contract no longer allows leaves the disk, not only the
// next batch.
func TestAnInvalidStoredRowIsDeleted(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{visit(2, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
	for _, r := range s.rows {
		r.Record.AppName = "a stored name: no longer allowed?"
	}
	sender, _ := newTestSender(t, s, func(w http.ResponseWriter, _ *http.Request) {
		t.Error("nothing valid was left to send")
	})
	if _, err := sender.SendOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(s.path)
	if s.Len() != 0 || strings.Contains(string(data), "no longer allowed") {
		t.Fatalf("rows = %d, file = %s", s.Len(), data)
	}
}

// An answer longer than the limit is not read as a cut-off acknowledgement.
func TestAnAnswerOverTheLimitIsNotTaken(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{visit(2, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
	sender, _ := newTestSender(t, s, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"accepted":1,"rejected":[]}`+strings.Repeat(" ", MaxResponseBytes))
	})
	if outcome, _ := sender.SendOnce(context.Background()); outcome != Retry {
		t.Fatalf("outcome = %v, want Retry", outcome)
	}
	if len(s.Pending(10).Records) != 1 {
		t.Fatal("the row was marked sent")
	}
}

// An answer for a batch taken under one enrollment does not mark rows of the
// next one sent, even when key and version match.
func TestAnAckFromThePreviousEnrollmentIsIgnored(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{visit(2, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
	old := s.Pending(10)
	if _, err := s.Bind(Binding("https://app.kontext.dev", "ins_0123456789abcdefghijklmnopqrstuv", "workspace-b")); err != nil {
		t.Fatal(err)
	}
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{visit(2, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
	if err := s.Ack(old); err != nil {
		t.Fatal(err)
	}
	if len(s.Pending(10).Records) != 1 {
		t.Fatal("the previous enrollment's answer marked the new row sent")
	}
}

// A hello whose enrollment cannot be confirmed is answered unavailable, not
// with the enrollment the store last had.
func TestAHelloWithoutAConfirmedEnrollmentIsUnavailable(t *testing.T) {
	s := openTestStore(t)
	h := &Handler{Store: s, Refresh: func(context.Context) error { return errors.New("another cloud") }}
	got := string(h.Answer(context.Background(), json.RawMessage(`{"contract":2,"type":"hello","extension":{"version":"0.1.0","browser":"chrome","profile":"p7Hq2vXkLm9s"}}`)))
	if !strings.Contains(got, ErrorUnavailable) {
		t.Fatalf("answer = %s", got)
	}
}

// A temporary copy a crash left beside the store is removed at the next open.
func TestALeftoverTemporaryCopyIsRemoved(t *testing.T) {
	s := openTestStore(t)
	leftover := filepath.Join(filepath.Dir(s.path), "."+filepath.Base(s.path)+"-123.tmp")
	if err := os.WriteFile(leftover, []byte(`{"rows":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openStore(s.path, testNow); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(leftover); !os.IsNotExist(err) {
		t.Fatalf("leftover still there: %v", err)
	}
	// A file someone saved under a similar name is not the store's.
	for _, name := range []string{"-backup.tmp", "-000123.tmp", "-202611230930.tmp"} {
		kept := filepath.Join(filepath.Dir(s.path), "."+filepath.Base(s.path)+name)
		if err := os.WriteFile(kept, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := openStore(s.path, testNow); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(kept); err != nil {
			t.Fatalf("%s, which CreateTemp cannot make, was removed: %v", name, err)
		}
	}
}

// A hello does not wait for a stuck token read past its own deadline.
func TestAHelloDoesNotWaitForAStuckTokenRead(t *testing.T) {
	s := openTestStore(t)
	stuck := make(chan struct{})
	defer close(stuck)
	sender := &Sender{Store: s, BaseURL: "https://app.kontext.dev", InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		Tokens: func(ctx context.Context) (string, error) {
			select {
			case <-stuck:
			case <-ctx.Done():
			}
			return "", errors.New("keychain")
		}}
	go func() { _, _ = sender.Rebind(context.Background()) }()
	time.Sleep(20 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := sender.Rebind(ctx); err == nil {
		t.Fatal("a rebind behind a stuck read succeeded")
	}
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("waited %v", waited)
	}
}

// When the enrollment cannot be confirmed, such as when the configuration
// names another cloud, the store takes nothing and names no enrollment, so
// nothing seen meanwhile can later reach the old workspace.
func TestAnUnconfirmedEnrollmentTakesNoRecords(t *testing.T) {
	s := openTestStore(t)
	before := s.Enrollment()
	sender := &Sender{Store: s, BaseURL: "https://app.kontext.dev", InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		Tokens: func(context.Context) (string, error) { return "", errors.New("the configuration names another cloud") }}
	if _, err := sender.Rebind(context.Background()); err == nil {
		t.Fatal("Rebind took a failed token read")
	}
	applied, err := s.Apply(testExtension, before, []IndexedRecord{visit(1, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
	if !errors.Is(err, ErrSuspended) || len(s.Pending(10).Records) != 0 || s.Enrollment() != "" {
		t.Fatalf("applied = %+v, enrollment = %q, err = %v", applied, s.Enrollment(), err)
	}
	// The extension is told the daemon is unavailable, not that the
	// enrollment changed: an empty enrollment would make it discard its
	// counts.
	h := &Handler{Store: s}
	records := `{"contract":2,"type":"records","enrollment":"` + before + `","extension":{"version":"0.1.0","browser":"chrome","profile":"p7Hq2vXkLm9s"},"records":[]}`
	for _, msg := range []string{records, `{"contract":2,"type":"hello","extension":{"version":"0.1.0","browser":"chrome","profile":"p7Hq2vXkLm9s"}}`} {
		if got := string(h.Answer(context.Background(), json.RawMessage(msg))); !strings.Contains(got, ErrorUnavailable) {
			t.Fatalf("answer = %s", got)
		}
	}
	if _, err := s.Bind(Binding("https://app.kontext.dev", "ins_0123456789abcdefghijklmnopqrstuv", "workspace-a")); err != nil {
		t.Fatal(err)
	}
	if s.Enrollment() != before {
		t.Fatal("a confirmed enrollment did not lift the suspension")
	}
}

// An answer for a batch of A does not mark A's rows of a later binding sent,
// after A to B and back to A.
func TestAnAckFromAnEarlierBindingOfTheSameEnrollmentIsIgnored(t *testing.T) {
	s := openTestStore(t)
	a := Binding("https://app.kontext.dev", "ins_0123456789abcdefghijklmnopqrstuv", "workspace-a")
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{visit(2, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
	old := s.Pending(10)
	_, _ = s.Bind(Binding("https://app.kontext.dev", "ins_0123456789abcdefghijklmnopqrstuv", "workspace-b"))
	_, _ = s.Bind(a)
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{visit(2, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
	_ = s.Ack(old)
	if len(s.Pending(10).Records) != 1 {
		t.Fatal("an answer from the earlier binding marked the new row sent")
	}
}

// A stored row the contract no longer allows leaves the disk at open, even
// one already sent.
func TestASentRowTheContractNoLongerAllowsIsDroppedAtOpen(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{visit(2, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
	for _, r := range s.rows {
		r.Record.AppName = "no longer allowed?"
		r.Sent = r.Version
	}
	s.mu.Lock()
	_ = s.saveLocked()
	s.mu.Unlock()
	reopened, err := openStore(s.path, testNow)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(s.path)
	if reopened.Len() != 0 || strings.Contains(string(data), "no longer allowed") {
		t.Fatalf("rows = %d, file = %s", reopened.Len(), data)
	}
}

// A token read that ignores its context still ends at the deadline.
func TestATokenReadEndsAtItsDeadline(t *testing.T) {
	release := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	released := make(chan struct{})
	_, err, handedOff := readToken(ctx, func(context.Context) (string, error) {
		<-release
		return "token", nil
	}, func() { close(released) }, func() {})
	if err == nil || !handedOff || time.Since(start) > time.Second {
		t.Fatalf("err = %v, handed off %v, after %v", err, handedOff, time.Since(start))
	}
	select {
	case <-released:
		t.Fatal("released while the read still runs")
	default:
	}
	release <- struct{}{}
	<-released
}

// A message whose save fails is taken back, so it cannot go out after the
// extension was told unavailable.
func TestAMessageWhoseSaveFailsIsTakenBack(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{visit(2, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
	if err := s.Ack(s.Pending(10)); err != nil {
		t.Fatal(err)
	}
	// A file where the store's folder was: the save cannot make it again.
	if err := os.RemoveAll(filepath.Dir(s.path)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Dir(s.path), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := s.Apply(testExtension, s.Enrollment(), []IndexedRecord{
		visit(3, "2026-11-20T08:00:00Z", "2026-11-20T09:00:00Z"),
		{Index: 2, Record: Record{Kind: KindVisit, Day: "2026-11-20", App: "claude", AppName: "Claude", Provider: "Anthropic", Surface: "web", Host: "claude.ai", FirstSeen: "2026-11-20T08:00:00Z", LastSeen: "2026-11-20T08:00:00Z", Requests: 1}},
	})
	if err == nil {
		t.Fatal("a failed save was not reported")
	}
	if n := len(s.Pending(10).Records); n != 0 {
		t.Fatalf("%d rows of a refused message pending", n)
	}
}

// A token read that started before a hello gave up waiting cannot lift the
// suspension that hello left: the token it read may be older than it.
func TestAnOlderTokenReadDoesNotUndoANewerSuspension(t *testing.T) {
	s := openTestStore(t)
	started := make(chan struct{})
	finish := make(chan struct{})
	sender := &Sender{Store: s, BaseURL: "https://app.kontext.dev", InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		Tokens: func(context.Context) (string, error) {
			close(started)
			<-finish
			return "workspace-a", nil
		}}
	older := make(chan error, 1)
	go func() { _, err := sender.Rebind(context.Background()); older <- err }()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := sender.Rebind(ctx); err == nil {
		t.Fatal("a rebind behind a running read succeeded")
	}
	close(finish)
	if err := <-older; err == nil {
		t.Fatal("the older read bound the store after a newer suspension")
	}
	if _, ok := s.Confirmed(); ok {
		t.Fatal("the older read lifted the suspension")
	}
}

// A caller that gave up waiting does not suspend an enrollment a read
// confirmed while it waited.
func TestAWaiterDoesNotSuspendABindingConfirmedMeanwhile(t *testing.T) {
	s := openTestStore(t)
	epoch := s.Epoch()
	if _, err := s.Bind(Binding("https://app.kontext.dev", "ins_0123456789abcdefghijklmnopqrstuv", "workspace-a")); err != nil {
		t.Fatal(err)
	}
	if s.SuspendAt(epoch) {
		t.Fatal("a waiter suspended a binding confirmed while it waited")
	}
	if _, ok := s.Confirmed(); !ok {
		t.Fatal("the confirmed binding was suspended")
	}
}

// One damaged row does not take the other rows of the file with it.
func TestADamagedRowDoesNotDiscardTheOthers(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{visit(2, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
	data, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	damaged := strings.Replace(string(data), `"rows":{`, `"rows":{"broken":{"version":"not a number"},`, 1)
	if err := os.WriteFile(s.path, []byte(damaged), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := openStore(s.path, testNow)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(s.path)
	if reopened.Len() != 1 || strings.Contains(string(after), "broken") {
		t.Fatalf("rows = %d, file = %s", reopened.Len(), after)
	}
}

// A stored account row with a key the contract does not allow, such as an
// address put back by a backup, is dropped at open and leaves the file: a
// decode would drop the key silently and keep the text on disk.
// A restored file with one row id twice decodes as its last row; the
// earlier one, with whatever it holds, leaves the disk at open.
func TestARepeatedRowIDLeavesTheDiskAtOpen(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{account(AccountPersonal, "2026-11-20T09:00:00Z")})
	s.mu.Lock()
	_ = s.saveLocked()
	s.mu.Unlock()
	data, _ := os.ReadFile(s.path)
	text := string(data)
	start := strings.Index(text, `"rows":{`) + len(`"rows":{`)
	end := strings.Index(text[start:], `:{"record"`)
	if start < len(`"rows":{`) || end < 0 {
		t.Fatalf("no row in %s", text)
	}
	id := text[start : start+end]
	tampered := text[:start] + id + `:{"email":"jane@example.com"},` + text[start:]
	if err := os.WriteFile(s.path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := openStore(s.path, testNow)
	if err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(s.path)
	if reopened.Len() != 1 || strings.Contains(string(data), "jane@example.com") {
		t.Fatalf("rows = %d, file = %s", reopened.Len(), data)
	}
}

// A restored file that gives its binding or its rows twice, in any case,
// or in another spelling, says two things:
// none of its rows is read, whichever a decoder would keep, and the file is
// written again without them.
func TestAFileWithARepeatedBindingOrRowsIsNotRead(t *testing.T) {
	for name, tamper := range map[string]func(string) string{
		"binding": func(data string) string {
			return strings.Replace(data, `"binding":`, `"binding":"other","binding":`, 1)
		},
		"rows": func(data string) string {
			return strings.Replace(data, `"rows":`, `"rows":{},"rows":`, 1)
		},
		// The decoder matches keys in any case: "Binding" fills the same
		// field as "binding".
		"binding in another case": func(data string) string {
			return strings.Replace(data, `"binding":`, `"binding":"other","Binding":`, 1)
		},
		"rows in another case": func(data string) string {
			return strings.Replace(data, `"rows":`, `"Rows":{},"rows":`, 1)
		},
		"only a binding in another case": func(data string) string {
			return strings.Replace(data, `"binding":`, `"BINDING":`, 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := openTestStore(t)
			_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{account(AccountPersonal, "2026-11-20T09:00:00Z")})
			s.mu.Lock()
			_ = s.saveLocked()
			s.mu.Unlock()
			data, _ := os.ReadFile(s.path)
			tampered := tamper(string(data))
			if tampered == string(data) {
				t.Fatalf("nothing to repeat in %s", data)
			}
			if err := os.WriteFile(s.path, []byte(tampered), 0o600); err != nil {
				t.Fatal(err)
			}
			reopened, err := openStore(s.path, testNow)
			if err != nil {
				t.Fatal(err)
			}
			data, _ = os.ReadFile(s.path)
			if reopened.Len() != 0 || strings.Contains(string(data), AccountPersonal) {
				t.Fatalf("rows = %d, file = %s", reopened.Len(), data)
			}
		})
	}
}

func TestAStoredAccountWithAnExtraOrRepeatedKeyIsDroppedAtOpen(t *testing.T) {
	for name, tamper := range map[string]func(string) string{
		"in the record": func(data string) string {
			return strings.Replace(data, `"kind":"account"`, `"kind":"account","email":"jane@example.com"`, 1)
		},
		"beside the record": func(data string) string {
			return strings.Replace(data, `"record":{`, `"email":"jane@example.com","record":{`, 1)
		},
		// A key given twice reads as its last value here, but may read as
		// its first anywhere else.
		"a record key given twice": func(data string) string {
			return strings.Replace(data, `"account_type":"personal"`, `"account_type":"company","account_type":"personal"`, 1)
		},
		"a row key given twice": func(data string) string {
			return strings.Replace(data, `"sent":0`, `"sent":1,"sent":0`, 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := openTestStore(t)
			_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{account(AccountPersonal, "2026-11-20T09:00:00Z")})
			s.mu.Lock()
			_ = s.saveLocked()
			s.mu.Unlock()
			data, _ := os.ReadFile(s.path)
			tampered := tamper(string(data))
			if tampered == string(data) {
				t.Fatalf("no account row in %s", data)
			}
			if err := os.WriteFile(s.path, []byte(tampered), 0o600); err != nil {
				t.Fatal(err)
			}
			reopened, err := openStore(s.path, testNow)
			if err != nil {
				t.Fatal(err)
			}
			data, _ = os.ReadFile(s.path)
			if reopened.Len() != 0 || strings.Contains(string(data), "jane@example.com") {
				t.Fatalf("rows = %d, file = %s", reopened.Len(), data)
			}
		})
	}
}

// An account too far ahead of the clock, kept while the clock was set back
// or restored from a file, is dropped at open and before a send: its later
// time would hide every later observation of that type.
func TestAStoredAccountAheadOfTheClockIsDropped(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{account(AccountPersonal, "2026-11-20T11:55:00Z")})
	// The clock is set back two hours.
	earlier := func() time.Time { return testNow().Add(-2 * time.Hour) }
	s.mu.Lock()
	s.now = earlier
	s.mu.Unlock()
	if n := len(s.Pending(10).Records); n != 0 {
		t.Fatalf("pending = %d, want the account dropped", n)
	}
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{account(AccountPersonal, "2026-11-20T10:00:00Z")})
	if got := s.Pending(10).Records; len(got) != 1 || got[0].ObservedAt != "2026-11-20T10:00:00Z" {
		t.Fatalf("pending = %+v, want the 10:00 observation", got)
	}
	reopened, err := openStore(s.path, func() time.Time { return testNow().Add(-3 * time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Len() != 0 {
		t.Fatalf("rows = %d, want the account dropped at open", reopened.Len())
	}
}

// A row whose delivery counters are damaged is sent again, not taken as
// delivered and never sent.
func TestARowWithDamagedCountersIsSentAgain(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{visit(2, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
	data, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, counters := range []string{`"version":null,"sent":0`, `"version":1,"sent":"1"`, `"version":1,"sent":-0.5`, `"version":7,"sent":null`, `"version":9223372036854775807,"sent":9223372036854775807`, `"version":1e400,"sent":0`} {
		damaged := strings.Replace(string(data), `"version":1,"sent":0`, counters, 1)
		if damaged == string(data) {
			t.Fatalf("no counters in %s", data)
		}
		if err := os.WriteFile(s.path, []byte(damaged), 0o600); err != nil {
			t.Fatal(err)
		}
		reopened, err := openStore(s.path, testNow)
		if err != nil {
			t.Fatal(err)
		}
		if n := len(reopened.Pending(10).Records); n != 1 {
			t.Fatalf("%s: pending = %d, want the row sent again", counters, n)
		}
	}
}

// A restored store with more rows than the store takes keeps the newest.
func TestARestoredStoreOverTheRowCapKeepsTheNewest(t *testing.T) {
	rows := map[string]*row{}
	for i := 0; i < MaxRows+5; i++ {
		at := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Second).Format(time.RFC3339)
		r := CloudRecord{Browser: "chrome", Profile: "p7Hq2vXkLm9s", ExtensionVersion: "0.1.0", Record: visit(1, at, at).Record}
		rows[fmt.Sprint(i)] = &row{Record: r, Version: 1}
	}
	trimRows(rows)
	if len(rows) != MaxRows {
		t.Fatalf("rows = %d", len(rows))
	}
	for i := 0; i < 5; i++ {
		if _, ok := rows[fmt.Sprint(i)]; ok {
			t.Fatalf("row %d, among the oldest, was kept", i)
		}
	}
}

// With accounts among the rows, the cap still drops the oldest by time: an
// account sorts by its observation time, never at the zero time.
func TestARestoredStoreOverTheRowCapKeepsTheNewestAccounts(t *testing.T) {
	rows := map[string]*row{}
	source := func(r Record) CloudRecord {
		return CloudRecord{Browser: "chrome", Profile: "p7Hq2vXkLm9s", ExtensionVersion: "0.1.0", Record: r}
	}
	for i := 0; i < MaxRows; i++ {
		at := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Second).Format(time.RFC3339)
		rows[fmt.Sprint("visit", i)] = &row{Record: source(visit(1, at, at).Record), Version: 1}
	}
	// The newest row of all is an account; the oldest is one too.
	rows["new account"] = &row{Record: source(account(AccountPersonal, "2026-11-20T11:00:00Z").Record), Version: 1}
	rows["old account"] = &row{Record: source(account(AccountCompany, "2026-11-19T23:00:00Z").Record), Version: 1}
	trimRows(rows)
	if len(rows) != MaxRows {
		t.Fatalf("rows = %d", len(rows))
	}
	if _, ok := rows["new account"]; !ok {
		t.Fatal("the newest row, an account, was dropped")
	}
	if _, ok := rows["old account"]; ok {
		t.Fatal("the oldest row, an account, was kept")
	}
	if _, ok := rows["visit0"]; ok {
		t.Fatal("the oldest visit was kept")
	}
}

// An answer to a batch acknowledges only the record it carried: a row
// pruned while the batch was out and recorded again under the same key, at
// version 1 again, is still sent.
func TestAnAnswerDoesNotAcknowledgeARowRecordedAgain(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{account(AccountPersonal, "2026-11-20T11:55:00Z")})
	sent := s.Pending(10)
	if len(sent.Records) != 1 {
		t.Fatalf("pending = %d", len(sent.Records))
	}
	// The clock is set back while the batch is out: the row is dropped as
	// ahead of the clock, and a new observation takes its key.
	s.mu.Lock()
	s.now = func() time.Time { return testNow().Add(-2 * time.Hour) }
	s.mu.Unlock()
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{account(AccountPersonal, "2026-11-20T10:00:00Z")})
	if err := s.Ack(sent); err != nil {
		t.Fatal(err)
	}
	if got := s.Pending(10).Records; len(got) != 1 || got[0].ObservedAt != "2026-11-20T10:00:00Z" {
		t.Fatalf("pending = %+v, want the 10:00 observation still to send", got)
	}
}

// A switch whose save failed is not confirmed by the next bind until it is
// on disk.
func TestASwitchWhoseSaveFailedIsNotConfirmedUntilSaved(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{visit(2, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
	dir := filepath.Dir(s.path)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	b := Binding("https://app.kontext.dev", "ins_0123456789abcdefghijklmnopqrstuv", "workspace-b")
	if _, err := s.Bind(b); err == nil {
		t.Fatal("a switch whose save failed was reported done")
	}
	if _, err := s.Bind(b); err == nil {
		t.Fatal("a second bind confirmed a switch that is still not on disk")
	}
	if _, ok := s.Confirmed(); ok {
		t.Fatal("the store takes records under a switch not on disk")
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Bind(b); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Confirmed(); !ok {
		t.Fatal("a saved switch was not confirmed")
	}
}
