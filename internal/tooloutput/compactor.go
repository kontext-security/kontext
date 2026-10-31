// Package tooloutput implements tool output compaction. The daemon sends a
// large tool output to the Kontext API and applies what comes back: Claude
// Code outputs are shortened live, with the full output saved where the agent
// can read it back; Codex outputs are sent in shadow mode, never waited for
// or changed. The endpoint configuration's switch turns it on, and every
// failure leaves the output as it was.
package tooloutput

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/modelusage"
)

// HookWait bounds the whole live round trip as the hook sees it.
const HookWait = 3 * time.Second

// apiWait bounds the daemon's part, transcript read and API call included,
// leaving it time to save the output and answer the hook before HookWait
// runs out. A variable so tests need not wait it out.
var apiWait = 2750 * time.Millisecond

const (
	shadowWait   = 10 * time.Second
	readBackWait = 10 * time.Second
	// maxLive bounds live calls in flight. Each holds a hook connection, and
	// policy decisions must never queue behind them.
	maxLive   = 8
	queueSize = 32
	// Retention is how long a saved output is kept.
	Retention     = 7 * 24 * time.Hour
	pruneInterval = time.Hour
	// sessionIdle is how long a session's state is kept in memory after its
	// last event. Saved records reload from disk if it comes back.
	sessionIdle = 24 * time.Hour
)

type Options struct {
	// Client is the API client; without one nothing is sent.
	Client *Client
	// Enabled reports the endpoint's switch. Nil reads as off.
	Enabled func() bool
	// Dir is where full outputs are saved (DefaultDirForDB).
	Dir        string
	Diagnostic diagnostic.Logger
	// Home is the user's home directory, for ~ in paths and the check that
	// keeps the daemon out of folders macOS guards; "" means the current
	// user's.
	Home string
	Now  func() time.Time
}

type Compactor struct {
	client     *Client
	enabled    func() bool
	dir        string
	refs       *regexp.Regexp
	dirName    string
	diagnostic diagnostic.Logger
	home       string
	now        func() time.Time

	live      chan struct{}
	shadow    chan shadowJob
	readBacks chan ReadBack

	mu       sync.Mutex
	sessions map[string]*session
}

type shadowJob struct {
	event hook.Event
	out   output
	goal  string
}

// session is what the compactor knows about one agent session.
type session struct {
	goal     string
	touched  time.Time
	records  []record
	reported map[[2]string]bool
}

// record is a compaction the agent saw, kept to recognize its read-backs. It
// is saved next to the output as <toolUseId>.json.
type record struct {
	EventID   string `json:"eventId"`
	ToolUseID string `json:"toolUseId"`
	Kind      string `json:"kind"`
	// FilePath and Omitted (file line ranges, both ends included) describe a
	// compacted Read.
	FilePath string   `json:"filePath,omitempty"`
	Omitted  [][2]int `json:"omitted,omitempty"`
	// At orders a session's records, newest last, across a restart.
	At time.Time `json:"at"`
}

func New(opts Options) *Compactor {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	// The agent is told where a saved output is; that must not depend on
	// its working directory.
	if dir, err := filepath.Abs(opts.Dir); err == nil && opts.Dir != "" {
		opts.Dir = dir
	}
	dirName := saveDirName(opts.Dir)
	return &Compactor{
		client:     opts.Client,
		enabled:    opts.Enabled,
		dir:        opts.Dir,
		refs:       savedRefPattern(dirName),
		dirName:    dirName,
		diagnostic: opts.Diagnostic,
		home:       opts.Home,
		now:        now,
		live:       make(chan struct{}, maxLive),
		shadow:     make(chan shadowJob, queueSize),
		readBacks:  make(chan ReadBack, queueSize),
		sessions:   map[string]*session{},
	}
}

func (c *Compactor) on() bool {
	return c != nil && c.client != nil && c.dir != "" && c.enabled != nil && c.enabled()
}

// Offers reports whether a PostToolUse is one live compaction would take up,
// for the daemon's answer to offer it: the switch is on and the output is a
// candidate. It is cheap; Compact makes the rest of the checks.
func (c *Compactor) Offers(event hook.Event) bool {
	_, ok := liveOutput(event)
	return ok && c.on()
}

// Compact runs live compaction for a Claude Code PostToolUse and returns the
// tool response the agent should see instead, or nil to leave the output
// unchanged: when the switch is off, the output is not a candidate, the call
// reads a saved output back, or anything fails. The output comes with the
// event, so no file of the call is opened, wherever it is.
func (c *Compactor) Compact(ctx context.Context, event hook.Event) map[string]any {
	out, ok := liveOutput(event)
	if !ok || !c.on() || c.readsBack(event) {
		return nil
	}
	if !safeSegment(event.SessionID) || !safeSegment(event.ToolUseID) {
		return nil
	}
	select {
	case c.live <- struct{}{}:
		defer func() { <-c.live }()
	default:
		c.diagnostic.Printf("tool output compaction: too many calls in flight; output left as is\n")
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, apiWait)
	defer cancel()

	saved := filepath.Join(c.dir, event.SessionID, event.ToolUseID+".txt")
	request := c.request(ModeLive, event, out, c.goal(event.SessionID))
	if out.kind == KindText {
		request.Output.RecoveryPath = saved
	}
	body, fits := encode(request)
	if !fits {
		return nil
	}
	response, err := c.client.Compact(ctx, body)
	if err != nil {
		c.diagnostic.Printf("%v; output left as is\n", err)
		return nil
	}
	if response.Decision != DecisionReplace || !out.acceptable(*response.Text) {
		return nil
	}
	compaction := record{EventID: response.EventID, ToolUseID: event.ToolUseID, Kind: out.kind, At: c.now()}
	if out.kind == KindText {
		// The full output must be readable before the agent is told where.
		if err := writePrivate(c.dir, saved, []byte(out.text)); err != nil {
			c.diagnostic.Printf("tool output compaction: %v; output left as is\n", err)
			return nil
		}
	} else {
		compaction.FilePath = filepath.Clean(out.filePath)
		compaction.Omitted = omittedLines(out.text, *response.Text, out.startLine)
	}
	c.remember(event.SessionID, compaction)
	return out.rebuild(*response.Text)
}

// Observe follows the hook events the daemon answers: the person's prompts,
// for context; Claude Code calls that read a compacted output back, which
// are reported; and Codex outputs, sent in shadow mode. It only queues
// network work, so it never delays a hook.
func (c *Compactor) Observe(_ context.Context, event hook.Event) {
	if c == nil || event.SessionID == "" {
		return
	}
	switch event.HookName {
	case hook.HookUserPromptSubmit:
		prompt, _ := event.ToolInput["prompt"].(string)
		if prompt != "" && !modelusage.IsHarnessEnvelope(prompt) {
			c.mu.Lock()
			c.session(event.SessionID).goal = modelusage.WithoutSystemReminders(prompt)
			c.mu.Unlock()
		}
	case hook.HookPreToolUse, hook.HookPostToolUse:
		if !c.on() {
			return
		}
		if event.Agent == "claude" {
			c.reportReadBacks(event)
		}
		if out, ok := shadowOutput(event); ok {
			select {
			case c.shadow <- shadowJob{event: event, out: out, goal: c.goal(event.SessionID)}:
			default:
				c.diagnostic.Printf("tool output compaction: shadow queue full; output not sent\n")
			}
		}
	}
}

// Run sends queued shadow requests and read-backs, and deletes saved outputs
// older than Retention, until ctx ends.
func (c *Compactor) Run(ctx context.Context) {
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case job := <-c.shadow:
				c.sendShadow(ctx, job)
			}
		}
	}()
	defer workers.Wait()
	c.Prune()
	ticker := time.NewTicker(pruneInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case readBack := <-c.readBacks:
			if !c.on() {
				continue
			}
			sendCtx, cancel := context.WithTimeout(ctx, readBackWait)
			if err := c.client.ReportReadBack(sendCtx, readBack); err != nil {
				c.diagnostic.Printf("tool output compaction read-back: %v\n", err)
			}
			cancel()
		case <-ticker.C:
			c.Prune()
		}
	}
}

// sendShadow sends a Codex output in shadow mode. The answer changes nothing.
func (c *Compactor) sendShadow(ctx context.Context, job shadowJob) {
	if !c.on() {
		return
	}
	body, fits := encode(c.request(ModeShadow, job.event, job.out, job.goal))
	if !fits {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, shadowWait)
	defer cancel()
	if _, err := c.client.Compact(ctx, body); err != nil {
		c.diagnostic.Printf("%v (shadow)\n", err)
	}
}

func (c *Compactor) request(mode string, event hook.Event, out output, goal string) Request {
	withheld := func(input any) bool { return c.namesSaveDir(input, event.CWD) }
	context, model := requestContext(event, goal, c.home, withheld)
	agent := event.Agent
	if agent == "claude" {
		agent = "claude-code"
	}
	return Request{
		Mode:      mode,
		Agent:     agent,
		SessionID: event.SessionID,
		ToolUseID: event.ToolUseID,
		ToolName:  event.ToolName,
		ToolInput: event.ToolInput,
		Model:     model,
		Output:    Output{Kind: out.kind, Text: out.text, FilePath: out.filePath, StartLine: out.startLine},
		Context:   context,
	}
}

// encode returns the request's body within MaxRequestBytes, dropping the
// oldest history first, or false when even the bare output does not fit.
func encode(request Request) ([]byte, bool) {
	for {
		body, err := json.Marshal(request)
		if err != nil {
			return nil, false
		}
		if len(body) <= MaxRequestBytes {
			return body, true
		}
		if len(request.Context.History) == 0 {
			return nil, false
		}
		request.Context.History = request.Context.History[1:]
	}
}

// readsBack reports whether a call reads a compacted output back: it names
// the save directory, or reads lines of a compacted file that the compaction
// left out. Such a call is never compacted itself.
func (c *Compactor) readsBack(event hook.Event) bool {
	if c.namesSaveDir(event.ToolInput, event.CWD) {
		return true
	}
	_, found := c.omittedReadBack(event)
	return found
}

// namesSaveDir reports whether a call's input names the save directory,
// however the path is spelled. A call that does reads saved outputs, which
// never leave the machine again: not as its own output, and not in the
// history sent with a later one. An input too large to read in full counts
// as naming it.
func (c *Compactor) namesSaveDir(input any, cwd string) bool {
	named := false
	eachString(input, func(value string) bool {
		named = strings.Contains(normalizedPath(value), c.dirName)
		return !named
	})
	if named {
		return true
	}
	whole := c.eachPath(input, cwd, maxPathWords, maxScanBytes, func(path string) bool {
		named = inside(path, c.dir)
		return !named
	})
	return named || !whole
}

// eachPath calls visit with each path a call's input names (see pathScan),
// reading at most maxPaths paths and maxBytes of input, and reports whether
// it read the whole input.
func (c *Compactor) eachPath(input any, cwd string, maxPaths, maxBytes int, visit func(path string) bool) bool {
	home := c.home
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	scan := pathScan{home: home, visit: visit, maxPaths: maxPaths, maxBytes: maxBytes}
	eachString(input, func(value string) bool {
		scan.value(value, cwd, 0)
		return !scan.stopped
	})
	return !scan.short
}

// reportReadBacks queues a read-back for each compaction a call reads back,
// once per call and compaction.
func (c *Compactor) reportReadBacks(event hook.Event) {
	var found []record
	// Unlike the scan that decides on compaction, this one reads every word a
	// hook message can carry, so a reference late in a long input counts.
	refer := func(text string) {
		for _, match := range c.refs.FindAllStringSubmatch(text, -1) {
			compaction, ok := c.saved(match[1], match[2])
			if ok && !slices.ContainsFunc(found, func(other record) bool { return other.EventID == compaction.EventID }) {
				found = append(found, compaction)
			}
		}
	}
	eachString(event.ToolInput, func(value string) bool {
		refer(normalizedPath(value))
		return true
	})
	c.eachPath(event.ToolInput, event.CWD, readBackPaths, readBackScanBytes, func(path string) bool {
		refer(filepath.ToSlash(path))
		return true
	})
	if compaction, ok := c.omittedReadBack(event); ok {
		found = append(found, compaction)
	}
	for _, compaction := range found {
		if compaction.ToolUseID != event.ToolUseID {
			c.queueReadBack(ReadBack{SessionID: event.SessionID, EventID: compaction.EventID, ToolUseID: event.ToolUseID})
		}
	}
}

// queueReadBack queues a read-back unless it already was. It counts as
// queued only once the queue takes it, so a full queue leaves it to the
// call's next hook event.
func (c *Compactor) queueReadBack(readBack ReadBack) {
	c.mu.Lock()
	defer c.mu.Unlock()
	reported := c.session(readBack.SessionID).reported
	key := [2]string{readBack.ToolUseID, readBack.EventID}
	if reported[key] {
		return
	}
	select {
	case c.readBacks <- readBack:
		reported[key] = true
	default:
		c.diagnostic.Printf("tool output compaction: read-back queue full; read-back not reported yet\n")
	}
}

// saved finds the record of the saved output <session>/<name>.txt.
func (c *Compactor) saved(sessionID, name string) (record, bool) {
	if !safeSegment(sessionID) || !safeSegment(name) {
		return record{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, compaction := range c.session(sessionID).records {
		if compaction.Kind == KindText && compaction.ToolUseID == name {
			return compaction, true
		}
	}
	return record{}, false
}

// omittedReadBack finds the latest compaction of the file a Read names whose
// omitted lines the Read covers. A Read without an offset starts at line 1,
// and one without a limit runs to the end of the file.
func (c *Compactor) omittedReadBack(event hook.Event) (record, bool) {
	path, _ := event.ToolInput["file_path"].(string)
	if event.ToolName != "Read" || path == "" {
		return record{}, false
	}
	first, last := 1, math.MaxInt
	if offset, ok := lineNumber(event.ToolInput["offset"]); ok {
		first = offset
	}
	if limit, ok := lineNumber(event.ToolInput["limit"]); ok && limit <= math.MaxInt-first {
		last = first + limit - 1
	}
	path = filepath.Clean(path)
	c.mu.Lock()
	defer c.mu.Unlock()
	records := c.session(event.SessionID).records
	for _, compaction := range slices.Backward(records) {
		if compaction.Kind != KindFileLines || compaction.FilePath != path {
			continue
		}
		for _, lines := range compaction.Omitted {
			if first <= lines[1] && last >= lines[0] {
				return compaction, true
			}
		}
	}
	return record{}, false
}

func (c *Compactor) goal(sessionID string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session(sessionID).goal
}

// remember keeps a compaction in memory and, best effort, beside its output,
// so a restarted daemon still recognizes its read-backs.
func (c *Compactor) remember(sessionID string, compaction record) {
	c.mu.Lock()
	state := c.session(sessionID)
	state.records = append(state.records, compaction)
	c.mu.Unlock()
	data, err := json.Marshal(compaction)
	if err == nil {
		err = writePrivate(c.dir, filepath.Join(c.dir, sessionID, compaction.ToolUseID+".json"), data)
	}
	if err != nil {
		c.diagnostic.Printf("tool output compaction: %v\n", err)
	}
}

// session returns a session's state, loading its saved records the first
// time it is seen. c.mu must be held.
func (c *Compactor) session(sessionID string) *session {
	state := c.sessions[sessionID]
	if state == nil {
		state = &session{reported: map[[2]string]bool{}, records: c.load(sessionID)}
		c.sessions[sessionID] = state
	}
	state.touched = c.now()
	return state
}

func (c *Compactor) load(sessionID string) []record {
	if c.dir == "" || !safeSegment(sessionID) {
		return nil
	}
	dir := filepath.Join(c.dir, sessionID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var records []record
	for _, entry := range entries {
		if !entry.Type().IsRegular() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		var compaction record
		if err == nil && json.Unmarshal(data, &compaction) == nil && compaction.EventID != "" {
			records = append(records, compaction)
		}
	}
	// Directory order is file name order; the search wants time order.
	slices.SortStableFunc(records, func(a, b record) int { return a.At.Compare(b.At) })
	return records
}

// Prune deletes saved outputs older than Retention, and forgets sessions idle
// for a day.
func (c *Compactor) Prune() {
	if c == nil {
		return
	}
	now := c.now()
	c.mu.Lock()
	for id, state := range c.sessions {
		if now.Sub(state.touched) > sessionIdle {
			delete(c.sessions, id)
		}
	}
	c.mu.Unlock()
	if c.dir == "" {
		return
	}
	sessions, err := os.ReadDir(c.dir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			c.diagnostic.Printf("tool output compaction prune: %v\n", err)
		}
		return
	}
	for _, sessionDir := range sessions {
		if !sessionDir.IsDir() {
			continue
		}
		dir := filepath.Join(c.dir, sessionDir.Name())
		files, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		left := len(files)
		for _, file := range files {
			info, err := file.Info()
			if err != nil || file.IsDir() || now.Sub(info.ModTime()) <= Retention {
				continue
			}
			if err := os.Remove(filepath.Join(dir, file.Name())); err == nil {
				left--
			}
		}
		if left == 0 {
			_ = os.Remove(dir)
		}
	}
}
