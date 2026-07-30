package riskclassifier

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// storedCommandMaxBytes caps persisted command text. Generous compared to
	// the 240-char decision summaries: long scripts are the interesting
	// training examples, and the cap only guards against pathological inputs.
	storedCommandMaxBytes = 8192

	// storedTaskMaxBytes caps the persisted agent task (user prompt).
	storedTaskMaxBytes = 2048

	observerQueueSize    = 256
	observerWorkers      = 1
	observerSinkTimeout  = 5 * time.Second
	observerDrainTimeout = 3 * time.Second
	promptCacheSize      = 256
)

// Redactor masks credential material before text is persisted.
type Redactor func(string) string

// Sink persists one classifier record.
type Sink func(context.Context, Record) error

// ObserverOptions configure the observe-mode classifier pipeline.
type ObserverOptions struct {
	SVM    *SVM     // required
	Sink   Sink     // required
	Redact Redactor // required; applied to command and agent task before storage
}

// ObserveInput identifies one intercepted bash command.
type ObserveInput struct {
	ActionID  string
	SessionID string
	ToolUseID string
	Agent     string
	Command   string
}

// Observer scores intercepted bash commands and appends one record per command
// to the feedback store. It is strictly observe-mode plumbing: enqueueing never
// blocks the hook path, failures are swallowed rather than surfaced, and
// nothing here feeds back into decisions.
//
// Work is done off the hook path because the store write — not the ~12µs
// scoring — is what would otherwise make a tool call wait.
type Observer struct {
	svm    *SVM
	sink   Sink
	redact Redactor

	queue   chan ObserveInput
	baseCtx context.Context
	cancel  context.CancelFunc
	workers sync.WaitGroup

	// closeMu serializes queue sends against the close: an Observe holding the
	// read lock either saw the closed flag or finishes its send before Close
	// can close the channel.
	closeMu sync.RWMutex
	closed  atomic.Bool

	prompts *boundedStringMap
}

// NewObserver starts the worker pool. Callers own Close.
func NewObserver(opts ObserverOptions) *Observer {
	if opts.SVM == nil || opts.Sink == nil || opts.Redact == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	observer := &Observer{
		svm:     opts.SVM,
		sink:    opts.Sink,
		redact:  opts.Redact,
		queue:   make(chan ObserveInput, observerQueueSize),
		baseCtx: ctx,
		cancel:  cancel,
		prompts: newBoundedStringMap(promptCacheSize),
	}
	observer.workers.Add(observerWorkers)
	for i := 0; i < observerWorkers; i++ {
		go observer.work()
	}
	return observer
}

// RecordPrompt remembers a session's latest user prompt, already redacted, so
// subsequent records carry the task context.
func (o *Observer) RecordPrompt(sessionID, prompt string) {
	if o == nil || sessionID == "" || prompt == "" {
		return
	}
	o.prompts.set(sessionID, truncateAtRuneBoundary(o.redact(prompt), storedTaskMaxBytes))
}

// Observe enqueues one command for classification. It never blocks: if the
// queue is full the record is dropped rather than delaying a tool call. Only
// the verdict is lost — the tool call itself is already persisted on the
// decision path before the observer is involved.
func (o *Observer) Observe(input ObserveInput) {
	if o == nil || input.Command == "" || input.ActionID == "" || input.SessionID == "" {
		return
	}
	o.closeMu.RLock()
	defer o.closeMu.RUnlock()
	if o.closed.Load() {
		return
	}
	select {
	case o.queue <- input:
	default:
	}
}

// Close stops intake, waits briefly for queued work to drain, then aborts
// whatever is still in flight.
func (o *Observer) Close() {
	if o == nil || !o.closed.CompareAndSwap(false, true) {
		return
	}
	o.closeMu.Lock()
	close(o.queue)
	o.closeMu.Unlock()
	done := make(chan struct{})
	go func() {
		o.workers.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(observerDrainTimeout):
	}
	o.cancel()
}

func (o *Observer) work() {
	defer o.workers.Done()
	for input := range o.queue {
		o.process(input)
	}
}

func (o *Observer) process(input ObserveInput) {
	raw := input.Command
	redacted := o.redact(raw)
	truncated := len(redacted) > storedCommandMaxBytes
	if truncated {
		redacted = truncateAtRuneBoundary(redacted, storedCommandMaxBytes)
	}
	// Hash exactly what is stored — redacted AND truncated — never the raw or
	// the pre-truncation text. Anything the hash covers but the row omits is a
	// guessing oracle over the omitted part: hashing the raw command would let a
	// reader confirm a low-entropy secret, and hashing the untruncated text
	// would do the same for the dropped suffix. Hashing the stored form keeps
	// the projection internally consistent, and verbatim repeats still collide,
	// which is all the hash is used for.
	storedHash := sha256.Sum256([]byte(redacted))

	svmVerdict := o.svm.Classify(raw)
	record := Record{
		ActionID:         input.ActionID,
		SessionID:        input.SessionID,
		ToolUseID:        input.ToolUseID,
		Agent:            input.Agent,
		Command:          redacted,
		CommandHash:      hex.EncodeToString(storedHash[:]),
		CommandTruncated: truncated,
		AgentTask:        o.prompts.get(input.SessionID),
		SVM:              &svmVerdict,
		Enforced:         false,
		CreatedAt:        time.Now().UTC(),
	}

	sinkCtx, cancel := context.WithTimeout(o.baseCtx, observerSinkTimeout)
	defer cancel()
	_ = o.sink(sinkCtx, record)
}

// truncateAtRuneBoundary caps s at max bytes without splitting a UTF-8
// sequence.
func truncateAtRuneBoundary(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut]
}

// boundedStringMap is a small concurrency-safe string map that evicts the
// least recently used entry once full. Recency matters: arbitrary eviction can
// drop a still-active session's task while keeping a finished one, which
// silently blanks agent_task on every later command from that session.
type boundedStringMap struct {
	mu      sync.Mutex
	max     int
	order   *list.List
	entries map[string]*list.Element
}

type boundedEntry struct {
	key   string
	value string
}

func newBoundedStringMap(max int) *boundedStringMap {
	return &boundedStringMap{max: max, order: list.New(), entries: make(map[string]*list.Element, max)}
}

func (m *boundedStringMap) set(key, value string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if element, ok := m.entries[key]; ok {
		element.Value.(*boundedEntry).value = value
		m.order.MoveToFront(element)
		return
	}
	m.entries[key] = m.order.PushFront(&boundedEntry{key: key, value: value})
	if m.order.Len() > m.max {
		oldest := m.order.Back()
		m.order.Remove(oldest)
		delete(m.entries, oldest.Value.(*boundedEntry).key)
	}
}

func (m *boundedStringMap) get(key string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	element, ok := m.entries[key]
	if !ok {
		return ""
	}
	// Reading counts as use: a session actively issuing commands must not be
	// evicted in favour of an idle one.
	m.order.MoveToFront(element)
	return element.Value.(*boundedEntry).value
}
