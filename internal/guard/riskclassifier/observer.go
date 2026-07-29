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

	observerQueueSize = 256
	// observerWorkers stays low on purpose: llama-server serves a small number
	// of slots, and an async data-collection feature must not crowd out
	// anything else sharing that sidecar.
	observerWorkers      = 1
	observerSinkTimeout  = 5 * time.Second
	observerDrainTimeout = 10 * time.Second
	promptCacheSize      = 256
	llmCacheSize         = 512
)

// Redactor masks credential material before text is persisted.
type Redactor func(string) string

// Sink persists one classifier record.
type Sink func(context.Context, Record) error

// ObserverOptions configure the observe-mode classifier pipeline.
type ObserverOptions struct {
	SVM       *SVM       // required
	Sink      Sink       // required
	Redact    Redactor   // required; applied to command and agent task before storage
	Guardrail *Guardrail // optional; nil records the SVM alone
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
	svm       *SVM
	sink      Sink
	redact    Redactor
	guardrail *Guardrail

	queue   chan queuedObservation
	baseCtx context.Context
	cancel  context.CancelFunc
	workers sync.WaitGroup

	// closeMu serializes queue sends against the close: an Observe holding the
	// read lock either saw the closed flag or finishes its send before Close
	// can close the channel.
	closeMu sync.RWMutex
	closed  atomic.Bool

	prompts  *boundedStringMap
	llmCache *lruCache[LLMVerdict]
}

// NewObserver starts the worker pool. Callers own Close.
func NewObserver(opts ObserverOptions) *Observer {
	if opts.SVM == nil || opts.Sink == nil || opts.Redact == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	observer := &Observer{
		svm:       opts.SVM,
		sink:      opts.Sink,
		redact:    opts.Redact,
		guardrail: opts.Guardrail,
		queue:     make(chan queuedObservation, observerQueueSize),
		baseCtx:   ctx,
		cancel:    cancel,
		prompts:   newBoundedStringMap(promptCacheSize),
		llmCache:  newLRUCache[LLMVerdict](llmCacheSize),
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
	// Resolve the agent task HERE, not in the worker. The prompt cache holds one
	// entry per session, so a second prompt arriving before this item is
	// processed would otherwise attach the wrong task to this command — or an
	// empty one, if the entry was evicted. What the queue carries is what was
	// true when the command was intercepted.
	case o.queue <- queuedObservation{ObserveInput: input, agentTask: o.prompts.get(input.SessionID)}:
	default:
	}
}

// queuedObservation is an observation plus the session context captured at
// intake, so nothing that changes while the item waits can rewrite its history.
type queuedObservation struct {
	ObserveInput
	agentTask string
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
	for item := range o.queue {
		o.process(item)
	}
}

func (o *Observer) process(item queuedObservation) {
	input := item.ObserveInput
	raw := input.Command
	// Redact the WHOLE command, however long, and only then truncate. Clipping
	// first is what makes a credential splittable: the rules are structural — the
	// JWT pattern needs all three dot-separated segments — so a token whose tail
	// falls past the cut stops matching, and its head gets stored. There is no
	// safe clip point either, since nothing bounds how long a credential can be.
	// Redaction is linear in length (RE2, no backtracking), so paying it in full
	// is cheap next to being wrong.
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
		AgentTask:        item.agentTask,
		SVM:              &svmVerdict,
		Enforced:         false,
		CreatedAt:        time.Now().UTC(),
	}
	o.attachLLM(raw, &record)

	sinkCtx, cancel := context.WithTimeout(o.baseCtx, observerSinkTimeout)
	defer cancel()
	_ = o.sink(sinkCtx, record)
}

// attachLLM fills the record's LLM half, with verbatim repeats served from an
// LRU because agents rerun identical commands constantly. Absence and failure
// are both recorded rather than hidden.
func (o *Observer) attachLLM(raw string, record *Record) {
	if o.guardrail == nil {
		record.LLMError = "guardrail not configured"
		return
	}
	key := NormalizeCommand(raw)
	if cached, ok := o.llmCache.get(key); ok {
		cached.Cached = true
		record.LLM = &cached
		return
	}
	verdict, err := o.guardrail.Classify(o.baseCtx, raw)
	if err != nil {
		record.LLMError = err.Error()
		return
	}
	record.LLM = &verdict
	o.llmCache.set(key, verdict)
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

// lruCache is a minimal LRU keyed by string.
type lruCache[V any] struct {
	mu      sync.Mutex
	max     int
	order   *list.List
	entries map[string]*list.Element
}

type lruEntry[V any] struct {
	key   string
	value V
}

func newLRUCache[V any](max int) *lruCache[V] {
	return &lruCache[V]{max: max, order: list.New(), entries: make(map[string]*list.Element, max)}
}

func (c *lruCache[V]) get(key string) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	element, ok := c.entries[key]
	if !ok {
		var zero V
		return zero, false
	}
	c.order.MoveToFront(element)
	return element.Value.(*lruEntry[V]).value, true
}

func (c *lruCache[V]) set(key string, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if element, ok := c.entries[key]; ok {
		element.Value.(*lruEntry[V]).value = value
		c.order.MoveToFront(element)
		return
	}
	c.entries[key] = c.order.PushFront(&lruEntry[V]{key: key, value: value})
	if c.order.Len() > c.max {
		oldest := c.order.Back()
		c.order.Remove(oldest)
		delete(c.entries, oldest.Value.(*lruEntry[V]).key)
	}
}
