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
	observerWorkers      = 2
	observerSinkTimeout  = 5 * time.Second
	observerDrainTimeout = 3 * time.Second
	llmCacheSize         = 512
	promptCacheSize      = 256
)

// Redactor masks credential material before text is persisted.
type Redactor func(string) string

// Sink persists one classifier record.
type Sink func(context.Context, Record) error

// ObserverOptions configure the observe-mode classifier pipeline.
type ObserverOptions struct {
	SVM       *SVM       // required
	Guardrail *Guardrail // optional; records carry llm_error when absent calls fail
	Sink      Sink       // required
	Redact    Redactor   // required; applied to command and agent task before storage
}

// ObserveInput identifies one intercepted bash command.
type ObserveInput struct {
	ActionID  string
	SessionID string
	ToolUseID string
	Agent     string
	Command   string
}

// Observer runs both risk models on intercepted bash commands and appends one
// record per command to the feedback store. It is strictly observe-mode
// plumbing: enqueueing never blocks the hook path, failures only surface in
// the records themselves, and nothing here feeds back into decisions.
type Observer struct {
	svm       *SVM
	guardrail *Guardrail
	sink      Sink
	redact    Redactor

	queue   chan ObserveInput
	baseCtx context.Context
	cancel  context.CancelFunc
	workers sync.WaitGroup

	// closeMu serializes queue sends against the close: an Observe holding the
	// read lock either saw the closed flag or finishes its send before Close
	// can close the channel.
	closeMu sync.RWMutex
	closed  atomic.Bool
	dropped atomic.Int64

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
		guardrail: opts.Guardrail,
		sink:      opts.Sink,
		redact:    opts.Redact,
		queue:     make(chan ObserveInput, observerQueueSize),
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

// Observe enqueues one command for classification. It never blocks: under
// sustained overload records are dropped and counted rather than delaying
// tool calls.
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
		o.dropped.Add(1)
	}
}

// Dropped reports how many records were lost to queue overflow.
func (o *Observer) Dropped() int64 {
	if o == nil {
		return 0
	}
	return o.dropped.Load()
}

// GuardrailModel reports the configured LLM, empty when the guardrail is off.
func (o *Observer) GuardrailModel() string {
	if o == nil {
		return ""
	}
	return o.guardrail.Model()
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
	rawHash := sha256.Sum256([]byte(raw))
	redacted := o.redact(raw)
	truncated := len(redacted) > storedCommandMaxBytes
	if truncated {
		redacted = truncateAtRuneBoundary(redacted, storedCommandMaxBytes)
	}

	svmVerdict := o.svm.Classify(raw)
	record := Record{
		ActionID:         input.ActionID,
		SessionID:        input.SessionID,
		ToolUseID:        input.ToolUseID,
		Agent:            input.Agent,
		Command:          redacted,
		CommandHash:      hex.EncodeToString(rawHash[:]),
		CommandTruncated: truncated,
		AgentTask:        o.prompts.get(input.SessionID),
		SVM:              &svmVerdict,
		Enforced:         false,
		CreatedAt:        time.Now().UTC(),
	}
	o.classifyLLM(raw, &record)

	sinkCtx, cancel := context.WithTimeout(o.baseCtx, observerSinkTimeout)
	defer cancel()
	_ = o.sink(sinkCtx, record)
}

// classifyLLM fills the record's LLM half: from the verbatim-repeat cache when
// possible (agents rerun identical commands constantly), otherwise from the
// guardrail. Absence or failure is data too — it lands in llm_error.
func (o *Observer) classifyLLM(raw string, record *Record) {
	if o.guardrail == nil {
		record.LLMError = "guardrail not configured"
		return
	}
	cacheKey := NormalizeCommand(raw)
	if cached, ok := o.llmCache.get(cacheKey); ok {
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
	o.llmCache.set(cacheKey, verdict)
}

// boundedStringMap is a tiny concurrency-safe map with arbitrary eviction once
// full — session counts on one machine stay far below the bound in practice.
type boundedStringMap struct {
	mu     sync.Mutex
	max    int
	values map[string]string
}

func newBoundedStringMap(max int) *boundedStringMap {
	return &boundedStringMap{max: max, values: make(map[string]string, max)}
}

func (m *boundedStringMap) set(key, value string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.values[key]; !exists && len(m.values) >= m.max {
		for evict := range m.values {
			delete(m.values, evict)
			break
		}
	}
	m.values[key] = value
}

func (m *boundedStringMap) get(key string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.values[key]
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
