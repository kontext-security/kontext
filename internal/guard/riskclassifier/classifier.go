package riskclassifier

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	// storedCommandMaxBytes caps persisted command text. Generous compared to
	// the 240-char decision summaries: long scripts are the interesting
	// training examples, and the cap only guards against pathological inputs.
	storedCommandMaxBytes = 8192

	// storedTaskMaxBytes caps the persisted agent task (user prompt).
	storedTaskMaxBytes = 2048

	promptCacheSize = 256
	llmCacheSize    = 512
)

// Redactor masks credential material before text is persisted.
type Redactor func(string) string

// Verdicts is one command's advisory risk annotation. It is produced in the
// decision path but never consulted there: the caller finalizes its decision
// first and only then attaches this.
type Verdicts struct {
	SVM      *SVMVerdict
	LLM      *LLMVerdict
	LLMError string

	// Command is the persisted form — redacted and capped — and CommandHash is
	// the SHA-256 of exactly that text, so the hash never covers content the
	// record omits. Verbatim repeats still collide, which is all it is used for.
	Command          string
	CommandHash      string
	CommandTruncated bool

	// AgentTask is the session's latest user prompt, redacted. Local only.
	AgentTask string
}

// ClassifierOptions configure the in-path classifier.
type ClassifierOptions struct {
	SVM       *SVM       // required
	Redact    Redactor   // required
	Guardrail *Guardrail // optional; nil records the SVM alone
	// LLMEnabled reports whether the guardrail may run. Consulted per call so
	// a remote kill switch takes effect without a restart. Nil means enabled.
	LLMEnabled func() bool
}

// Classifier scores intercepted bash commands. It runs synchronously in the
// decision path, so every guardrail call is bounded by a timeout, a circuit
// breaker, and a readiness probe — an unhealthy or still-loading sidecar must
// cost a tool call nothing.
//
// The SVM is embedded and effectively free (~12µs), so it always runs. The
// guardrail is the expensive, failable half and is the only part gated.
type Classifier struct {
	svm        *SVM
	redact     Redactor
	guardrail  *Guardrail
	llmEnabled func() bool

	breaker  *breaker
	prompts  *lruCache[string]
	llmCache *lruCache[LLMVerdict]

	// llmSkipped counts calls that shed the guardrail (breaker open, not ready,
	// or remotely disabled), for diagnostics.
	llmSkipped atomic.Int64
}

func NewClassifier(opts ClassifierOptions) *Classifier {
	if opts.SVM == nil || opts.Redact == nil {
		return nil
	}
	classifier := &Classifier{
		svm:        opts.SVM,
		redact:     opts.Redact,
		guardrail:  opts.Guardrail,
		llmEnabled: opts.LLMEnabled,
		prompts:    newLRUCache[string](promptCacheSize),
		llmCache:   newLRUCache[LLMVerdict](llmCacheSize),
	}
	if opts.Guardrail != nil {
		classifier.breaker = newBreaker(opts.Guardrail.readinessProbe())
	}
	return classifier
}

// RecordPrompt remembers a session's latest user prompt, redacted, so
// subsequent annotations carry the task that motivated the command.
func (c *Classifier) RecordPrompt(sessionID, prompt string) {
	if c == nil || sessionID == "" || prompt == "" {
		return
	}
	c.prompts.set(sessionID, truncateAtRuneBoundary(c.redact(prompt), storedTaskMaxBytes))
}

// LLMSkipped reports how many commands ran without a guardrail verdict because
// it was shed or disabled.
func (c *Classifier) LLMSkipped() int64 {
	if c == nil {
		return 0
	}
	return c.llmSkipped.Load()
}

// Classify annotates one command. It runs for every decision outcome; the
// caller has already decided by the time this is called.
func (c *Classifier) Classify(ctx context.Context, sessionID, command string) Verdicts {
	if c == nil || strings.TrimSpace(command) == "" {
		return Verdicts{}
	}
	redacted := c.redact(command)
	truncated := len(redacted) > storedCommandMaxBytes
	if truncated {
		redacted = truncateAtRuneBoundary(redacted, storedCommandMaxBytes)
	}
	// Hash exactly what is stored — redacted AND truncated. Hashing anything
	// wider makes the hash an oracle for the part the record drops: raw text
	// would confirm guesses at a redacted secret, pre-truncation text guesses at
	// the dropped suffix. Verbatim repeats still collide, which is all it does.
	storedHash := sha256.Sum256([]byte(redacted))

	svmVerdict := c.svm.Classify(command)
	verdicts := Verdicts{
		SVM:              &svmVerdict,
		Command:          redacted,
		CommandHash:      hex.EncodeToString(storedHash[:]),
		CommandTruncated: truncated,
		AgentTask:        c.agentTask(sessionID),
	}
	c.attachLLM(ctx, command, &verdicts)
	return verdicts
}

func (c *Classifier) attachLLM(ctx context.Context, command string, verdicts *Verdicts) {
	switch {
	case c.guardrail == nil:
		verdicts.LLMError = "guardrail not configured"
		return
	case c.llmEnabled != nil && !c.llmEnabled():
		c.llmSkipped.Add(1)
		verdicts.LLMError = "skipped: guardrail disabled by configuration"
		return
	}

	key := NormalizeCommand(command)
	if cached, ok := c.llmCache.get(key); ok {
		cached.Cached = true
		verdicts.LLM = &cached
		return
	}
	if !c.breaker.allow(ctx) {
		c.llmSkipped.Add(1)
		verdicts.LLMError = ErrLLMUnavailable.Error()
		return
	}
	verdict, err := c.guardrail.Classify(ctx, command)
	if err != nil {
		c.breaker.fail()
		verdicts.LLMError = err.Error()
		return
	}
	c.breaker.succeed()
	verdicts.LLM = &verdict
	c.llmCache.set(key, verdict)
}

// agentTask returns the session's latest prompt, empty when none was observed.
// Reading counts as use in the LRU, so a session actively issuing commands is
// not evicted in favour of an idle one.
func (c *Classifier) agentTask(sessionID string) string {
	task, _ := c.prompts.get(sessionID)
	return task
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

// lruCache is a minimal LRU keyed by string. Verbatim command repeats are
// common — agents rerun the same build or test command constantly — and reusing
// a verdict avoids an inference the answer cannot differ from.
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
