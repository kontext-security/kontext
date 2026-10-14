package riskclassifier

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
)

const (
	// storedCommandMaxBytes caps persisted command text. Generous compared to
	// the 240-char decision summaries: long scripts are the interesting
	// training examples, and the cap only guards against pathological inputs.
	storedCommandMaxBytes = 8192

	// storedTaskMaxBytes caps the persisted agent task (user prompt).
	storedTaskMaxBytes = 2048

	promptCacheSize = 256
)

// Redactor masks credential material before text is persisted.
type Redactor func(string) string

// Verdicts is one command's advisory risk annotation. It is produced in the
// decision path but never consulted there: the caller finalizes its decision
// first and only then attaches this.
type Verdicts struct {
	SVM           *SVMVerdict
	RiskTypes     *RiskTypeVerdict
	RiskTypeError string

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
	SVM           *SVM         // required
	RiskTypes     *RiskTypeSVM // optional; nil leaves the second stage absent
	RiskTypeError string       // optional load failure retained for eligible rows
	Redact        Redactor     // required
}

// Classifier scores commands with the embedded binary SVM and risk-type SVM.
type Classifier struct {
	svm           *SVM
	riskTypes     *RiskTypeSVM
	riskTypeError string
	redact        Redactor

	prompts *lruCache[string]
}

func NewClassifier(opts ClassifierOptions) *Classifier {
	if opts.SVM == nil || opts.Redact == nil {
		return nil
	}
	return &Classifier{
		svm:           opts.SVM,
		riskTypes:     opts.RiskTypes,
		riskTypeError: opts.RiskTypeError,
		redact:        opts.Redact,
		prompts:       newLRUCache[string](promptCacheSize),
	}
}

// RecordPrompt remembers a session's latest user prompt, redacted, so
// subsequent annotations carry the task that motivated the command.
func (c *Classifier) RecordPrompt(sessionID, prompt string) {
	if c == nil || sessionID == "" || prompt == "" {
		return
	}
	c.prompts.set(sessionID, truncateAtRuneBoundary(c.redact(prompt), storedTaskMaxBytes))
}

// Classify annotates one command. It runs for every decision outcome; the
// caller has already decided by the time this is called. toolName is kept at
// this boundary so the risk-type stage can require an explicit shell tool — a
// command-shaped field on apply_patch is not shell execution.
func (c *Classifier) Classify(_ context.Context, sessionID, toolName, command string) Verdicts {
	if c == nil || strings.TrimSpace(command) == "" {
		return Verdicts{}
	}
	// Redact the WHOLE command, however long, and only then truncate. Clipping
	// first is what makes a credential splittable: the rules are structural — the
	// JWT pattern needs all three dot-separated segments — so a token whose tail
	// falls past the cut stops matching, and its head gets stored. There is no
	// safe clip point either, since nothing bounds how long a credential can be.
	// Redaction is linear in length (RE2, no backtracking), so paying it in full
	// is cheap next to being wrong.
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
	c.attachRiskTypes(toolName, command, svmVerdict, &verdicts)
	return verdicts
}

func (c *Classifier) attachRiskTypes(toolName, command string, svmVerdict SVMVerdict, verdicts *Verdicts) {
	if svmVerdict.Verdict != VerdictRisky || !IsShellCommandTool(toolName) {
		return
	}
	if c.riskTypes == nil {
		verdicts.RiskTypeError = c.riskTypeError
		return
	}
	// A corrupt in-memory model or scorer bug is advisory degradation. Recover
	// here so this second stage can never crash the daemon after authorization
	// has already settled the tool call.
	defer func() {
		if recovered := recover(); recovered != nil {
			verdicts.RiskTypes = nil
			verdicts.RiskTypeError = fmt.Sprintf("risk-type classifier panic: %v", recovered)
		}
	}()
	verdict := c.riskTypes.Classify(command)
	verdicts.RiskTypes = &verdict
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

// lruCache bounds the retained session prompts.
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
