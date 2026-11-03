package codexproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/kontext-security/kontext/internal/modelusage"
)

const (
	// minPartBytes is the smallest printed part worth asking about, as on the
	// hook path, and maxPartBytes the largest: the API takes no request over
	// 1 MiB.
	minPartBytes = 2048
	maxPartBytes = 1 << 20
	// maxPart is the highest part index the API takes.
	maxPart = 1000
	// windowMessages is how many messages before the first new part's call go
	// with a decision request, for context, and maxMessageText bounds each.
	windowMessages = 32
	maxMessageText = 64 << 10
)

// Identity is whose request it is, as Codex says in its headers.
type Identity struct {
	SessionID string
	ThreadID  string
}

func (id Identity) session() string {
	if id.SessionID != "" {
		return id.SessionID
	}
	return id.ThreadID
}

// Rewriter replaces printed parts of code mode results in the Responses
// requests Codex sends. It asks the Decider about each new part once, stores
// the answer, and replays every stored answer on every later request of the
// session, so the prompt prefix the backend caches never changes.
type Rewriter struct {
	decider Decider
	store   *Store
	// budget bounds the decisions one request waits for.
	budget time.Duration
	// locks take a session's requests one at a time, so two never decide the
	// same part.
	locks [64]sync.Mutex
}

// NewRewriter builds a Rewriter that asks decider and keeps its answers in
// store; budget bounds each request's wait for new decisions.
func NewRewriter(decider Decider, store *Store, budget time.Duration) *Rewriter {
	return &Rewriter{decider: decider, store: store, budget: budget}
}

// Stats count what one rewrite did.
type Stats struct {
	Parts, Asked, Replaced, Replayed int
	BytesBefore, BytesAfter          int
	// PartsMissing counts the new code mode results in which no part was
	// found, not even Codex's framing, which it sends each one with: a sign
	// that Codex's format changed.
	PartsMissing int
}

func (s Stats) String() string {
	return fmt.Sprintf(" (parts=%d asked=%d replaced=%d replayed=%d missing=%d bytes %d->%d)",
		s.Parts, s.Asked, s.Replaced, s.Replayed, s.PartsMissing, s.BytesBefore, s.BytesAfter)
}

// ask is a new printed part to decide.
type ask struct {
	item item
	span span
	key  string
}

// Rewrite returns body with stored and new replacements applied. Bytes outside
// the replaced string values are copied unchanged.
func (rw *Rewriter) Rewrite(ctx context.Context, id Identity, body []byte) ([]byte, Stats, error) {
	var stats Stats
	request, err := parseRequest(body)
	if err != nil {
		return nil, stats, err
	}
	session := id.session()
	// One thread's requests are taken one at a time; a subagent's thread
	// never waits on another's.
	thread := id.ThreadID
	if thread == "" {
		thread = session
	}
	unlock := rw.lock(thread)
	defer unlock()

	// Only outputs after the model's last item are new. Anything earlier was
	// in a previous request, where it was decided or left alone for good:
	// changing it now would change a prefix the backend has already cached.
	firstNew := 0
	for i, it := range request.items {
		if it.fromModel() {
			firstNew = i + 1
		}
	}
	stats.PartsMissing = partsMissing(request.items, firstNew)
	var edits []edit
	replace := func(it item, t span, replacement string) {
		with := encodeString(replacement)
		stats.Replaced++
		stats.BytesBefore += t.end - t.start
		stats.BytesAfter += len(with)
		edits = append(edits, edit{start: it.start + t.start, end: it.start + t.end, with: with})
	}
	var asks []ask
	for i, it := range request.items {
		for _, t := range it.texts {
			stats.Parts++
			key := decisionKey(it.callID, t.part, t.value)
			if replacement, decided := rw.store.Get(session, key); decided {
				if replacement != nil {
					stats.Replayed++
					replace(it, t, *replacement)
				}
				continue
			}
			// Only code mode prints parts; Codex's summary of the run is the
			// first and never one of them.
			if size := len(t.text()); i >= firstNew && it.kind == "custom_tool_call_output" && t.part >= 1 && t.part <= maxPart &&
				size > minPartBytes && size <= maxPartBytes {
				asks = append(asks, ask{item: it, span: t, key: key})
			}
		}
	}
	// The context of a new part is the request as the model will see it:
	// with the stored answers replayed.
	seen := request
	if len(asks) > 0 && len(edits) > 0 {
		replayed := slices.Clone(edits)
		slices.SortFunc(replayed, func(a, b edit) int { return a.start - b.start })
		if parsed, err := parseRequest(applyEdits(body, replayed)); err == nil {
			seen = parsed
		}
	}
	for k, decided := range rw.decide(ctx, id, request, seen, asks) {
		stats.Asked++
		if replacement := rw.store.PutIfAbsent(session, asks[k].key, decided); replacement != nil {
			replace(asks[k].item, asks[k].span, *replacement)
		}
	}
	if len(edits) == 0 {
		return body, stats, nil
	}
	slices.SortFunc(edits, func(a, b edit) int { return a.start - b.start })
	return applyEdits(body, edits), stats, nil
}

// decide asks the Decider about asks and returns, for each, the whole text
// the model should read instead, or nil to keep it. Every failure keeps them.
func (rw *Rewriter) decide(ctx context.Context, id Identity, request, seen parsedRequest, asks []ask) []*string {
	decided := make([]*string, len(asks))
	if rw.decider == nil || len(asks) == 0 {
		return decided
	}
	wire := DecideRequest{SessionID: id.SessionID, ThreadID: id.ThreadID, Model: request.model, CWD: request.cwd()}
	wire.Messages, wire.Start = window(seen, asks[0].item.callID)
	calls := map[string]item{}
	for _, it := range request.items {
		if it.kind == "custom_tool_call" {
			calls[it.callID] = it
		}
	}
	for _, a := range asks {
		call := calls[a.item.callID]
		wire.Parts = append(wire.Parts, Part{CallID: a.item.callID, Part: a.span.part, ToolName: call.name,
			ToolInput: call.script, Text: a.span.text()})
	}
	ctx, cancel := context.WithTimeout(ctx, rw.budget)
	defer cancel()
	wire.Deadline, _ = ctx.Deadline()
	response, err := rw.decider.Decide(ctx, wire)
	if err != nil || len(response.Texts) != len(asks) {
		return decided
	}
	for k, text := range response.Texts {
		t := asks[k].span
		if text == nil || len(*text) >= len(t.text()) {
			continue
		}
		whole := *text
		if t.inner != nil {
			whole = t.value[:t.inner.start] + string(encodeString(*text)) + t.value[t.inner.end:]
		}
		decided[k] = &whole
	}
	return decided
}

// codeModeTool is the custom tool Codex runs code mode scripts with.
const codeModeTool = "exec"

// partsMissing counts the code mode results from firstNew on in which no
// text was found, neither Codex's framing nor a printed part.
func partsMissing(items []item, firstNew int) int {
	codeMode := map[string]bool{}
	for _, it := range items[:firstNew] {
		if it.kind == "custom_tool_call" && it.name == codeModeTool {
			codeMode[it.callID] = true
		}
	}
	missing := 0
	for _, it := range items[firstNew:] {
		if it.kind == "custom_tool_call_output" && codeMode[it.callID] && !it.framed && len(it.texts) == 0 {
			missing++
		}
	}
	return missing
}

func (rw *Rewriter) lock(session string) func() {
	hash := fnv.New32a()
	_, _ = io.WriteString(hash, session)
	lock := &rw.locks[hash.Sum32()%uint32(len(rw.locks))]
	lock.Lock()
	return lock.Unlock
}

// window is the request's conversation from windowMessages before the call
// callID on, each message clipped, and where it starts.
func window(request parsedRequest, callID string) ([]Message, int) {
	raw := make([]json.RawMessage, len(request.items))
	for i, it := range request.items {
		raw[i] = request.body[it.start:it.end]
	}
	messages := modelusage.CodexItemsConversation(raw).Messages
	// A tool output reads as the model got it: its string, or its parts'
	// text with nothing between them.
	outputs := map[string]string{}
	for i, it := range request.items {
		if it.kind == "custom_tool_call_output" || it.kind == "function_call_output" {
			outputs[it.callID] = outputText(raw[i])
		}
	}
	call := slices.IndexFunc(messages, func(message modelusage.Message) bool {
		return message.ToolCall != nil && message.ToolCall.ID == callID
	})
	start := max(call-windowMessages, 0)
	kept := slices.Clone(messages[start:])
	for i := range kept {
		if text, ok := outputs[kept[i].ToolUseID]; ok && kept[i].Role == "tool" {
			kept[i].Text = text
		}
		kept[i].Text = clip(kept[i].Text, maxMessageText)
	}
	return wireMessages(kept), start
}

// outputText is an output item's text as the model reads it.
func outputText(raw json.RawMessage) string {
	var item struct {
		Output json.RawMessage `json:"output"`
	}
	if json.Unmarshal(raw, &item) != nil {
		return ""
	}
	var text string
	if json.Unmarshal(item.Output, &text) == nil {
		return text
	}
	var parts []struct {
		Text string `json:"text"`
	}
	_ = json.Unmarshal(item.Output, &parts)
	var joined strings.Builder
	for _, part := range parts {
		joined.WriteString(part.Text)
	}
	return joined.String()
}

// clip shortens text over limit bytes to its start and end.
func clip(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	const marker = "\n[...]\n"
	head := (limit - len(marker)) / 2
	tail := len(text) - (limit - len(marker) - head)
	for head > 0 && !utf8.RuneStart(text[head]) {
		head--
	}
	for tail < len(text) && !utf8.RuneStart(text[tail]) {
		tail++
	}
	return text[:head] + marker + text[tail:]
}

// parsedRequest is what a rewrite reads of a Responses request body.
type parsedRequest struct {
	body  []byte
	model string
	items []item
}

// cwd is the working directory Codex last told the model about.
func (r parsedRequest) cwd() string {
	cwd := ""
	for _, it := range r.items {
		if it.cwd != "" {
			cwd = it.cwd
		}
	}
	return cwd
}

func parseRequest(body []byte) (parsedRequest, error) {
	request := parsedRequest{body: body}
	dec := json.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return request, errors.New("request is not a JSON object")
	}
	found := false
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return request, err
		}
		switch key {
		case "model":
			if err := dec.Decode(&request.model); err != nil {
				return request, err
			}
		case "input":
			if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
				return request, errors.New("input is not an array")
			}
			for dec.More() {
				var raw json.RawMessage
				if err := dec.Decode(&raw); err != nil {
					return request, err
				}
				end := int(dec.InputOffset())
				it := item{start: end - len(raw), end: end}
				if err := it.parse(raw); err != nil {
					return request, err
				}
				request.items = append(request.items, it)
			}
			if _, err := dec.Token(); err != nil {
				return request, err
			}
			found = true
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return request, err
			}
		}
	}
	if !found {
		return request, errors.New("request has no input")
	}
	return request, nil
}

// item is one element of the request's input array; start and end locate it
// in the body.
type item struct {
	start, end int
	kind       string
	role       string
	callID     string
	name       string
	script     string
	// cwd is the working directory an environment context message names.
	cwd   string
	texts []span
	// framed reports that a call output starts with Codex's code mode
	// framing, which texts leaves out.
	framed bool
}

// span is a JSON string literal inside an item, [start, end) relative to it.
type span struct {
	part       int
	start, end int
	value      string
	// inner locates the "output" literal inside value when value is a
	// printed exec_command result.
	inner *span
}

// text is what the model reads of the span: a printed exec_command result's
// output alone.
func (t span) text() string {
	if t.inner != nil {
		return t.inner.value
	}
	return t.value
}

var cwdPattern = regexp.MustCompile(`<cwd>([^<]*)</cwd>`)

func (it *item) parse(raw []byte) error {
	var head struct {
		Type      string `json:"type"`
		Role      string `json:"role"`
		CallID    string `json:"call_id"`
		Name      string `json:"name"`
		Input     string `json:"input"`
		Arguments string `json:"arguments"`
		Content   []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		// A message's content may be a string; nothing else is read from it.
		var plain struct {
			Type string `json:"type"`
			Role string `json:"role"`
		}
		if json.Unmarshal(raw, &plain) != nil {
			return err
		}
		it.kind, it.role = plain.Type, plain.Role
		return nil
	}
	it.kind, it.role, it.callID, it.name = head.Type, head.Role, head.CallID, head.Name
	switch head.Type {
	case "custom_tool_call":
		it.script = head.Input
	case "function_call":
		it.script = head.Arguments
	case "custom_tool_call_output", "function_call_output":
		texts, framed, err := outputTexts(raw)
		if err != nil {
			return err
		}
		it.texts, it.framed = texts, framed
	case "message":
		for _, content := range head.Content {
			if strings.Contains(content.Text, "<environment_context>") {
				if match := cwdPattern.FindStringSubmatch(content.Text); match != nil {
					it.cwd = strings.TrimSpace(match[1])
				}
			}
		}
	}
	return nil
}

// fromModel reports whether the model produced the item (so it ended a response).
func (it item) fromModel() bool {
	switch it.kind {
	case "custom_tool_call", "function_call", "local_shell_call", "reasoning":
		return true
	case "message":
		return it.role == "assistant"
	}
	return false
}

func decisionKey(callID string, part int, text string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%d\x00", callID, part)
	io.WriteString(h, text)
	return hex.EncodeToString(h.Sum(nil))
}

type edit struct {
	start, end int
	with       []byte
}

// applyEdits splices edits, which are in body order and never overlap.
func applyEdits(body []byte, edits []edit) []byte {
	var out bytes.Buffer
	out.Grow(len(body))
	at := 0
	for _, e := range edits {
		out.Write(body[at:e.start])
		out.Write(e.with)
		at = e.end
	}
	out.Write(body[at:])
	return out.Bytes()
}

// encodeString is the one encoding used for replacements, so a replayed
// replacement is the same bytes every time.
func encodeString(s string) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.Encode(s)
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

// outputTexts finds the strings the model reads in an output item: "output"
// itself when it is a string, else each part's "text". A code mode result's
// first part ("Script completed …\nOutput:\n") is Codex's own framing: it is
// skipped, and reported as found.
func outputTexts(raw []byte) ([]span, bool, error) {
	var spans []span
	framed := false
	err := walkStrings(raw, func(path []string, start, end int, value string) {
		switch {
		case len(path) == 1 && path[0] == "output":
			spans = append(spans, span{start: start, end: end, value: value})
		case len(path) == 3 && path[0] == "output" && path[2] == "text":
			part, _ := strconv.Atoi(path[1])
			if part == 0 && strings.HasPrefix(value, "Script ") {
				framed = true
				return
			}
			spans = append(spans, span{part: part, start: start, end: end, value: value})
		}
	})
	for i := range spans {
		spans[i].inner = execResultOutput(spans[i].value)
	}
	return spans, framed, err
}

// execResultOutput locates "output" in text when text is a printed
// exec_command result: {"chunk_id":…,"wall_time_seconds":…,"exit_code":…,"output":"…"}.
func execResultOutput(text string) *span {
	if !strings.HasPrefix(text, "{") || !strings.Contains(text, `"exit_code"`) {
		return nil
	}
	var found *span
	err := walkStrings([]byte(text), func(path []string, start, end int, value string) {
		if len(path) == 1 && path[0] == "output" {
			found = &span{start: start, end: end, value: value}
		}
	})
	if err != nil {
		return nil
	}
	return found
}

// walkStrings calls visit for every string value in doc with its path (object
// keys, array indexes) and the byte range of its literal.
func walkStrings(doc []byte, visit func(path []string, start, end int, value string)) error {
	type frame struct {
		array     bool
		index     int
		key       string
		expectKey bool
	}
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	var stack []*frame
	path := func() []string {
		p := make([]string, len(stack))
		for i, f := range stack {
			if f.array {
				p[i] = strconv.Itoa(f.index)
			} else {
				p[i] = f.key
			}
		}
		return p
	}
	// valueDone moves the enclosing container past the value just read.
	valueDone := func() {
		if len(stack) == 0 {
			return
		}
		if top := stack[len(stack)-1]; top.array {
			top.index++
		} else {
			top.expectKey = true
		}
	}
	for {
		before := int(dec.InputOffset())
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{':
				stack = append(stack, &frame{expectKey: true})
			case '[':
				stack = append(stack, &frame{array: true})
			default:
				stack = stack[:len(stack)-1]
				valueDone()
			}
		case string:
			if len(stack) > 0 && !stack[len(stack)-1].array && stack[len(stack)-1].expectKey {
				stack[len(stack)-1].key = v
				stack[len(stack)-1].expectKey = false
				continue
			}
			end := int(dec.InputOffset())
			start := before + bytes.IndexByte(doc[before:end], '"')
			visit(path(), start, end, v)
			valueDone()
		default:
			valueDone()
		}
	}
}
