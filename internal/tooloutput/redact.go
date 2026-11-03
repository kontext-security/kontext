package tooloutput

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/kontext-security/kontext/internal/payloadcapture"
)

// No secret the payload capture ruleset finds leaves the device with a
// request. In the output, each one is replaced by a numbered placeholder,
// and the daemon puts it back into the text the server answers with, which
// is built from what it was sent, before the agent sees it. Everything else
// a request carries is redacted for good, as payload capture redacts it.

// delimiters open and close a placeholder, which reads like
// \u27e6REDACTED_SECRET_1\u27e7. A request uses the first pair that neither its
// output nor what the server may repeat contains, so a placeholder that comes
// back cut short leaves a delimiter behind.
var delimiters = [][2]string{{"\u27e6", "\u27e7"}, {"\u2983", "\u2984"}, {"\u27ec", "\u27ed"}}

const placeholderName = "REDACTED_SECRET_"

// secrets are what an output's placeholders stand for: placeholder n, from 1,
// stands for values[n-1].
type secrets struct {
	open, close string
	values      []string
}

// hideSecrets returns text with each secret in it replaced by a placeholder,
// and the secrets, to put back with reveal. A secret over several lines is
// replaced line by line, so the text keeps its line breaks and the server
// counts lines as the agent does. echoed are what else the server may repeat
// in its answer. It reports false when no pair of delimiters is free.
func hideSecrets(text string, echoed ...string) (_ string, _ *secrets, ok bool) {
	// Redaction runs on untrusted content; a panic must keep the output
	// from being sent, not take the daemon down.
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	found := &secrets{}
	spans := payloadcapture.RedactedSpans(text)
	if len(spans) == 0 {
		return text, found, true
	}
	for _, pair := range delimiters {
		if !strings.Contains(text, pair[0]) && !strings.Contains(text, pair[1]) && !anyContains(echoed, pair[0], pair[1]) {
			found.open, found.close = pair[0], pair[1]
			break
		}
	}
	if found.open == "" {
		return "", nil, false
	}
	var out strings.Builder
	out.Grow(len(text))
	at := 0
	for _, span := range spans {
		out.WriteString(text[at:span.Start])
		for i, line := range strings.Split(text[span.Start:span.End], "\n") {
			if i > 0 {
				out.WriteByte('\n')
			}
			if line != "" {
				found.values = append(found.values, line)
				out.WriteString(found.open + placeholderName + strconv.Itoa(len(found.values)) + found.close)
			}
		}
		at = span.End
	}
	out.WriteString(text[at:])
	return out.String(), found, true
}

// reveal returns text with each placeholder replaced by its secret. It
// reports false when a placeholder came back cut short or changed, or names
// no secret of the output: the text is then not made of the output's lines.
func (s *secrets) reveal(text string) (string, bool) {
	if len(s.values) == 0 {
		return text, true
	}
	var out strings.Builder
	out.Grow(len(text))
	for {
		start := strings.Index(text, s.open)
		if start < 0 {
			break
		}
		if strings.Contains(text[:start], s.close) {
			return "", false
		}
		out.WriteString(text[:start])
		rest := text[start+len(s.open):]
		end := strings.Index(rest, s.close)
		if end < 0 {
			return "", false
		}
		number, named := strings.CutPrefix(rest[:end], placeholderName)
		n, err := strconv.Atoi(number)
		if !named || err != nil || n < 1 || n > len(s.values) || strconv.Itoa(n) != number {
			return "", false
		}
		out.WriteString(s.values[n-1])
		text = rest[end+len(s.close):]
	}
	if strings.Contains(text, s.close) {
		return "", false
	}
	out.WriteString(text)
	return out.String(), true
}

func anyContains(texts []string, subs ...string) bool {
	for _, text := range texts {
		for _, sub := range subs {
			if strings.Contains(text, sub) {
				return true
			}
		}
	}
	return false
}

// redacted returns text with its secrets redacted for good.
func redacted(text string) string {
	text, _ = payloadcapture.RedactText(text)
	return text
}

// redactedInput returns a tool input with its secrets redacted for good: an
// object's sensitive keys lose their values, and every string is redacted.
func redactedInput(input any) any {
	if object, isObject := input.(map[string]any); isObject && object == nil {
		return input
	}
	input, _ = payloadcapture.RedactValue(input)
	return input
}

// redactedJSON returns raw JSON with its secrets redacted for good, as
// redactedInput redacts the value it holds.
func redactedJSON(raw json.RawMessage) json.RawMessage {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil || decoder.More() {
		data, _ := json.Marshal(redacted(string(raw)))
		return data
	}
	value, changed := payloadcapture.RedactValue(value)
	if !changed {
		return raw
	}
	data, err := json.Marshal(value)
	if err != nil {
		data, _ = json.Marshal(redacted(string(raw)))
	}
	return data
}

// hideOutput hides the secrets of a request's output, whose text is sent
// with placeholders the answer's are revealed from; its file path is
// redacted for good. The server may repeat both paths in its answer. An
// output too large for any request is never sent, so it is not redacted
// either.
func hideOutput(output *Output) (*secrets, bool) {
	if len(output.Text) > MaxRequestBytes {
		return nil, false
	}
	text, found, ok := hideSecrets(output.Text, output.RecoveryPath, output.FilePath)
	if !ok {
		return nil, false
	}
	output.Text, output.FilePath = text, redacted(output.FilePath)
	return found, true
}
