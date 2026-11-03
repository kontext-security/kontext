package tooloutput

import (
	"bytes"
	"encoding/json"
	"errors"
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

var (
	errRedaction   = errors.New("redacting the output failed")
	errDelimiters  = errors.New("the output holds every placeholder delimiter")
	errPlaceholder = errors.New("a placeholder came back changed")
	errNoShorter   = errors.New("the answer is no shorter than the output with its secrets back")
	errSecretPath  = errors.New("the path the output is saved under holds a secret")
)

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
// in its answer. It fails when no pair of delimiters is free.
func hideSecrets(text string, echoed ...string) (_ string, _ *secrets, err error) {
	// Redaction runs on untrusted content; a panic must keep the output
	// from being sent, not take the daemon down.
	defer func() {
		if recover() != nil {
			err = errRedaction
		}
	}()
	found := &secrets{}
	spans := payloadcapture.RedactedSpans(text)
	if len(spans) == 0 {
		return text, found, nil
	}
	for _, pair := range delimiters {
		if !strings.Contains(text, pair[0]) && !strings.Contains(text, pair[1]) && !anyContains(echoed, pair[0], pair[1]) {
			found.open, found.close = pair[0], pair[1]
			break
		}
	}
	if found.open == "" {
		return "", nil, errDelimiters
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
	return out.String(), found, nil
}

// reveal returns text with each placeholder replaced by its secret. It fails
// when a placeholder came back cut short or changed, or names no secret of
// the output, since the text is then not made of the output's lines. It
// also fails, before it builds the text, when the text would reach limit
// bytes: a placeholder the answer repeats could make it far larger than the
// answer.
func (s *secrets) reveal(text string, limit int) (string, error) {
	if len(s.values) == 0 {
		return text, nil
	}
	var out strings.Builder
	out.Grow(min(len(text), limit))
	add := func(part string) error {
		if out.Len()+len(part) >= limit {
			return errNoShorter
		}
		out.WriteString(part)
		return nil
	}
	for {
		start := strings.Index(text, s.open)
		if start < 0 {
			break
		}
		if strings.Contains(text[:start], s.close) {
			return "", errPlaceholder
		}
		if err := add(text[:start]); err != nil {
			return "", err
		}
		rest := text[start+len(s.open):]
		end := strings.Index(rest, s.close)
		if end < 0 {
			return "", errPlaceholder
		}
		number, named := strings.CutPrefix(rest[:end], placeholderName)
		n, err := strconv.Atoi(number)
		if !named || err != nil || n < 1 || n > len(s.values) || strconv.Itoa(n) != number {
			return "", errPlaceholder
		}
		if err := add(s.values[n-1]); err != nil {
			return "", err
		}
		text = rest[end+len(s.close):]
	}
	if strings.Contains(text, s.close) {
		return "", errPlaceholder
	}
	if err := add(text); err != nil {
		return "", err
	}
	return out.String(), nil
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
// redacted for good. The server may repeat both paths in its answer, and
// shows the agent where the full output is saved, so that path goes as it
// is: an output saved under a path with a secret in it is not sent.
func hideOutput(output *Output) (*secrets, error) {
	if len(payloadcapture.RedactedSpans(output.RecoveryPath)) > 0 {
		return nil, errSecretPath
	}
	text, found, err := hideSecrets(output.Text, output.RecoveryPath, output.FilePath)
	if err != nil {
		return nil, err
	}
	output.Text, output.FilePath = text, redacted(output.FilePath)
	return found, nil
}
