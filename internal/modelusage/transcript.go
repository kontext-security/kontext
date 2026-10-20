package modelusage

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
)

// Transcript parses an append-only JSONL transcript across reads, so a caller
// can parse only the bytes appended since its previous read. After every Read
// it returns the same records and errors as a full read of the same bytes:
// rows whose meaning depends on earlier rows see the carried parser state.
type Transcript struct {
	kind    string
	state   transcriptState
	offset  int64
	err     error
	prompts []Prompt
}

// transcriptState is a provider parser's state after its last parsed line.
type transcriptState interface {
	parseLine(line []byte) error
	// finish returns the records so far without changing the state.
	finish() ([]Record, error)
	// promptsSoFar returns the turn boundaries so far without changing the
	// state.
	promptsSoFar() []Prompt
	// clone copies everything a later line can change.
	clone() transcriptState
}

// Offset is the byte offset just after the last complete line parsed. The
// next Read must start there.
func (t *Transcript) Offset() int64 {
	return t.offset
}

// Read parses the bytes reader yields from Offset onward and returns every
// record in the transcript so far. Only newline-terminated lines advance
// Offset. A valid unterminated last line is applied to a copy of the state, as
// a full read would apply it, and parsed again once its newline arrives.
func (t *Transcript) Read(reader io.Reader) ([]Record, error) {
	if t.err != nil {
		return nil, t.err
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	terminated := false
	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			terminated = true
			return i + 1, data[:i], nil
		}
		terminated = false
		if atEOF && json.Valid(data) {
			return len(data), data, nil
		}
		if atEOF {
			return len(data), nil, nil
		}
		return 0, nil, nil
	})
	state := t.state
	for scanner.Scan() {
		if !terminated {
			state = state.clone()
		}
		if err := state.parseLine(scanner.Bytes()); err != nil {
			if terminated {
				// Appends cannot change a complete line, so every later full
				// read fails here too.
				t.err = err
			}
			return nil, err
		}
		if terminated {
			t.offset += int64(len(scanner.Bytes())) + 1
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s transcript: %w", t.kind, err)
	}
	records, err := state.finish()
	if err == nil {
		t.prompts = state.promptsSoFar()
	}
	return records, err
}

// Prompts returns where the transcript's turns began, in file order, as of
// the last successful Read, which a full read of the same bytes also returns.
func (t *Transcript) Prompts() []Prompt {
	return slices.Clone(t.prompts)
}
