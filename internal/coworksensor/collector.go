package coworksensor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kontext-security/kontext/internal/modelusage"
)

// Collect attaches explicitly to this session user's mounted transcript. The
// EDR daemon stays unprivileged and never opens a client-supplied file path.
// Only future completed VM Bash calls are observed; no backfill or enforcement.
func Collect(ctx context.Context, session string, duration time.Duration, maxEvents int, log io.Writer) error {
	if runtime.GOOS != "linux" {
		return errors.New("collector must run inside the Cowork Linux VM")
	}
	if _, err := uuid.Parse(session); err != nil {
		return errors.New("a transcript session UUID is required")
	}
	if duration <= 0 || duration > 10*time.Minute || maxEvents < 1 || maxEvents > 100 {
		return errors.New("collector requires duration <=10m and 1..100 events")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(home, "/sessions/") || filepath.Clean(home) != home || strings.Contains(session, "/") {
		return errors.New("collector requires a Cowork session home")
	}
	path := filepath.Join(home, "mnt/.claude/projects/session", session+".jsonl")
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	if real != path {
		return errors.New("symlink transcript rejected")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("transcript must be a regular file")
	}
	offset, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	skipPartial := false
	if offset > 0 {
		var b [1]byte
		if _, err = f.ReadAt(b[:], offset-1); err != nil {
			return err
		}
		skipPartial = b[0] != '\n'
	}
	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	client := observationClient("/run/kontext-cowork/observations.sock")
	defer client.CloseIdleConnections()
	if err := Status(ctx, "/run/kontext-cowork/observations.sock", io.Discard); err != nil {
		return fmt.Errorf("VM observation daemon not ready: %w", err)
	}
	fmt.Fprintf(log, "COLLECTOR_READY source=cowork.vm_mounted_transcript session=%s offset=%d pid=%d mode=observe max_events=%d\n", session, offset, os.Getpid(), maxEvents)
	return followTranscript(ctx, f, session, skipPartial, maxEvents, func(o Observation) error {
		id, err := postObservation(ctx, client, o)
		if err != nil {
			return err
		}
		fmt.Fprintf(log, "OBSERVATION_ACK session=%s tool_use_id=%s action_id=%s source=%s\n", o.SessionID, o.ToolUseID, id, o.Source)
		return nil
	})
}

type transcriptPairs struct {
	session string
	pending map[string]Observation
	done    map[string]bool
}

func (p *transcriptPairs) line(line []byte) ([]Observation, error) {
	var row struct {
		SessionID string    `json:"sessionId"`
		Timestamp time.Time `json:"timestamp"`
		Message   struct {
			Content []struct {
				Type      string `json:"type"`
				ToolUseID string `json:"tool_use_id"`
				IsError   bool   `json:"is_error"`
			} `json:"content"`
		} `json:"message"`
	}
	if json.Unmarshal(line, &row) != nil || row.SessionID != p.session || row.Timestamp.IsZero() {
		return nil, nil
	}
	if p.pending == nil {
		p.pending = map[string]Observation{}
		p.done = map[string]bool{}
	}
	// Reuse the daemon's Claude transcript adapter. Only paired VM Bash tool
	// blocks leave this process; prompts, output and thinking are not forwarded.
	c := modelusage.ReadClaudeConversation(bytes.NewReader(line), false)
	var observations []Observation
	for _, m := range c.Messages {
		if t := m.ToolCall; t != nil && t.Name == "mcp__workspace__bash" && !p.done[t.ID] {
			var input struct {
				Command string `json:"command"`
			}
			if json.Unmarshal(t.Input, &input) != nil || input.Command == "" || len(input.Command) > 65536 {
				continue
			}
			if len(p.pending) >= 1024 {
				return nil, errors.New("too many pending transcript calls")
			}
			p.pending[t.ID] = Observation{Source: "cowork.vm_mounted_transcript", SessionID: p.session, ToolUseID: t.ID, ToolName: t.Name, Command: input.Command}
		}
		if m.Role != "tool" || p.done[m.ToolUseID] {
			continue
		}
		o, ok := p.pending[m.ToolUseID]
		if !ok {
			continue
		}
		o.ObservedAt = row.Timestamp
		for _, b := range row.Message.Content {
			if b.Type == "tool_result" && b.ToolUseID == m.ToolUseID {
				o.Failed = b.IsError
				break
			}
		}
		if err := o.validate(); err != nil {
			return nil, err
		}
		observations = append(observations, o)
		delete(p.pending, m.ToolUseID)
		p.done[m.ToolUseID] = true
	}
	return observations, nil
}

func followTranscript(ctx context.Context, f *os.File, session string, skipPartial bool, maxEvents int, send func(Observation) error) error {
	reader := bufio.NewReaderSize(f, 65536)
	pairs := transcriptPairs{session: session}
	var partial []byte
	count := 0
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	for {
		line, err := reader.ReadSlice('\n')
		if len(partial)+len(line) > 4*1024*1024 {
			return errors.New("transcript row exceeds 4 MiB; collector stopped")
		}
		partial = append(partial, line...)
		if len(partial) > 0 && partial[len(partial)-1] == '\n' {
			if !skipPartial {
				items, e := pairs.line(partial)
				if e != nil {
					return e
				}
				for _, o := range items {
					if e := send(o); e != nil {
						return e
					}
					count++
					if count >= maxEvents {
						return nil
					}
				}
			}
			skipPartial = false
			partial = partial[:0]
		}
		if err == nil || errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if !errors.Is(err, io.EOF) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		info, e := f.Stat()
		if e != nil {
			return e
		}
		position, e := f.Seek(0, io.SeekCurrent)
		if e != nil {
			return e
		}
		if info.Size() < position {
			return errors.New("transcript truncated; collector stopped")
		}
	}
}
