package coworksensor

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const collectorSession = "9ea56abc-6c9a-4491-b95c-88ac9963018d"

func transcriptFixture(kind, content string) string {
	return `{"type":"` + kind + `","sessionId":"` + collectorSession + `","timestamp":"2026-11-23T19:10:00Z","message":{"content":` + content + `}}` + "\n"
}

func TestTranscriptPairsOnlyCompletedOwnVMCalls(t *testing.T) {
	p := transcriptPairs{session: collectorSession}
	rows := []struct {
		name, line string
		want       int
	}{
		{"prompt", transcriptFixture("user", `"private prompt"`), 0},
		{"thinking", transcriptFixture("assistant", `[{"type":"thinking","thinking":"private"}]`), 0},
		{"host tool", transcriptFixture("assistant", `[{"type":"tool_use","id":"host","name":"Read","input":{"file_path":"private"}}]`), 0},
		{"unmatched result", transcriptFixture("user", `[{"type":"tool_result","tool_use_id":"missing","content":"private output"}]`), 0},
		{"VM call", transcriptFixture("assistant", `[{"type":"tool_use","id":"toolu_real","name":"mcp__workspace__bash","input":{"command":"printf harmless","description":"private description"}}]`), 0},
		{"other session result", strings.ReplaceAll(transcriptFixture("user", `[{"type":"tool_result","tool_use_id":"toolu_real"}]`), collectorSession, "another-session"), 0},
		{"paired result", transcriptFixture("user", `[{"type":"tool_result","tool_use_id":"toolu_real","is_error":true,"content":"private output"}]`), 1},
		{"duplicate result", transcriptFixture("user", `[{"type":"tool_result","tool_use_id":"toolu_real","content":"private output"}]`), 0},
	}
	for _, r := range rows {
		func() {
			got, err := p.line([]byte(r.line))
			if err != nil || len(got) != r.want {
				t.Fatalf("%s: got %d observations, %v", r.name, len(got), err)
			}
			if len(got) == 1 {
				if !got[0].Failed || got[0].Command != "printf harmless" || got[0].ToolUseID != "toolu_real" {
					t.Fatalf("wrong observation: %+v", got)
				}
				b, _ := json.Marshal(got)
				if strings.Contains(string(b), "private") {
					t.Fatal("non-tool content leaked")
				}
			}
		}()
	}
}

func TestTranscriptTailSkipsHistoricalPartialRow(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "transcript")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// This is the suffix of a row that existed before attachment, followed by
	// fresh split-independent tool records. No historical event is imported.
	data := "historical suffix\n" + transcriptFixture("assistant", `[{"type":"tool_use","id":"toolu_new","name":"mcp__workspace__bash","input":{"command":"printf fresh"}}]`) + transcriptFixture("user", `[{"type":"tool_result","tool_use_id":"toolu_new","content":"fresh"}]`)
	if _, err = f.WriteString(data); err != nil {
		t.Fatal(err)
	}
	if _, err = f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	var got []Observation
	err = followTranscript(context.Background(), f, collectorSession, true, 1, func(o Observation) error { got = append(got, o); return nil })
	if err != nil || len(got) != 1 || got[0].ToolUseID != "toolu_new" {
		t.Fatalf("observations %+v error %v", got, err)
	}
}
