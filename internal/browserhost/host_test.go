package browserhost

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func frames(t *testing.T, messages ...string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	for _, m := range messages {
		if err := WriteFrame(&buf, json.RawMessage(m)); err != nil {
			t.Fatal(err)
		}
	}
	return &buf
}

func readAll(t *testing.T, buf *bytes.Buffer) []string {
	t.Helper()
	var out []string
	for buf.Len() > 0 {
		m, err := ReadFrame(buf)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(m))
	}
	return out
}

func withAllowed(t *testing.T, ids ...string) {
	t.Helper()
	saved := storeExtensionIDs
	storeExtensionIDs = ids
	t.Cleanup(func() { storeExtensionIDs = saved })
}

func TestServeRelaysEachMessageAndWritesTheAnswer(t *testing.T) {
	withAllowed(t, "abcdefghijklmnopabcdefghijklmnop")
	in := frames(t, `{"n":1}`, `{"n":2}`)
	var out bytes.Buffer
	var seen []string
	relay := func(_ context.Context, m json.RawMessage) (json.RawMessage, error) {
		seen = append(seen, string(m))
		return json.RawMessage(`{"ok":` + string(m) + `}`), nil
	}
	if err := Serve(context.Background(), "chrome-extension://abcdefghijklmnopabcdefghijklmnop/", in, &out, relay); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(seen, ","); got != `{"n":1},{"n":2}` {
		t.Fatalf("relayed %s", got)
	}
	if got := strings.Join(readAll(t, &out), ","); got != `{"ok":{"n":1}},{"ok":{"n":2}}` {
		t.Fatalf("answered %s", got)
	}
}

func TestServeRefusesAnotherExtension(t *testing.T) {
	withAllowed(t, "abcdefghijklmnopabcdefghijklmnop")
	relay := func(context.Context, json.RawMessage) (json.RawMessage, error) {
		t.Fatal("relayed for a refused caller")
		return nil, nil
	}
	for _, origin := range []string{"", "chrome-extension://pppppppppppppppppppppppppppppppp/", "https://chatgpt.com"} {
		err := Serve(context.Background(), origin, frames(t, `{}`), &bytes.Buffer{}, relay)
		if !errors.Is(err, ErrCallerRefused) {
			t.Errorf("origin %q: err = %v, want ErrCallerRefused", origin, err)
		}
	}
}

func TestReleaseBuildRefusesEveryoneUntilStoreIDsExist(t *testing.T) {
	if len(storeExtensionIDs) != 0 {
		t.Skip("store IDs are set")
	}
	for _, id := range AllowedExtensionIDs() {
		if id != devIDForTest() {
			t.Fatalf("unexpected allowed id %q", id)
		}
	}
}

func TestDaemonFailureAnswersUnavailable(t *testing.T) {
	withAllowed(t, "abcdefghijklmnopabcdefghijklmnop")
	var out bytes.Buffer
	relay := func(context.Context, json.RawMessage) (json.RawMessage, error) {
		return nil, errors.New("dial unix: no such file")
	}
	if err := Serve(context.Background(), "chrome-extension://abcdefghijklmnopabcdefghijklmnop/", frames(t, `{}`), &out, relay); err != nil {
		t.Fatal(err)
	}
	got := readAll(t, &out)
	if len(got) != 1 || got[0] != `{"contract":2,"type":"error","error":"unavailable"}` {
		t.Fatalf("answered %v", got)
	}
}

func TestOversizedOrEmptyFramesAreRefused(t *testing.T) {
	for _, length := range []uint32{0, 1<<20 + 1} {
		var buf bytes.Buffer
		_ = binary.Write(&buf, binary.LittleEndian, length)
		if _, err := ReadFrame(&buf); err == nil {
			t.Errorf("length %d: read, want refused", length)
		}
	}
}

func TestCallerOriginSkipsTheWindowsParentFlag(t *testing.T) {
	got := CallerOrigin([]string{"chrome-extension://abc/", "--parent-window=0"})
	if got != "chrome-extension://abc/" {
		t.Fatalf("origin = %q", got)
	}
	if CallerOrigin([]string{"--parent-window=0"}) != "" {
		t.Fatal("found an origin where there is none")
	}
}

func TestAFrameCutAfterItsHeaderIsNotACleanEnd(t *testing.T) {
	withAllowed(t, "abcdefghijklmnopabcdefghijklmnop")
	var in bytes.Buffer
	_ = binary.Write(&in, binary.LittleEndian, uint32(12))
	relay := func(context.Context, json.RawMessage) (json.RawMessage, error) { return nil, nil }
	err := Serve(context.Background(), "chrome-extension://abcdefghijklmnopabcdefghijklmnop/", &in, &bytes.Buffer{}, relay)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v, want io.ErrUnexpectedEOF", err)
	}
}
