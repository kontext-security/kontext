// Package browserhost is `kontext browser-host`, the native messaging host
// of the Kontext browser extension. The browser starts it for the extension
// and talks to it over stdin and stdout. It holds no token: it checks that
// the caller is our extension, then relays each message to the daemon and
// writes the daemon's answer back (browser/contract).
package browserhost

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/kontext-security/kontext/internal/browserevents"
)

// Name is the host's name in the browsers' native messaging manifests.
const Name = "security.kontext.browser_host"

// MaxAnswerBytes is the most a host may write to the browser in one message.
const MaxAnswerBytes = 1 << 20

// Relay sends one message to the daemon and returns its answer.
type Relay func(ctx context.Context, message json.RawMessage) (json.RawMessage, error)

// ErrCallerRefused is returned when the browser started the host for an
// extension that is not ours.
var ErrCallerRefused = errors.New("browser host: caller is not the Kontext extension")

// CallerOrigin finds the extension origin among the arguments the browser
// started the host with. Chrome and Edge pass it first; on Windows a
// --parent-window flag can follow.
func CallerOrigin(args []string) string {
	for _, arg := range args {
		if strings.HasPrefix(arg, "chrome-extension://") {
			return arg
		}
	}
	return ""
}

// Allowed reports whether origin is one of the extension IDs this build
// accepts (see AllowedExtensionIDs).
func Allowed(origin string) bool {
	id, ok := strings.CutPrefix(origin, "chrome-extension://")
	if !ok {
		return false
	}
	id = strings.TrimSuffix(id, "/")
	for _, allowed := range AllowedExtensionIDs() {
		if id == allowed {
			return true
		}
	}
	return false
}

// Serve checks the caller, then answers messages until the browser closes
// stdin. A message the daemon cannot take gets an error answer, so the
// extension always hears back; the host itself stops only on a broken frame
// or a closed pipe.
func Serve(ctx context.Context, origin string, in io.Reader, out io.Writer, relay Relay) error {
	if !Allowed(origin) {
		return ErrCallerRefused
	}
	for {
		message, err := ReadFrame(in)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		answer := answerFor(ctx, message, relay)
		if err := WriteFrame(out, answer); err != nil {
			return err
		}
	}
}

func answerFor(ctx context.Context, message json.RawMessage, relay Relay) json.RawMessage {
	answer, err := relay(ctx, message)
	if err != nil || len(answer) == 0 || len(answer) > MaxAnswerBytes {
		encoded, _ := json.Marshal(browserevents.NewError(browserevents.ErrorUnavailable))
		return encoded
	}
	return answer
}

// ReadFrame reads one native messaging frame: a 32-bit length in the
// machine's byte order, little-endian on every platform we build for, then
// that many bytes of JSON. Frames over browserevents.MaxMessageBytes are
// refused.
func ReadFrame(in io.Reader) (json.RawMessage, error) {
	var length uint32
	if err := binary.Read(in, binary.LittleEndian, &length); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("browser host: read frame length: %w", err)
		}
		return nil, err
	}
	if length == 0 || length > browserevents.MaxMessageBytes {
		return nil, fmt.Errorf("browser host: frame of %d bytes", length)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(in, data); err != nil {
		return nil, fmt.Errorf("browser host: read frame: %w", err)
	}
	return data, nil
}

// WriteFrame writes one native messaging frame.
func WriteFrame(out io.Writer, message json.RawMessage) error {
	if len(message) > MaxAnswerBytes {
		return fmt.Errorf("browser host: answer of %d bytes", len(message))
	}
	frame := make([]byte, 4+len(message))
	binary.LittleEndian.PutUint32(frame, uint32(len(message)))
	copy(frame[4:], message)
	_, err := out.Write(frame)
	return err
}
