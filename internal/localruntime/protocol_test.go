package localruntime

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"testing"
)

func TestABrowserMessageKeepsItsBytesThroughTheSocket(t *testing.T) {
	// "&", "<" and ">" grow to six bytes each under json.Marshal, which would
	// push a message under the contract's 1 MiB limit over it.
	message := json.RawMessage(`{"contract":2,"type":"hello","future":"` + strings.Repeat("&<>", 300_000) + `"}`)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_ = WriteMessage(client, EvaluateRequest{Type: BrowserRequestType, Browser: message})
	}()
	var got EvaluateRequest
	if err := ReadMessage(server, &got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Browser, message) {
		t.Fatalf("relayed %d bytes, sent %d", len(got.Browser), len(message))
	}
}
