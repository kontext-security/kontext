package localruntime

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
)

type EvaluateRequest struct {
	ProtocolVersion int             `json:"protocol_version,omitempty"`
	Type            string          `json:"type"`
	SessionID       string          `json:"session_id,omitempty"`
	Agent           string          `json:"agent"`
	HookEvent       string          `json:"hook_event"`
	Prompt          string          `json:"prompt,omitempty"`
	ToolName        string          `json:"tool_name"`
	ToolInput       json.RawMessage `json:"tool_input,omitempty"`
	ToolResponse    json.RawMessage `json:"tool_response,omitempty"`
	ToolUseID       string          `json:"tool_use_id"`
	CWD             string          `json:"cwd"`
	PermissionMode  string          `json:"permission_mode,omitempty"`
	DurationMs      *int64          `json:"duration_ms,omitempty"`
	Error           string          `json:"error,omitempty"`
	IsInterrupt     *bool           `json:"is_interrupt,omitempty"`
}

type EvaluateResult struct {
	ProtocolVersion int    `json:"protocol_version,omitempty"`
	Type            string `json:"type"`
	Decision        string `json:"decision,omitempty"`
	Allowed         bool   `json:"allowed"`
	Reason          string `json:"reason"`
	ReasonCode      string `json:"reason_code,omitempty"`
	RequestID       string `json:"request_id,omitempty"`
	Mode            string `json:"mode,omitempty"`
	Epoch           string `json:"epoch,omitempty"`
	// EventID is the persisted decision row's ID — pre-minted when the
	// runtime answers before persisting — so a hook client can correlate
	// its response with the eventual record.
	EventID      string         `json:"event_id,omitempty"`
	UpdatedInput map[string]any `json:"updated_input,omitempty"`
}

func WriteMessage(conn net.Conn, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	length := uint32(len(data))
	if err := binary.Write(conn, binary.BigEndian, length); err != nil {
		return fmt.Errorf("write length: %w", err)
	}
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	return nil
}

func ReadMessage(conn net.Conn, v any) error {
	var length uint32
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return fmt.Errorf("read length: %w", err)
	}

	if length > 10*1024*1024 {
		return fmt.Errorf("message too large: %d bytes", length)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return fmt.Errorf("read payload: %w", err)
	}

	return json.Unmarshal(data, v)
}
