package agentauthority

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"
)

// Ids and fingerprints are keyed with the per-Mac secret K_dev, which never
// leaves the Mac (ADR-0011). Each is the first 16 bytes of an HMAC-SHA256,
// base64url without padding, behind a prefix. The scheme version is part of
// every input, so a later scheme can never collide with this one.

func keyed(key []byte, prefix string, parts ...string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("kontext/hook-inventory/v" + strconv.Itoa(HookIDScheme) + "\x00" + prefix))
	for _, part := range parts {
		mac.Write([]byte{0})
		mac.Write([]byte(part))
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
}

// scopeID names one file or plugin: its kind and its canonical path, or
// "plugin|name@marketplace" for a plugin.
func scopeID(key []byte, kind, canonical string) string {
	return keyed(key, "sc", kind, canonical)
}

// hookID is stable across command and version changes: bucket holds agent,
// scope, plugin, event, matcher, type and anchor, and ordinal tells identical
// entries apart in declaration order.
func hookID(key []byte, bucket string, ordinal int) string {
	return keyed(key, "hk", bucket, strconv.Itoa(ordinal))
}

// contentFP sees any change to the entry as written, including parts the
// summary redacts. The handler is re-encoded so key order doesn't count.
func contentFP(key []byte, event, matcher string, raw json.RawMessage) string {
	canonical := []byte(raw)
	var value any
	if json.Unmarshal(raw, &value) == nil {
		if encoded, err := json.Marshal(value); err == nil {
			canonical = encoded
		}
	}
	return keyed(key, "fp", event, matcher, string(canonical))
}
