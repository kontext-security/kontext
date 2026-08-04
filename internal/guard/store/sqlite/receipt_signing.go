package sqlite

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/ledgerfact"
	"github.com/kontext-security/kontext-cli/internal/payloadcapture"
)

const (
	ledgerSigningEnv    = "KONTEXT_GUARD_LEDGER_SIGNING"
	ledgerSigningKeyEnv = "KONTEXT_GUARD_LEDGER_SIGNING_KEY"
)

type receiptSigner interface {
	Sign(message []byte) (signature, algorithm, keyID string, err error)
}

type ed25519ReceiptSigner struct {
	privateKey ed25519.PrivateKey
	keyID      string
}

func newReceiptSigner(dbPath string) (receiptSigner, error) {
	if !ledgerSigningEnabled() {
		return nil, nil
	}
	keyPath := os.Getenv(ledgerSigningKeyEnv)
	if keyPath == "" {
		keyPath = filepath.Join(filepath.Dir(dbPath), "receipt-signing-ed25519.key")
	}
	privateKey, err := loadOrCreateEd25519Key(keyPath)
	if err != nil {
		return nil, err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(publicKey)
	return ed25519ReceiptSigner{
		privateKey: privateKey,
		keyID:      "local-ed25519:" + hex.EncodeToString(sum[:8]),
	}, nil
}

func ledgerSigningEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(ledgerSigningEnv))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func loadOrCreateEd25519Key(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, fmt.Errorf("decode receipt signing key: %w", err)
		}
		if len(decoded) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("receipt signing key has %d bytes, want %d", len(decoded), ed25519.PrivateKeySize)
		}
		return ed25519.PrivateKey(decoded), nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	encoded := base64.StdEncoding.EncodeToString(privateKey)
	if err := os.WriteFile(path, []byte(encoded+"\n"), 0o600); err != nil {
		return nil, err
	}
	return privateKey, nil
}

func (s ed25519ReceiptSigner) Sign(message []byte) (string, string, string, error) {
	signature := ed25519.Sign(s.privateKey, message)
	return base64.StdEncoding.EncodeToString(signature), "ed25519", s.keyID, nil
}

func (s ed25519ReceiptSigner) Verify(message []byte, signature, keyID string) error {
	if keyID != s.keyID {
		return fmt.Errorf("receipt signature key %q does not match local key %q", keyID, s.keyID)
	}
	decoded, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("decode receipt signature: %w", err)
	}
	publicKey := s.privateKey.Public().(ed25519.PublicKey)
	if !ed25519.Verify(publicKey, message, decoded) {
		return fmt.Errorf("invalid receipt signature")
	}
	return nil
}

func (s *Store) VerifyReceipts(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `
select r.id, r.receipt_payload_json, r.previous_receipt_hash, r.receipt_hash,
	  coalesce(r.signature, ''), coalesce(r.signature_algorithm, ''), coalesce(r.key_id, ''),
	  coalesce(a.decision_fact_json, ''), coalesce(a.schema_version, ''), coalesce(a.tool_call_id, ''),
	  coalesce(a.applied_mode, ''), coalesce(a.evaluation_state, ''), coalesce(a.cedar_action, '')
from authorization_receipts r
left join authorization_actions a on a.id = r.action_id
order by r.rowid
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	previous := ""
	for rows.Next() {
		var id, payload, receiptHash, signature, algorithm, keyID, decisionFactJSON string
		var schemaVersion, toolCallID, appliedMode, evaluationState, cedarAction string
		var previousHash sql.NullString
		if err := rows.Scan(&id, &payload, &previousHash, &receiptHash, &signature, &algorithm, &keyID,
			&decisionFactJSON, &schemaVersion, &toolCallID, &appliedMode, &evaluationState, &cedarAction); err != nil {
			return err
		}
		if got := hashString(payload); got != receiptHash {
			return fmt.Errorf("receipt %s hash mismatch: got %s want %s", id, got, receiptHash)
		}
		storedPrevious := ""
		if previousHash.Valid {
			storedPrevious = previousHash.String
		}
		if storedPrevious != previous {
			return fmt.Errorf("receipt %s previous hash mismatch: got %s want %s", id, storedPrevious, previous)
		}
		payloadPrevious, err := receiptPayloadPreviousHash(payload)
		if err != nil {
			return fmt.Errorf("receipt %s payload previous hash: %w", id, err)
		}
		if payloadPrevious != storedPrevious {
			return fmt.Errorf("receipt %s payload previous hash mismatch: got %s want %s", id, payloadPrevious, storedPrevious)
		}
		if err := s.verifyReceiptSignature(receiptHash, signature, algorithm, keyID); err != nil {
			return fmt.Errorf("receipt %s: %w", id, err)
		}
		if err := verifyReceiptDecisionFact(payload, decisionFactJSON, decisionFactMirrors{
			SchemaVersion: schemaVersion, ToolCallID: toolCallID, AppliedMode: appliedMode,
			EvaluationState: evaluationState, CedarAction: cedarAction,
		}); err != nil {
			return fmt.Errorf("receipt %s: %w", id, err)
		}
		previous = receiptHash
	}
	return rows.Err()
}

// verifyReceiptDecisionFact makes the receipt chain attest the decision fact
// stored on its action as well as the receipt JSON itself. Legacy receipts do
// not carry a fact and intentionally remain verifiable.
type decisionFactMirrors struct {
	SchemaVersion   string
	ToolCallID      string
	AppliedMode     string
	EvaluationState string
	CedarAction     string
}

func verifyReceiptDecisionFact(payload, stored string, mirrors decisionFactMirrors) error {
	var receipt struct {
		Action struct {
			ID           string          `json:"id"`
			DecisionFact json.RawMessage `json:"decision_fact"`
		} `json:"action"`
	}
	if err := json.Unmarshal([]byte(payload), &receipt); err != nil {
		return err
	}
	if len(receipt.Action.DecisionFact) == 0 {
		return nil
	}
	if receipt.Action.ID == "" {
		return fmt.Errorf("decision-fact receipt has no action id")
	}
	// JCS on both sides: clean-form receipt payloads are stored as JCS
	// bytes, so the embedded fact's key order/escaping differs from the
	// stored fact column even when the values are identical.
	canonicalReceipt, err := payloadcapture.CanonicalJSON(json.RawMessage(receipt.Action.DecisionFact))
	if err != nil {
		return fmt.Errorf("canonicalize receipt decision fact: %w", err)
	}
	canonicalStored, err := payloadcapture.CanonicalJSON(json.RawMessage(stored))
	if err != nil {
		return fmt.Errorf("canonicalize stored decision fact: %w", err)
	}
	if string(canonicalReceipt) != string(canonicalStored) {
		return fmt.Errorf("action decision fact mismatch")
	}
	var fact ledgerfact.DecisionFact
	if err := json.Unmarshal(receipt.Action.DecisionFact, &fact); err != nil {
		return fmt.Errorf("decode receipt decision fact: %w", err)
	}
	cedarAction := ""
	if fact.CedarAction != nil {
		cedarAction = string(*fact.CedarAction)
	}
	if mirrors.SchemaVersion != fact.SchemaVersion || mirrors.ToolCallID != fact.ToolCallID ||
		mirrors.AppliedMode != string(fact.AppliedMode) || mirrors.EvaluationState != string(fact.EvaluationState) ||
		mirrors.CedarAction != cedarAction {
		return fmt.Errorf("action decision fact mirror mismatch")
	}
	return nil
}

func receiptPayloadPreviousHash(payload string) (string, error) {
	var decoded struct {
		PreviousReceiptHash string `json:"previous_receipt_hash"`
	}
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		return "", err
	}
	return decoded.PreviousReceiptHash, nil
}

func (s *Store) verifyReceiptSignature(receiptHash, signature, algorithm, keyID string) error {
	switch algorithm {
	case "", "none":
		if s.signer != nil {
			return fmt.Errorf("signed ledger receipt is missing an ed25519 signature")
		}
		return nil
	case "ed25519":
		signer, ok := s.signer.(ed25519ReceiptSigner)
		if !ok {
			return fmt.Errorf("ed25519 receipt cannot be verified without local signing key")
		}
		if signature == "" {
			return fmt.Errorf("ed25519 receipt has empty signature")
		}
		return signer.Verify([]byte(receiptHash), signature, keyID)
	default:
		return fmt.Errorf("unsupported receipt signature algorithm %q", algorithm)
	}
}

func canonicalJSON(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func jsonText(value any) (string, error) {
	data, err := canonicalJSON(value)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func hashString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func hashJSON(value any) (payload string, hash string, err error) {
	payload, err = jsonText(value)
	if err != nil {
		return "", "", err
	}
	return payload, hashString(payload), nil
}
