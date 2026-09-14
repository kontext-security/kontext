package stepsafety

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	sentencepiece "github.com/tggo/goSentencePiece"
	"golang.org/x/text/unicode/norm"
)

// This adapter is deliberately specific to the checksum-pinned DeBERTa
// tokenizer. The SentencePiece library supplies Unigram segmentation; we
// implement the pinned HF Replace -> NFC -> Strip normalizer here because
// the library only implements precompiled normalizers.
type tokenizer struct{ unigram *sentencepiece.Tokenizer }

var specialTokens = []string{"[PAD]", "[CLS]", "[SEP]", "[UNK]", "[MASK]", "[USER_REQUEST]", "[INTERACTION_HISTORY]", "[CURRENT_ACTION]", "[TOOL_DESCRIPTIONS]"}
var specialTokenIDs = []int64{0, 1, 2, 3, 128000, 128001, 128002, 128003, 128004}

func loadTokenizer(path string) (*tokenizer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config map[string]json.RawMessage
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	// Flatten the one-element Sequence so the library recognizes Metaspace.
	// These changes are in memory only; the original artifact stays pinned.
	config["pre_tokenizer"] = json.RawMessage(`{"type":"Metaspace","replacement":"▁","prepend_scheme":"always","split":true}`)
	config["normalizer"] = json.RawMessage(`null`)
	data, err = json.Marshal(config)
	if err != nil {
		return nil, err
	}
	unigram, err := sentencepiece.NewTokenizerFromJSONReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return &tokenizer{unigram: unigram}, nil
}

func (t *tokenizer) encode(ctx context.Context, text string) ([]int64, error) {
	var ids []int64
	for len(text) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		next, special := len(text), -1
		for i, token := range specialTokens {
			if at := strings.Index(text, token); at >= 0 && at < next {
				next, special = at, i
			}
		}
		// Added special tokens are extracted before normalizing each ordinary
		// segment, matching normalized=false and lstrip/rstrip=false in HF.
		segment := text[:next]
		normalized := normalizeText(segment)
		// Go NFC inserts CGJ for non-stream-safe combining sequences; HF NFC
		// does not. Abstain on those rare inputs rather than silently changing
		// the representation the checkpoint was trained on.
		if strings.Count(normalized, "\u034f") != strings.Count(segment, "\u034f") {
			return nil, backendError(ErrorUnsupportedText, nil)
		}
		pieces, err := t.unigram.Encode(normalized)
		if err != nil {
			return nil, err
		}
		for _, id := range pieces {
			ids = append(ids, int64(id))
		}
		if special < 0 {
			break
		}
		ids = append(ids, specialTokenIDs[special])
		text = text[next+len(specialTokens[special]):]
	}
	return ids, ctx.Err()
}

func normalizeText(text string) string {
	var out strings.Builder
	out.Grow(len(text))
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		if !unicode.IsSpace(r) {
			out.WriteRune(r)
			i += size
			continue
		}
		start, count := i, 0
		for i < len(text) {
			r, size = utf8.DecodeRuneInString(text[i:])
			if !unicode.IsSpace(r) {
				break
			}
			count++
			i += size
		}
		whitespace := text[start:i]
		// Rust regex \s{2,}|[\n\r\t] uses Unicode whitespace; Go's regexp \s
		// is ASCII-only, so using it here would silently change token IDs.
		if count >= 2 || whitespace == "\n" || whitespace == "\r" || whitespace == "\t" {
			out.WriteByte(' ')
		} else {
			out.WriteString(whitespace)
		}
	}
	return strings.TrimRightFunc(norm.NFC.String(out.String()), unicode.IsSpace)
}
