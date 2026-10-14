package stepsafety

import (
	"context"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// This adapter is deliberately specific to the checksum-pinned DeBERTa
// tokenizer: the HF Replace -> NFC -> Strip normalizer and added special
// tokens here, Metaspace and Unigram segmentation in unigram.go.
type tokenizer struct{ unigram *unigram }

var specialTokens = []string{"[PAD]", "[CLS]", "[SEP]", "[UNK]", "[MASK]", "[USER_REQUEST]", "[INTERACTION_HISTORY]", "[CURRENT_ACTION]", "[TOOL_DESCRIPTIONS]"}
var specialTokenIDs = []int64{0, 1, 2, 3, 128000, 128001, 128002, 128003, 128004}

func loadTokenizer(path string) (*tokenizer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseTokenizer(data)
}

func parseTokenizer(data []byte) (*tokenizer, error) {
	unigram, err := parseUnigram(data)
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
		ids = t.unigram.encode(normalized, ids)
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
	return strings.TrimRightFunc(nfcUnicode9(out.String()), unicode.IsSpace)
}

// nfcUnicode9 matches HF NFC, whose tables are Unicode 9.0. HF treats every
// later character as an unassigned starter that never reorders or composes,
// while x/text's newer tables move or merge the ones in postUnicode9NFC. NFC
// cannot act across such a starter, so normalizing the text between them and
// copying them unchanged reproduces HF.
func nfcUnicode9(text string) string {
	var out strings.Builder
	for {
		i := strings.IndexFunc(text, func(r rune) bool { return unicode.Is(postUnicode9NFC, r) })
		if i < 0 {
			break
		}
		_, size := utf8.DecodeRuneInString(text[i:])
		out.WriteString(norm.NFC.String(text[:i]))
		out.WriteString(text[i : i+size])
		text = text[i+size:]
	}
	if out.Len() == 0 {
		return norm.NFC.String(text)
	}
	out.WriteString(norm.NFC.String(text))
	return out.String()
}
