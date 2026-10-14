package stepsafety

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"unicode/utf8"
)

const metaspace = "▁"

// unigram is the Metaspace pre-tokenizer and Unigram model of the pinned
// tokenizer.json, matching HF tokenizers 0.22.2 (Unigram::encode_optimized)
// exactly: every vocab entry is matchable, including the literal "<0xNN>"
// and bracketed special pieces; path scores accumulate in float64; the first
// candidate to reach a position wins ties; an unknown rune scores the lowest
// piece score minus 10, and consecutive unknowns fuse into one [UNK].
//
// The vocabulary is a map whose keys share one backing string, about 8 MiB.
// A byte trie with a 256-pointer array per node held the same vocabulary in
// more than 600 MiB for the lifetime of the daemon.
type unigram struct {
	ids      map[string]int32
	scores   []float32 // the artifact's scores are exact float32 values
	maxLen   int       // longest piece in bytes
	unkID    int32
	unkScore float64
}

func parseUnigram(data []byte) (*unigram, error) {
	var config struct {
		Model struct {
			Type         string            `json:"type"`
			UnkID        *int              `json:"unk_id"`
			ByteFallback bool              `json:"byte_fallback"`
			Vocab        []json.RawMessage `json:"vocab"`
		} `json:"model"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	model := config.Model
	if model.Type != "Unigram" || model.UnkID == nil || *model.UnkID < 0 || *model.UnkID >= len(model.Vocab) || model.ByteFallback {
		return nil, errors.New("unsupported tokenizer model")
	}
	pieces := make([]string, len(model.Vocab))
	scores := make([]float32, len(model.Vocab))
	size, minScore := 0, math.Inf(1)
	for i, raw := range model.Vocab {
		var entry [2]json.RawMessage
		var score float64
		if err := json.Unmarshal(raw, &entry); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(entry[0], &pieces[i]); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(entry[1], &score); err != nil {
			return nil, err
		}
		if float64(float32(score)) != score || pieces[i] == "" || !utf8.ValidString(pieces[i]) {
			return nil, errors.New("unsupported tokenizer vocabulary entry")
		}
		scores[i] = float32(score)
		minScore = math.Min(minScore, score)
		size += len(pieces[i])
	}
	var backing strings.Builder
	backing.Grow(size)
	for _, piece := range pieces {
		backing.WriteString(piece)
	}
	all := backing.String()
	u := &unigram{ids: make(map[string]int32, len(pieces)), scores: scores, unkID: int32(*model.UnkID), unkScore: minScore - 10}
	offset := 0
	for i, piece := range pieces {
		// HF resolves duplicate pieces to the later id.
		u.ids[all[offset:offset+len(piece)]] = int32(i)
		offset += len(piece)
		u.maxLen = max(u.maxLen, len(piece))
	}
	return u, nil
}

// encode pre-tokenizes one normalized segment that holds no special tokens:
// spaces become ▁, a ▁ is prepended unless present, and every word starts at
// a ▁. Each word is segmented independently.
func (u *unigram) encode(normalized string, ids []int64) []int64 {
	if normalized == "" {
		return ids
	}
	text := strings.ReplaceAll(normalized, " ", metaspace)
	if !strings.HasPrefix(text, metaspace) {
		text = metaspace + text
	}
	for len(text) > 0 {
		word := text
		if next := strings.Index(text[len(metaspace):], metaspace); next >= 0 {
			word = text[:len(metaspace)+next]
		}
		ids = u.segment(word, ids)
		text = text[len(word):]
	}
	return ids
}

type unigramNode struct {
	score float64
	start int // -1 until reached
	id    int32
}

// segment appends the best-scoring segmentation of word.
func (u *unigram) segment(word string, ids []int64) []int64 {
	n := len(word)
	nodes := make([]unigramNode, n+1)
	for i := range nodes {
		nodes[i].start = -1
	}
	relax := func(end, start int, id int32, score float64) {
		if node := &nodes[end]; node.start < 0 || score > node.score {
			*node = unigramNode{score: score, start: start, id: id}
		}
	}
	for start := 0; start < n; {
		here := nodes[start].score
		_, runeLen := utf8.DecodeRuneInString(word[start:])
		single := false
		for end := start + 1; end <= min(n, start+u.maxLen); end++ {
			// Pieces are valid UTF-8, so they end on rune boundaries.
			if end < n && !utf8.RuneStart(word[end]) {
				continue
			}
			id, ok := u.ids[word[start:end]]
			if !ok {
				continue
			}
			relax(end, start, id, here+float64(u.scores[id]))
			single = single || end-start == runeLen
		}
		if !single {
			relax(start+runeLen, start, u.unkID, here+u.unkScore)
		}
		start += runeLen
	}
	first := len(ids)
	for end := n; end > 0; {
		node := nodes[end]
		start, id := node.start, node.id
		if id == u.unkID {
			for start > 0 && nodes[start].id == u.unkID {
				start = nodes[start].start
			}
			// HF maps the fused surface string back through the vocabulary.
			if known, ok := u.ids[word[start:end]]; ok {
				id = known
			}
		}
		ids = append(ids, int64(id))
		end = start
	}
	for i, j := first, len(ids)-1; i < j; i, j = i+1, j-1 {
		ids[i], ids[j] = ids[j], ids[i]
	}
	return ids
}
