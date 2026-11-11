package impactfeatures

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
)

type Block struct {
	Vocabulary map[string]int `json:"vocabulary"`
	Weights    []float64      `json:"weights"`
	IDF        []float64      `json:"idf,omitempty"`
	Scale      []float64      `json:"scale,omitempty"`
}
type Model struct {
	Schema           string  `json:"schema"`
	Version          string  `json:"version"`
	ExtractorVersion string  `json:"extractor_version"`
	Intercept        float64 `json:"intercept"`
	Characters       Block   `json:"characters"`
	Tokens           Block   `json:"tokens"`
	Structure        Block   `json:"structure"`
}
type Prediction struct {
	Version          string   `json:"model_version"`
	ExtractorVersion string   `json:"extractor_version"`
	Status           string   `json:"status"`
	Score            *float64 `json:"score"`
}

// LoadModelBytes decodes an artifact supplied by the embedding application.
func LoadModelBytes(b []byte) (*Model, error) {
	var err error
	var m Model
	if err = json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m.Schema != "kontext-command-risk-linear/1" || m.ExtractorVersion != TrainingVersion || m.Version == "" {
		return nil, fmt.Errorf("unsupported artifact contract")
	}
	for j, x := range []Block{m.Characters, m.Tokens, m.Structure} {
		n := len(x.Weights)
		if len(x.Vocabulary) != n {
			return nil, fmt.Errorf("vocabulary dimensions")
		}
		seen := map[int]bool{}
		for _, i := range x.Vocabulary {
			if i < 0 || i >= n || seen[i] {
				return nil, fmt.Errorf("feature indices")
			}
			seen[i] = true
		}
		if j < 2 && len(x.IDF) != n || j == 2 && len(x.Scale) != n {
			return nil, fmt.Errorf("normalizer dimensions")
		}
		for _, v := range append(append(append([]float64{}, x.Weights...), x.IDF...), x.Scale...) {
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return nil, fmt.Errorf("nonfinite artifact")
			}
		}
		for _, v := range x.Scale {
			if v <= 0 {
				return nil, fmt.Errorf("invalid scale")
			}
		}
	}
	if math.IsNaN(m.Intercept) || math.IsInf(m.Intercept, 0) {
		return nil, fmt.Errorf("nonfinite intercept")
	}
	return &m, nil
}
func textScore(x map[string]float64, b Block) float64 {
	indices := make([]int, 0, len(x))
	values := map[int]float64{}
	for k, c := range x {
		if i, ok := b.Vocabulary[k]; ok && c > 0 {
			indices = append(indices, i)
			values[i] = (1 + math.Log(c)) * b.IDF[i]
		}
	}
	sort.Ints(indices)
	norm, dot := 0., 0.
	for _, i := range indices {
		v := values[i]
		norm += v * v
		dot += v * b.Weights[i]
	}
	if norm == 0 {
		return 0
	}
	return dot / math.Sqrt(norm)
}
func (m *Model) Score(f Features) Prediction {
	p := Prediction{Version: m.Version, ExtractorVersion: Version, Status: f.Status}
	if f.Status == "limit_exceeded" {
		return p
	}
	s := m.Intercept + textScore(f.Characters, m.Characters) + textScore(f.Tokens, m.Tokens)
	keys := make([]string, 0, len(f.Structure))
	for k := range f.Structure {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if i, ok := m.Structure.Vocabulary[k]; ok {
			s += f.Structure[k] / m.Structure.Scale[i] * m.Structure.Weights[i]
		}
	}
	p.Score = &s
	return p
}
