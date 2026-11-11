package riskclassifier

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	_ "embed"
	"fmt"
	"io"
	"math"
	"sync"

	"github.com/kontext-security/kontext/internal/guard/riskclassifier/impactfeatures"
	"github.com/kontext-security/kontext/internal/ledgerfact"
)

const (
	ImpactThreshold    = 1.1957946473415046
	ImpactModelVersion = "command-risk-process/9-P_process"
	ImpactModelSHA256  = "7105b32a4ce7c98f9efa1cba414d4f285f27c44d71137cef4829b045310b5e0d"
)

//go:embed model/impact.json.gz
var embeddedImpact []byte

// ImpactVerdict describes command capability, never permission or intent.
// Its score is a signed margin, not a probability. A nil score is unassessed.
type ImpactVerdict = ledgerfact.ClassifierImpact

// ImpactModel is immutable after initialization and safe for concurrent use.
type ImpactModel struct{ model *impactfeatures.Model }

var loadImpact = sync.OnceValues(func() (*ImpactModel, error) {
	z, err := gzip.NewReader(bytes.NewReader(embeddedImpact))
	if err != nil {
		return nil, fmt.Errorf("impact artifact compression: %w", err)
	}
	defer z.Close()
	data, err := io.ReadAll(io.LimitReader(z, 16*1024*1024+1))
	if err != nil || len(data) > 16*1024*1024 {
		return nil, fmt.Errorf("impact artifact unreadable or oversized")
	}
	if err := validateImpactModel(data); err != nil {
		return nil, err
	}
	m, err := impactfeatures.LoadModelBytes(data)
	if err != nil {
		return nil, fmt.Errorf("impact artifact contract: %w", err)
	}
	return &ImpactModel{model: m}, nil
})

func validateImpactModel(data []byte) error {
	if fmt.Sprintf("%x", sha256.Sum256(data)) != ImpactModelSHA256 {
		return fmt.Errorf("impact artifact checksum mismatch")
	}
	return nil
}

// LoadImpactModel verifies and loads the embedded frozen artifact once per process.
func LoadImpactModel() (*ImpactModel, error) { return loadImpact() }

func impactNotAssessed(status string) ImpactVerdict {
	return ImpactVerdict{ModelVersion: ImpactModelVersion, ExtractorVersion: impactfeatures.Version,
		ModelSHA256: ImpactModelSHA256, Threshold: ImpactThreshold, Status: status,
		Verdict: "not_assessed", Enforced: false}
}

func (m *ImpactModel) Classify(command string) (v ImpactVerdict) {
	v = impactNotAssessed("inference_error")
	// Annotation failure must never interrupt a tool call or disable old Kestrel.
	// Do not persist panic/error text, which could contain command material.
	defer func() {
		if recover() != nil {
			v = impactNotAssessed("inference_error")
		}
	}()
	if m == nil || m.model == nil {
		return impactNotAssessed("model_unavailable")
	}
	p := m.model.Score(impactfeatures.Extract(command))
	v.Status = p.Status
	if p.Score == nil {
		return v
	}
	if math.IsNaN(*p.Score) || math.IsInf(*p.Score, 0) {
		return impactNotAssessed("inference_error")
	}
	v.Score = p.Score
	v.Verdict = "below_threshold"
	if *p.Score >= ImpactThreshold {
		v.Verdict = "flagged"
	}
	return v
}
