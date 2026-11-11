package ledgerfact

import (
	"math"
	"regexp"
)

// ClassifierImpact is Kestrel Impact's independent, advisory capability signal.
// It is optional so historical signed facts keep their exact serialized shape.
type ClassifierImpact struct {
	ModelVersion     string   `json:"model_version"`
	ExtractorVersion string   `json:"extractor_version"`
	ModelSHA256      string   `json:"model_sha256"`
	Status           string   `json:"status"`
	Score            *float64 `json:"score"`
	Threshold        float64  `json:"threshold"`
	Verdict          string   `json:"verdict"`
	Enforced         bool     `json:"enforced"`
}

var impactSHA256 = regexp.MustCompile(`^[a-f0-9]{64}$`)

func validateImpact(v *ClassifierImpact, invalid func(string, ...any)) {
	if v == nil {
		return
	}
	if v.ModelVersion == "" || v.ExtractorVersion == "" || !impactSHA256.MatchString(v.ModelSHA256) {
		invalid("classifier.impact requires model/extractor provenance")
	}
	if v.Enforced {
		invalid("classifier.impact must be advisory")
	}
	if math.IsNaN(v.Threshold) || math.IsInf(v.Threshold, 0) {
		invalid("classifier.impact.threshold must be finite")
	}
	assessed := v.Status == "parsed" || v.Status == "syntax_error_text_only"
	switch v.Status {
	case "parsed", "syntax_error_text_only", "limit_exceeded", "model_unavailable", "inference_error":
	default:
		invalid("classifier.impact.status is unknown")
	}
	if !assessed {
		if v.Score != nil || v.Verdict != "not_assessed" {
			invalid("classifier.impact unassessed results require null score and not_assessed verdict")
		}
		return
	}
	if v.Score == nil || math.IsNaN(*v.Score) || math.IsInf(*v.Score, 0) {
		invalid("classifier.impact assessed results require finite score")
		return
	}
	want := "below_threshold"
	if *v.Score >= v.Threshold {
		want = "flagged"
	}
	if v.Verdict != want {
		invalid("classifier.impact verdict disagrees with margin/threshold")
	}
}
