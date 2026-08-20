package judge

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kontext-security/kontext/internal/guard/decision"
)

const (
	DecisionAllow = decision.Allow
	DecisionDeny  = decision.Deny
)

type Decision = decision.Decision

type RiskLevel string

const (
	RiskLevelLow    RiskLevel = "low"
	RiskLevelMedium RiskLevel = "medium"
	RiskLevelHigh   RiskLevel = "high"
)

type Input struct {
	ToolName           string    `json:"tool_name,omitempty"`
	ExplicitUserIntent bool      `json:"explicit_user_intent,omitempty"`
	ToolInput          ToolInput `json:"tool_input"`
}

type ToolInput struct {
	Command string `json:"command,omitempty"`
	Path    string `json:"path,omitempty"`
	Request string `json:"request,omitempty"`
}

type Output struct {
	Decision   Decision  `json:"decision"`
	RiskLevel  RiskLevel `json:"risk_level"`
	Categories []string  `json:"categories"`
	Reason     string    `json:"reason"`
}

type Metadata struct {
	Runtime     string
	Model       string
	DurationMs  int64
	FailureKind string
}

type Result struct {
	Output   Output
	Metadata Metadata
}

type Judge interface {
	Decide(context.Context, Input) (Result, error)
}

type MetadataProvider interface {
	Metadata() Metadata
}

const (
	FailureUnavailable   = "unavailable"
	FailureTimeout       = "timeout"
	FailureInvalidOutput = "invalid_output"
)

type Error struct {
	Kind string
	Err  error
}

func (e Error) Error() string {
	if e.Err == nil {
		return e.Kind
	}
	return fmt.Sprintf("%s: %v", e.Kind, e.Err)
}

func (e Error) Unwrap() error {
	return e.Err
}

func FailureKind(err error) string {
	if err == nil {
		return ""
	}
	var judgeErr Error
	if errors.As(err, &judgeErr) && judgeErr.Kind != "" {
		return judgeErr.Kind
	}
	return FailureUnavailable
}

func ValidateOutput(output Output) error {
	switch output.Decision {
	case DecisionAllow, DecisionDeny:
	default:
		return fmt.Errorf("invalid decision %q", output.Decision)
	}
	switch output.RiskLevel {
	case RiskLevelLow, RiskLevelMedium, RiskLevelHigh:
	default:
		return fmt.Errorf("invalid risk_level %q", output.RiskLevel)
	}
	if strings.TrimSpace(output.Reason) == "" {
		return errors.New("reason is required")
	}
	if len(output.Categories) > 12 {
		return errors.New("too many categories")
	}
	for _, category := range output.Categories {
		category = strings.TrimSpace(category)
		if category == "" {
			return errors.New("empty category")
		}
		if category == "short_snake_case_category" ||
			category == "one_or_more_specific_risk_or_safety_labels" ||
			category == "one_or_more_short_snake_case_labels" {
			return fmt.Errorf("placeholder category %q", category)
		}
	}
	return nil
}
