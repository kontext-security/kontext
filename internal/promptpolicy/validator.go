package promptpolicy

import (
	"errors"
	"time"
)

type ExpectedAudience struct {
	OrganizationID           string
	InstallationID           string
	AuthorizationSessionID   string
	PromptSequence           uint64
	ParentDeploymentIdentity string
	RolloutMode              string
}

// ActivationValidator checks that a decoded bundle is the exact, current
// response requested for one prompt before the session manager activates it.
type ActivationValidator struct {
	now func() time.Time
}

func NewActivationValidator() *ActivationValidator {
	return &ActivationValidator{now: time.Now}
}

func (v *ActivationValidator) Validate(bundle Bundle, expected ExpectedAudience) error {
	if err := bundle.Validate(); err != nil {
		return err
	}
	if (expected.OrganizationID != "" && bundle.Audience.OrganizationID != expected.OrganizationID) ||
		bundle.Audience.InstallationID != expected.InstallationID ||
		bundle.Audience.AuthorizationSessionID != expected.AuthorizationSessionID ||
		bundle.Audience.PromptSequence != expected.PromptSequence ||
		bundle.Parent.DeploymentIdentity != expected.ParentDeploymentIdentity ||
		(expected.RolloutMode != "" && bundle.RolloutMode != expected.RolloutMode) {
		return errors.New("prompt-policy audience or parent mismatch")
	}
	validFrom, _ := time.Parse(time.RFC3339Nano, bundle.ValidFrom)
	expiresAt, _ := time.Parse(time.RFC3339Nano, bundle.ExpiresAt)
	now := v.now()
	if now.Before(validFrom) || !now.Before(expiresAt) {
		return errors.New("prompt-policy bundle is outside its validity window")
	}
	return nil
}
