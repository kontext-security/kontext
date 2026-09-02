package cedareval

import (
	"fmt"
	"sort"
	"unicode/utf16"
	"unicode/utf8"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/kontext-security/kontext/internal/hook"
)

const (
	RequestContractVersion = 1
	PrincipalEntityType    = "Kontext::User"
	ActionEntityType       = "Kontext::Action"
	ToolEntityType         = "Kontext::Tool"
	ToolUseActionID        = "ToolUse"
	PolicyMaxBytes         = 1_048_576
	askAnnotation          = "ask"
	askAnnotationValue     = "prompt"
	idAnnotation           = "id"
)

type EvaluationPrincipal struct {
	EntityType string `json:"entityType"`
	EntityID   string `json:"entityId"`
}

type ToolUseInput struct {
	EvaluationPrincipal EvaluationPrincipal `json:"evaluationPrincipal"`
	ToolName            string              `json:"toolName"`
	ToolInput           map[string]any      `json:"toolInput"`
}

type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
)

type EngineReason struct {
	PolicyID string
	Position cedar.Position
}

type EngineError struct {
	PolicyID string
	Position cedar.Position
	Message  string
}

type EngineDiagnostics struct {
	Reasons []EngineReason
	Errors  []EngineError
}

type Result struct {
	Decision             Decision
	Ask                  bool
	DeterminingPolicyIDs []string
	ContextDiagnostics   []ContextDiagnostic
	EngineDiagnostics    EngineDiagnostics
}

type Evaluator struct {
	policies *cedar.PolicySet
}

func New(policyText string) (*Evaluator, error) {
	if len([]byte(policyText)) > PolicyMaxBytes {
		return nil, fmt.Errorf("cedareval: policy text exceeds %d bytes", PolicyMaxBytes)
	}

	policies, err := cedar.NewPolicySetFromBytes("policy.cedar", []byte(policyText))
	if err != nil {
		return nil, fmt.Errorf("cedareval: parse policy: %w", err)
	}
	if err := validatePolicyMetadata(policies); err != nil {
		return nil, err
	}
	return &Evaluator{policies: policies}, nil
}

func validatePolicyMetadata(policies *cedar.PolicySet) error {
	policyIDs := make([]cedar.PolicyID, 0)
	for policyID := range policies.All() {
		policyIDs = append(policyIDs, policyID)
	}
	sort.Slice(policyIDs, func(i, j int) bool {
		return string(policyIDs[i]) < string(policyIDs[j])
	})

	stableIDs := make(map[string]cedar.PolicyID, len(policyIDs))
	for _, policyID := range policyIDs {
		policy := policies.Get(policyID)
		annotations := policy.Annotations()
		stableID, ok := annotationValue(annotations, idAnnotation)
		if !ok || stableID == "" {
			return fmt.Errorf("cedareval: policy %q has no non-empty @id annotation", policyID)
		}
		if previousPolicyID, duplicate := stableIDs[stableID]; duplicate {
			return fmt.Errorf(
				"cedareval: policies %q and %q have duplicate @id %q",
				previousPolicyID,
				policyID,
				stableID,
			)
		}
		stableIDs[stableID] = policyID

		ask, hasAsk := annotationValue(annotations, askAnnotation)
		if hasAsk && ask != askAnnotationValue {
			return fmt.Errorf("cedareval: policy %q has unsupported @ask value %q", stableID, ask)
		}
	}
	return nil
}

func InputFromEvent(principal EvaluationPrincipal, event hook.Event) (ToolUseInput, error) {
	if event.HookName != hook.HookPreToolUse {
		return ToolUseInput{}, fmt.Errorf("cedareval: hook event %q is not pre-tool-use", event.HookName)
	}
	return ToolUseInput{
		EvaluationPrincipal: principal,
		ToolName:            event.ToolName,
		ToolInput:           event.ToolInput,
	}, nil
}

func BuildRequest(input ToolUseInput) (cedar.Request, []ContextDiagnostic, error) {
	if err := validateInput(input); err != nil {
		return cedar.Request{}, nil, err
	}

	context, diagnostics, err := ConvertToolInput(input.ToolInput)
	if err != nil {
		return cedar.Request{}, nil, err
	}
	return cedar.Request{
		Principal: cedar.NewEntityUID(
			cedar.EntityType(input.EvaluationPrincipal.EntityType),
			cedar.String(input.EvaluationPrincipal.EntityID),
		),
		Action: cedar.NewEntityUID(
			cedar.EntityType(ActionEntityType),
			cedar.String(ToolUseActionID),
		),
		Resource: cedar.NewEntityUID(
			cedar.EntityType(ToolEntityType),
			cedar.String(input.ToolName),
		),
		Context: context,
	}, diagnostics, nil
}

func (e *Evaluator) Evaluate(input ToolUseInput) (Result, error) {
	request, contextDiagnostics, err := BuildRequest(input)
	if err != nil {
		return Result{}, err
	}
	return e.evaluateRequest(request, contextDiagnostics)
}

func (e *Evaluator) evaluateRequest(request cedar.Request, contextDiagnostics []ContextDiagnostic) (Result, error) {
	return e.evaluateRequestWithEntities(request, nil, contextDiagnostics)
}

func (e *Evaluator) evaluateRequestWithEntities(request cedar.Request, entities cedar.EntityMap, contextDiagnostics []ContextDiagnostic) (Result, error) {
	decision, diagnostic := cedar.Authorize(e.policies, entities, request)
	engineDiagnostics := copyEngineDiagnostics(diagnostic)
	determiningPolicyIDs := make([]string, 0, len(diagnostic.Reasons))
	allAsk := len(diagnostic.Reasons) > 0
	for _, reason := range diagnostic.Reasons {
		policy := e.policies.Get(reason.PolicyID)
		if policy == nil {
			return Result{}, fmt.Errorf("cedareval: determining policy %q is missing", reason.PolicyID)
		}
		annotations := policy.Annotations()
		stableID, ok := annotationValue(annotations, idAnnotation)
		if !ok || stableID == "" {
			return Result{}, fmt.Errorf("cedareval: determining policy %q has no @id annotation", reason.PolicyID)
		}
		determiningPolicyIDs = append(determiningPolicyIDs, stableID)

		ask, hasAsk := annotationValue(annotations, askAnnotation)
		if hasAsk && ask != askAnnotationValue {
			return Result{}, fmt.Errorf(
				"cedareval: unsupported @ask value on %s: %s",
				stableID,
				ask,
			)
		}
		allAsk = allAsk && hasAsk
	}
	sort.Strings(determiningPolicyIDs)

	result := Result{
		Decision:             Decision(decision.String()),
		Ask:                  decision == cedar.Allow && allAsk,
		DeterminingPolicyIDs: determiningPolicyIDs,
		ContextDiagnostics:   contextDiagnostics,
		EngineDiagnostics:    engineDiagnostics,
	}
	return result, nil
}

func annotationValue(annotations cedar.Annotations, name string) (string, bool) {
	for key, value := range annotations {
		if string(key) == name {
			return string(value), true
		}
	}
	return "", false
}

func validateInput(input ToolUseInput) error {
	if input.EvaluationPrincipal.EntityType != PrincipalEntityType {
		return fmt.Errorf(
			"cedareval: unsupported principal entity type %q for request contract v%d",
			input.EvaluationPrincipal.EntityType,
			RequestContractVersion,
		)
	}
	if !utf8.ValidString(input.EvaluationPrincipal.EntityID) {
		return fmt.Errorf("cedareval: principal entity id must contain valid UTF-8")
	}
	if stringLength(input.EvaluationPrincipal.EntityID) == 0 || stringLength(input.EvaluationPrincipal.EntityID) > 1024 {
		return fmt.Errorf("cedareval: principal entity id must contain 1 to 1024 characters")
	}
	if !utf8.ValidString(input.ToolName) {
		return fmt.Errorf("cedareval: tool name must contain valid UTF-8")
	}
	if stringLength(input.ToolName) == 0 || stringLength(input.ToolName) > 4096 {
		return fmt.Errorf("cedareval: tool name must contain 1 to 4096 characters")
	}
	if input.ToolInput == nil {
		return fmt.Errorf("cedareval: tool input must be a JSON object")
	}
	return nil
}

func stringLength(value string) int {
	return len(utf16.Encode([]rune(value)))
}

func copyEngineDiagnostics(diagnostic cedar.Diagnostic) EngineDiagnostics {
	result := EngineDiagnostics{
		Reasons: make([]EngineReason, len(diagnostic.Reasons)),
		Errors:  make([]EngineError, len(diagnostic.Errors)),
	}
	for i, reason := range diagnostic.Reasons {
		result.Reasons[i] = EngineReason{
			PolicyID: string(reason.PolicyID),
			Position: reason.Position,
		}
	}
	for i, engineError := range diagnostic.Errors {
		result.Errors[i] = EngineError{
			PolicyID: string(engineError.PolicyID),
			Position: engineError.Position,
			Message:  engineError.Message,
		}
	}
	return result
}
