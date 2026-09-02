package cedareval

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	PolicyHashDomain         = "kontext:cedar-policy:v1\x00"
	DeploymentIdentityDomain = "kontext:cedar-deployment:v2"
	SchemaHashDomain         = "kontext:cedar-schema:v2\x00"
	DeploymentV2Domain       = "kontext:cedar-deployment:v3"
)

type DeploymentIdentityInput struct {
	ResponseVersion        int
	RequestContractVersion int
	PolicyHash             string
	RolloutMode            string
	EvaluationPrincipal    EvaluationPrincipal
}

func ComputePolicyHash(policyText string) string {
	sum := sha256.Sum256([]byte(PolicyHashDomain + policyText))
	return hex.EncodeToString(sum[:])
}

func DeploymentIdentityPreimage(input DeploymentIdentityInput) (string, error) {
	stringsToValidate := []string{
		input.PolicyHash,
		input.RolloutMode,
		input.EvaluationPrincipal.EntityType,
		input.EvaluationPrincipal.EntityID,
	}
	for _, value := range stringsToValidate {
		if !utf8.ValidString(value) {
			return "", fmt.Errorf("cedareval: deployment identity contains invalid utf-8")
		}
	}

	var builder strings.Builder
	builder.WriteByte('[')
	appendJSONString(&builder, DeploymentIdentityDomain)
	builder.WriteByte(',')
	builder.WriteString(strconv.Itoa(input.ResponseVersion))
	builder.WriteByte(',')
	builder.WriteString(strconv.Itoa(input.RequestContractVersion))
	for _, value := range stringsToValidate {
		builder.WriteByte(',')
		appendJSONString(&builder, value)
	}
	builder.WriteByte(']')
	return builder.String(), nil
}

// appendJSONString matches JSON.stringify for valid UTF-8 strings. In
// particular it leaves HTML-sensitive characters and U+2028/U+2029 literal;
// encoding/json intentionally escapes the latter and would change the
// cross-runtime deployment identity preimage.
func appendJSONString(builder *strings.Builder, value string) {
	builder.WriteByte('"')
	for _, char := range value {
		switch char {
		case '"', '\\':
			builder.WriteByte('\\')
			builder.WriteRune(char)
		case '\b':
			builder.WriteString(`\b`)
		case '\t':
			builder.WriteString(`\t`)
		case '\n':
			builder.WriteString(`\n`)
		case '\f':
			builder.WriteString(`\f`)
		case '\r':
			builder.WriteString(`\r`)
		default:
			if char < 0x20 {
				builder.WriteString(`\u00`)
				builder.WriteByte("0123456789abcdef"[byte(char)>>4])
				builder.WriteByte("0123456789abcdef"[byte(char)&0x0f])
				continue
			}
			builder.WriteRune(char)
		}
	}
	builder.WriteByte('"')
}

func ComputeDeploymentIdentity(input DeploymentIdentityInput) (string, error) {
	preimage, err := DeploymentIdentityPreimage(input)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(preimage))
	return hex.EncodeToString(sum[:]), nil
}

type DeploymentIdentityV2Input struct {
	ResponseVersion        int
	RequestContractVersion int
	PolicySetSourceHash    string
	SchemaHash             string
	ToolCatalogDigest      string
	RolloutMode            string
	EvaluationPrincipal    EvaluationPrincipal
}

func ComputeSchemaHash(schemaSource string) string {
	sum := sha256.Sum256([]byte(SchemaHashDomain + schemaSource))
	return hex.EncodeToString(sum[:])
}

func DeploymentIdentityV2Preimage(input DeploymentIdentityV2Input) (string, error) {
	stringsToValidate := []string{
		input.PolicySetSourceHash,
		input.SchemaHash,
		input.ToolCatalogDigest,
		input.RolloutMode,
		input.EvaluationPrincipal.EntityType,
		input.EvaluationPrincipal.EntityID,
	}
	for _, value := range stringsToValidate {
		if !utf8.ValidString(value) {
			return "", fmt.Errorf("cedareval: deployment identity contains invalid utf-8")
		}
	}

	var builder strings.Builder
	builder.WriteByte('[')
	appendJSONString(&builder, DeploymentV2Domain)
	builder.WriteByte(',')
	builder.WriteString(strconv.Itoa(input.ResponseVersion))
	builder.WriteByte(',')
	builder.WriteString(strconv.Itoa(input.RequestContractVersion))
	for _, value := range stringsToValidate {
		builder.WriteByte(',')
		appendJSONString(&builder, value)
	}
	builder.WriteByte(']')
	return builder.String(), nil
}

func ComputeDeploymentIdentityV2(input DeploymentIdentityV2Input) (string, error) {
	preimage, err := DeploymentIdentityV2Preimage(input)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(preimage))
	return hex.EncodeToString(sum[:]), nil
}
