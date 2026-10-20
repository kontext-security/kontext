package endpointconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

const identityFixturePath = "testdata/portable/v3/identity-v3.json"

// Update only when deliberately revising the portable fixture bytes. The cloud
// pins the same digest (FIXTURE_V3_DIGEST in packages/shared endpoint-config).
const identityFixtureSHA256 = "3da75190da4298b16ff781017d06cb82ff342924e57da20b0b6600ae02bcc785"

type identityFixture struct {
	SchemaVersion  string                  `json:"schemaVersion"`
	IdentityDomain string                  `json:"identityDomain"`
	Vectors        []identityFixtureVector `json:"vectors"`
}

type identityFixtureVector struct {
	Name            string `json:"name"`
	ResponseVersion int    `json:"responseVersion"`
	Config          Config `json:"config"`
	Preimage        string `json:"preimage"`
	ConfigIdentity  string `json:"configIdentity"`
}

func TestPortableIdentityFixture(t *testing.T) {
	data, err := os.ReadFile(identityFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if got := hex.EncodeToString(digest[:]); got != identityFixtureSHA256 {
		t.Fatalf("fixture SHA-256 = %s, want %s", got, identityFixtureSHA256)
	}
	var fixture identityFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.SchemaVersion != "endpoint-config-identity-fixture-v3" || fixture.IdentityDomain != identityDomain {
		t.Fatalf("fixture metadata = %#v", fixture)
	}
	// Six: three capture modes crossed with the work-type switch, which is
	// what makes the switch observably part of the identity.
	if len(fixture.Vectors) != 6 {
		t.Fatalf("fixture vector count = %d, want 6", len(fixture.Vectors))
	}
	for _, vector := range fixture.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			if vector.ResponseVersion != ResponseVersion {
				t.Fatalf("responseVersion = %d", vector.ResponseVersion)
			}
			identity, err := ComputeIdentity(vector.Config)
			if err != nil {
				t.Fatal(err)
			}
			if identity != vector.ConfigIdentity {
				t.Fatalf("ComputeIdentity() = %s, want %s", identity, vector.ConfigIdentity)
			}
			preimage, err := json.Marshal([]any{
				identityDomain,
				ResponseVersion,
				string(vector.Config.PayloadCaptureMode),
				*vector.Config.WorkTypeClassification,
			})
			if err != nil {
				t.Fatal(err)
			}
			if string(preimage) != vector.Preimage {
				t.Fatalf("preimage = %s, want %s", preimage, vector.Preimage)
			}
		})
	}
}
