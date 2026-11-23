package endpointconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
)

// The portable fixtures of the versions this build reads. Update a digest
// only when deliberately revising that fixture's bytes. The cloud pins the
// same digests (FIXTURE_V6_DIGEST and FIXTURE_V7_DIGEST in packages/shared
// endpoint-config).
var identityFixtures = []struct {
	path    string
	sha256  string
	version int
	// vectors is three capture modes crossed with both values of each
	// switch, which is what makes each switch observably part of the
	// identity; v7 adds hook states, generations and nonces on top.
	vectors int
}{
	{path: "testdata/portable/v6/identity-v6.json", sha256: "89386eade1aa943e41638dc39b2fdb0b9b51e034e316f6344244937c61327f6d", version: FallbackResponseVersion, vectors: 48},
	{path: "testdata/portable/v7/identity-v7.json", sha256: "8ec670da4cf964cb82aa3c24ea0cc0db3eb045758fd84f18749e3e7ca6eb3ad3", version: ResponseVersion, vectors: 60},
}

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
	for _, file := range identityFixtures {
		t.Run(file.path, func(t *testing.T) {
			data, err := os.ReadFile(file.path)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(data)
			if got := hex.EncodeToString(digest[:]); got != file.sha256 {
				t.Fatalf("fixture SHA-256 = %s, want %s", got, file.sha256)
			}
			var fixture identityFixture
			if err := json.Unmarshal(data, &fixture); err != nil {
				t.Fatal(err)
			}
			if fixture.SchemaVersion != "endpoint-config-identity-fixture-v"+strconv.Itoa(file.version) || fixture.IdentityDomain != identityDomain(file.version) {
				t.Fatalf("fixture metadata = %#v", fixture)
			}
			if len(fixture.Vectors) != file.vectors {
				t.Fatalf("fixture vector count = %d, want %d", len(fixture.Vectors), file.vectors)
			}
			for _, vector := range fixture.Vectors {
				t.Run(vector.Name, func(t *testing.T) {
					if vector.ResponseVersion != file.version {
						t.Fatalf("responseVersion = %d", vector.ResponseVersion)
					}
					response := Response{ResponseVersion: vector.ResponseVersion, Config: vector.Config, ConfigIdentity: vector.ConfigIdentity}
					if err := response.Validate(); err != nil {
						t.Fatal(err)
					}
					fields := []any{
						identityDomain(file.version),
						file.version,
						string(vector.Config.PayloadCaptureMode),
						*vector.Config.WorkTypeClassification,
						*vector.Config.ToolOutputCompaction,
					}
					if vector.Config.CodexProxy != nil {
						fields = append(fields, *vector.Config.CodexProxy)
					}
					if vector.Config.HookInventory != nil {
						fields = append(fields, *vector.Config.HookInventory)
					}
					if state := vector.Config.HookState; state != nil {
						fields = append(fields, state.Desired, state.Generation, state.RepairNonce)
					}
					preimage, err := json.Marshal(fields)
					if err != nil {
						t.Fatal(err)
					}
					if string(preimage) != vector.Preimage {
						t.Fatalf("preimage = %s, want %s", preimage, vector.Preimage)
					}
				})
			}
		})
	}
}
