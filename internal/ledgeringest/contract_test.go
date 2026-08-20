package ledgeringest_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/kontext-security/kontext-cli/internal/ledgeringest"
	"github.com/kontext-security/kontext-cli/internal/payloadcapture"
)

const bundleDir = "../../docs/contracts/ledger-ingest/v1"

// --- bundle integrity -------------------------------------------------------

type bundleManifest struct {
	Contract      string `json:"contract"`
	Release       string `json:"release"`
	SchemaDialect string `json:"schema_dialect"`
	Files         []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"files"`
}

func loadManifest(t *testing.T) (bundleManifest, []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(bundleDir, "manifest.json"))
	if err != nil {
		t.Fatalf("read bundle manifest: %v", err)
	}
	var manifest bundleManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("decode bundle manifest: %v", err)
	}
	return manifest, raw
}

// The manifest digest is the single pin for the whole vendored bundle; the
// manifest digests every other file, and no stray file may hide in the
// bundle directory outside the manifest.
func TestVendoredBundleMatchesPinnedManifest(t *testing.T) {
	manifest, raw := loadManifest(t)

	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != ledgeringest.ManifestDigest {
		t.Fatalf("manifest digest = %s, want %s (re-vendor the bundle and update the pin together)", got, ledgeringest.ManifestDigest)
	}
	if manifest.Release != ledgeringest.ContractRelease {
		t.Fatalf("manifest release = %s, want %s", manifest.Release, ledgeringest.ContractRelease)
	}
	if manifest.Contract != "ledger-ingest/v1" {
		t.Fatalf("manifest contract = %s", manifest.Contract)
	}

	listed := map[string]string{"manifest.json": ""}
	for _, file := range manifest.Files {
		content, err := os.ReadFile(filepath.Join(bundleDir, file.Path))
		if err != nil {
			t.Fatalf("read %s: %v", file.Path, err)
		}
		digest := sha256.Sum256(content)
		if got := hex.EncodeToString(digest[:]); got != file.SHA256 {
			t.Errorf("%s digest = %s, want %s", file.Path, got, file.SHA256)
		}
		listed[filepath.ToSlash(file.Path)] = file.SHA256
	}

	err := filepath.WalkDir(bundleDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		relative, err := filepath.Rel(bundleDir, path)
		if err != nil {
			return err
		}
		if _, ok := listed[filepath.ToSlash(relative)]; !ok {
			t.Errorf("bundle file %s is not listed in the manifest", relative)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk bundle: %v", err)
	}
}

// --- conformance corpus -----------------------------------------------------

type fixtureExpectation struct {
	Status      int    `json:"status"`
	Code        string `json:"code"`
	Pointer     string `json:"pointer"`
	Stage       string `json:"stage"`
	Disposition string `json:"disposition"`
}

type contractFixture struct {
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Kind        string             `json:"kind"`
	Requests    []json.RawMessage  `json:"requests"`
	Expected    fixtureExpectation `json:"expected"`
}

type fixtureManifest struct {
	Fixtures []struct {
		Name string `json:"name"`
		Kind string `json:"kind"`
		Path string `json:"path"`
	} `json:"fixtures"`
}

func loadFixtures(t *testing.T) []contractFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(bundleDir, "fixtures", "manifest.json"))
	if err != nil {
		t.Fatalf("read fixture manifest: %v", err)
	}
	var manifest fixtureManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("decode fixture manifest: %v", err)
	}
	if len(manifest.Fixtures) == 0 {
		t.Fatal("fixture manifest is empty")
	}

	fixtures := make([]contractFixture, 0, len(manifest.Fixtures))
	for _, entry := range manifest.Fixtures {
		content, err := os.ReadFile(filepath.Join(bundleDir, filepath.FromSlash(entry.Path)))
		if err != nil {
			t.Fatalf("read fixture %s: %v", entry.Name, err)
		}
		var fixture contractFixture
		if err := json.Unmarshal(content, &fixture); err != nil {
			t.Fatalf("decode fixture %s: %v", entry.Name, err)
		}
		fixtures = append(fixtures, fixture)
	}
	return fixtures
}

func compileSchema(t *testing.T, fileName string) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(bundleDir, fileName))
	if err != nil {
		t.Fatalf("read %s: %v", fileName, err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse %s: %v", fileName, err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource(fileName, doc); err != nil {
		t.Fatalf("add schema resource: %v", err)
	}
	schema, err := compiler.Compile(fileName)
	if err != nil {
		t.Fatalf("compile %s: %v", fileName, err)
	}
	return schema
}

// Every schema document in the bundle must compile standalone.
func TestPublishedSchemasCompile(t *testing.T) {
	for _, fileName := range []string{
		"ledger-batch.schema.json",
		"session-record.schema.json",
		"action-record.schema.json",
		"receipt-record.schema.json",
	} {
		compileSchema(t, fileName)
	}
}

func TestCorpusCoverage(t *testing.T) {
	fixtures := loadFixtures(t)
	counts := map[string]int{}
	names := map[string]bool{}
	for _, fixture := range fixtures {
		counts[fixture.Kind]++
		if names[fixture.Name] {
			t.Errorf("duplicate fixture name %s", fixture.Name)
		}
		names[fixture.Name] = true
	}
	if counts["valid"] < 8 || counts["invalid"]+counts["hybrid"] < 16 ||
		counts["compatibility"] < 4 || counts["replay"] < 4 {
		t.Fatalf("corpus coverage too small: %v", counts)
	}
}

// The cross-language agreement proof: the published batch schema must accept
// and reject exactly what the corpus declares, judged from Go. `structural`
// rejections fail the schema here too; `semantic` rules are server-owned, so
// those bodies pass the schema layer by design.
func TestCorpusAgainstBatchSchema(t *testing.T) {
	schema := compileSchema(t, "ledger-batch.schema.json")
	validate := func(raw json.RawMessage) error {
		value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			return fmt.Errorf("decode request: %w", err)
		}
		return schema.Validate(value)
	}

	for _, fixture := range loadFixtures(t) {
		t.Run(fixture.Name, func(t *testing.T) {
			switch fixture.Kind {
			case "valid", "replay":
				for index, request := range fixture.Requests {
					if err := validate(request); err != nil {
						t.Errorf("request[%d] should validate: %v", index, err)
					}
				}
			case "invalid":
				err := validate(fixture.Requests[len(fixture.Requests)-1])
				switch fixture.Expected.Stage {
				case "structural":
					if err == nil {
						t.Error("structural fixture must fail the published schema")
					}
				case "semantic":
					if err != nil {
						t.Errorf("semantic fixture must pass the schema layer: %v", err)
					}
				default:
					t.Errorf("unknown stage %q", fixture.Expected.Stage)
				}
			case "hybrid", "compatibility":
				// Neither form may ever validate as clean v1.
				for index, request := range fixture.Requests {
					if err := validate(request); err == nil {
						t.Errorf("request[%d] must not validate as clean v1", index)
					}
				}
			default:
				t.Errorf("unknown fixture kind %q", fixture.Kind)
			}
		})
	}
}

// --- receipt canonicalization ----------------------------------------------

type fixtureReceipt struct {
	Payload json.RawMessage `json:"payload"`
	Proof   struct {
		ReceiptHash string `json:"receipt_hash"`
	} `json:"proof"`
}

type fixtureBatch struct {
	Receipts []fixtureReceipt `json:"receipts"`
}

// Clean v1 receipt hashes are sha256 over the RFC 8785 (JCS) bytes of the
// payload. Recomputing every corpus hash with the CLI's own canonicalizer
// proves byte-for-byte agreement between the Go and server implementations —
// the property the contract's tamper-evidence claims rest on.
func TestCorpusReceiptHashesAgreeWithJCS(t *testing.T) {
	verified := 0
	for _, fixture := range loadFixtures(t) {
		if fixture.Kind != "valid" && fixture.Kind != "replay" {
			continue
		}
		for _, raw := range fixture.Requests {
			var batch fixtureBatch
			if err := json.Unmarshal(raw, &batch); err != nil {
				t.Fatalf("%s: decode batch: %v", fixture.Name, err)
			}
			for index, receipt := range batch.Receipts {
				var payload any
				if err := json.Unmarshal(receipt.Payload, &payload); err != nil {
					t.Fatalf("%s: decode receipt payload: %v", fixture.Name, err)
				}
				canonical, err := payloadcapture.CanonicalJSON(payload)
				if err != nil {
					t.Fatalf("%s: canonicalize receipt payload: %v", fixture.Name, err)
				}
				digest := sha256.Sum256(canonical)
				got := "sha256:" + hex.EncodeToString(digest[:])
				if got != receipt.Proof.ReceiptHash {
					t.Errorf("%s: receipts[%d] hash = %s, want %s", fixture.Name, index, got, receipt.Proof.ReceiptHash)
				}
				if !strings.HasPrefix(receipt.Proof.ReceiptHash, "sha256:") {
					t.Errorf("%s: receipts[%d] hash missing sha256: prefix", fixture.Name, index)
				}
				verified++
			}
		}
	}
	if verified == 0 {
		t.Fatal("corpus contains no receipts to verify")
	}
}
