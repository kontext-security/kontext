package cedareval_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/kontext-security/kontext/internal/cedareval"
)

const authorizationV2Digest = "12df68a1e41757dbee2f367105e9618a0743d589aa6ac5cf1e961547533c6d8f"

type authorizationFixtureV2 struct {
	Version  int                      `json:"version"`
	Name     string                   `json:"name"`
	Input    cedareval.ToolUseInputV2 `json:"input"`
	Expected struct {
		Principal entityUID       `json:"principal"`
		Action    entityUID       `json:"action"`
		Resource  entityUID       `json:"resource"`
		Context   json.RawMessage `json:"context"`
		Entities  []struct {
			UID     entityUID      `json:"uid"`
			Attrs   map[string]any `json:"attrs"`
			Parents []entityUID    `json:"parents"`
		} `json:"entities"`
	} `json:"expected"`
}

type entityUID struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func TestPortableAuthorizationV2Fixture(t *testing.T) {
	contents, err := os.ReadFile("testdata/portable/v2/authorization-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	if got := hex.EncodeToString(digest[:]); got != authorizationV2Digest {
		t.Fatalf("fixture digest = %s, want %s", got, authorizationV2Digest)
	}

	var fixtures []authorizationFixtureV2
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixtures); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			request, entities, err := cedareval.BuildRequestV2(fixture.Input)
			if err != nil {
				t.Fatal(err)
			}
			assertUID(t, request.Principal, fixture.Expected.Principal)
			assertUID(t, request.Action, fixture.Expected.Action)
			assertUID(t, request.Resource, fixture.Expected.Resource)

			actualContext, err := json.Marshal(request.Context)
			if err != nil {
				t.Fatal(err)
			}
			var actual, expected any
			if err := json.Unmarshal(actualContext, &actual); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(fixture.Expected.Context, &expected); err != nil {
				t.Fatal(err)
			}
			sortContextSets(actual)
			sortContextSets(expected)
			if !reflect.DeepEqual(actual, expected) {
				t.Fatalf("context = %s, want %s", actualContext, fixture.Expected.Context)
			}
			if len(entities) != len(fixture.Expected.Entities) {
				t.Fatalf("entities = %d, want %d", len(entities), len(fixture.Expected.Entities))
			}
			for _, expectedEntity := range fixture.Expected.Entities {
				found := false
				for uid := range entities {
					if string(uid.Type) == expectedEntity.UID.Type && string(uid.ID) == expectedEntity.UID.ID {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("missing entity %#v", expectedEntity.UID)
				}
			}

			evaluator, err := cedareval.New(`@id("baseline")
permit(principal, action == Kontext::Action::"ToolUse", resource);

@id("force")
forbid(principal, action == Kontext::Action::"ToolUse", resource == Kontext::Tool::"shell")
when { context.shell.facts.contains("git/force=true") };`)
			if err != nil {
				t.Fatal(err)
			}
			result, err := evaluator.EvaluateV2(fixture.Input)
			if err != nil {
				t.Fatal(err)
			}
			if result.Decision != cedareval.DecisionDeny {
				t.Fatalf("decision = %q, want deny", result.Decision)
			}
		})
	}
}

func sortContextSets(value any) {
	context, ok := value.(map[string]any)
	if !ok {
		return
	}
	shell, ok := context["shell"].(map[string]any)
	if !ok {
		return
	}
	for _, field := range []string{"facts", "features"} {
		values, ok := shell[field].([]any)
		if !ok {
			continue
		}
		sort.Slice(values, func(i, j int) bool {
			return values[i].(string) < values[j].(string)
		})
	}
}

func assertUID(t *testing.T, actual interface{ String() string }, expected entityUID) {
	t.Helper()
	want := expected.Type + `::"` + expected.ID + `"`
	if actual.String() != want {
		t.Fatalf("uid = %s, want %s", actual.String(), want)
	}
}
