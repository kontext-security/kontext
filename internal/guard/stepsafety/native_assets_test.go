package stepsafety

import "testing"

// requireEmbeddedModel skips a test that needs the model in a build made with
// the nostepsafetymodel tag. It keys on the tag, not on the files, so a broken
// embed in a normal build still fails.
func requireEmbeddedModel(t *testing.T) {
	t.Helper()
	if !modelEmbedded {
		t.Skip("built with nostepsafetymodel: no embedded step-safety model")
	}
}
