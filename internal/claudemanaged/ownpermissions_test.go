package claudemanaged

import (
	"encoding/json"
	"testing"
)

// A drop-in is ours with the rule of this OS, and with the macOS rule that
// early Windows builds wrote there; anything else in its permissions is not.
func TestOwnPermissionsAcceptsTheRuleOfThisOSAndTheOldOne(t *testing.T) {
	for name, test := range map[string]struct {
		allow []string
		want  bool
	}{
		"the rule of this OS":      {[]string{SavedOutputReadRule}, true},
		"the rule as macOS has it": {[]string{macOSSavedOutputReadRule}, true},
		"another rule":             {[]string{"Read(~/**)"}, false},
		"both rules":               {[]string{SavedOutputReadRule, macOSSavedOutputReadRule}, false},
		"no rule":                  {nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(map[string][]string{"allow": test.allow})
			if err != nil {
				t.Fatal(err)
			}
			if got := ownPermissions(data); got != test.want {
				t.Fatalf("ownPermissions(%s) = %v, want %v", data, got, test.want)
			}
		})
	}
	if ownPermissions(json.RawMessage(`{"allow":["` + SavedOutputReadRule + `"],"deny":[]}`)) {
		t.Fatal("ownPermissions accepts permissions with a second key")
	}
}
