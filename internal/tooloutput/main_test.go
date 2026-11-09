package tooloutput

import (
	"os"
	"testing"
)

// The Read path stays covered: compaction of Read is off in production (see
// compactRead), so the tests turn it on and TestReadIsNotACandidateByDefault
// turns it off again.
func TestMain(m *testing.M) {
	compactRead = true
	os.Exit(m.Run())
}
