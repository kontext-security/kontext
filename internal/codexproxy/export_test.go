package codexproxy

// The mock backend, for the tests in package codexproxy_test, which run Codex
// through the router's real launchd job.
type E2EBackend = e2eBackend

var E2ELogin = e2eLogin

// Responses counts the model requests the backend answered.
func (b *e2eBackend) Responses() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.responses)
}
