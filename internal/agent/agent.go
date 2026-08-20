package agent

import "github.com/kontext-security/kontext/internal/hook"

type Agent interface {
	Name() string

	DecodeHookInput(input []byte) (hook.Event, error)

	EncodeHookResult(event hook.Event, result hook.Result) ([]byte, error)
}

type Aliaser interface {
	Aliases() []string
}

var registry = map[string]Agent{}
var aliases = map[string]Agent{}

func Register(a Agent) {
	registry[a.Name()] = a
	if aliaser, ok := a.(Aliaser); ok {
		for _, alias := range aliaser.Aliases() {
			aliases[alias] = a
		}
	}
}

func Get(name string) (Agent, bool) {
	if a, ok := registry[name]; ok {
		return a, true
	}
	a, ok := aliases[name]
	return a, ok
}

func Names() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}
