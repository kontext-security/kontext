package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Each proxy run logs where Codex's route stands at its first request, and
// again only when that changes.
func TestTheProxyLogsWhereTheRouteStands(t *testing.T) {
	answers := []struct {
		held bool
		err  error
	}{{true, nil}, {true, nil}, {false, nil}, {false, nil}, {false, errors.New("config.toml: permission denied")}, {true, nil}}
	next := 0
	var lines []string
	held := reportHeld(func(context.Context) (bool, error) {
		answer := answers[next]
		next++
		return answer.held, answer.err
	}, func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) })
	for _, answer := range answers {
		if got := held(context.Background()); got != answer.held {
			t.Fatalf("held = %v, want %v", got, answer.held)
		}
	}
	want := []string{
		"Codex route held by a daemon",
		"Codex route not held by a daemon: taken away; passing requests through",
		"Codex route not held by a daemon, and not taken away: config.toml: permission denied",
		"Codex route held by a daemon",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("logged:\n%s", strings.Join(lines, "\n"))
	}
}
