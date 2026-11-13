//go:build !windows

package credstore

import (
	"errors"
	"testing"
)

func TestUnsupportedOffWindows(t *testing.T) {
	if _, err := Read("x"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Read = %v, want ErrUnsupported", err)
	}
	if err := Write("x", "y"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Write = %v, want ErrUnsupported", err)
	}
	if err := Delete("x"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Delete = %v, want ErrUnsupported", err)
	}
}
