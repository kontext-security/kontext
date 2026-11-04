package runtimehost

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCloseGivesUpOnAStuckStoreClose(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	host := &Host{closeStore: func() error {
		<-release
		return nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	returned := make(chan error, 1)
	go func() { returned <- host.Close(ctx) }()
	select {
	case err := <-returned:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Close() = %v, want the deadline", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close waited past its deadline for the store to close")
	}
}

func TestCloseReportsAStoreCloseError(t *testing.T) {
	failed := errors.New("close failed")
	host := &Host{closeStore: func() error { return failed }}
	if err := host.Close(context.Background()); !errors.Is(err, failed) {
		t.Errorf("Close() = %v, want %v", err, failed)
	}
}
