package runtimecore

import (
	"context"
	"testing"
)

func TestResponseWorkRunsOnceAfterResponseEvenIfContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ctx, finish := WithResponseWork(ctx)
	var ran int
	if !AfterResponse(ctx, func() { ran++ }) {
		t.Fatal("work was not registered")
	}
	if ran != 0 {
		t.Fatal("work ran before transport finished response")
	}
	cancel()
	finish()
	finish()
	if ran != 1 {
		t.Fatalf("work ran %d times", ran)
	}
	if AfterResponse(context.Background(), func() { t.Fatal("direct work ran unexpectedly") }) {
		t.Fatal("direct callers must explicitly submit work")
	}
}
