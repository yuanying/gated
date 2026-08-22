package main

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
)

// Being removed from a Service's endpoints and being sent SIGTERM are
// independent, so a replica that stops listening the moment it is signalled
// refuses the requests routed to it in between. The image has no shell to
// sleep in, so the wait is gated's own.
func TestShutdownIsHeldOffForTheDelay(t *testing.T) {
	parent, stop := context.WithCancel(context.Background())
	ctx := afterShutdownDelay(parent, 100*time.Millisecond, logr.Discard())

	stop()

	select {
	case <-ctx.Done():
		t.Fatal("the shutdown started as soon as the signal arrived, leaving no time for the endpoint removal to spread")
	case <-time.After(20 * time.Millisecond):
	}

	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the shutdown never started")
	}
}

// Nothing is running yet, so nothing should be waited for.
func TestShutdownIsNotHeldOffBeforeTheSignal(t *testing.T) {
	parent, stop := context.WithCancel(context.Background())
	defer stop()

	ctx := afterShutdownDelay(parent, time.Hour, logr.Discard())
	select {
	case <-ctx.Done():
		t.Fatal("the context was cancelled without a signal")
	case <-time.After(20 * time.Millisecond):
	}
}

// A delay of zero is the way to ask for the old behaviour, and it must not
// leave a goroutine or a second context behind to get it.
func TestNoShutdownDelayHandsBackTheSameContext(t *testing.T) {
	parent, stop := context.WithCancel(context.Background())
	defer stop()

	if got := afterShutdownDelay(parent, 0, logr.Discard()); got != parent {
		t.Errorf("afterShutdownDelay(parent, 0) = %v, want the context it was given", got)
	}
}
