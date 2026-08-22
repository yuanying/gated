package proxy

import (
	"testing"
	"time"
)

// The tests beside this one prove the deadlines work, with values short enough
// to run in a test. This one says what the values actually are in a deployment
// (ADR 0030), which no behavioural test can check without waiting minutes.
func TestTheDefaultDeadlinesAreTheOnesDecided(t *testing.T) {
	handler := &Handler{}
	if got := handler.bodyReadTimeout(); got != 60*time.Second {
		t.Errorf("the body read deadline = %v, want %v", got, 60*time.Second)
	}
	if got := handler.responseWriteTimeout(); got != 60*time.Second {
		t.Errorf("the response write deadline = %v, want %v", got, 60*time.Second)
	}

	server := (&Servers{}).newServer(nil)
	if got := server.IdleTimeout; got != 90*time.Second {
		t.Errorf("the idle deadline = %v, want %v", got, 90*time.Second)
	}
	if got := server.ReadHeaderTimeout; got != 20*time.Second {
		t.Errorf("the header deadline = %v, want %v", got, 20*time.Second)
	}
}

func TestAValueGivenBeatsTheDefault(t *testing.T) {
	handler := &Handler{BodyReadTimeout: time.Second, ResponseWriteTimeout: 2 * time.Second}
	if got := handler.bodyReadTimeout(); got != time.Second {
		t.Errorf("the body read deadline = %v, want %v", got, time.Second)
	}
	if got := handler.responseWriteTimeout(); got != 2*time.Second {
		t.Errorf("the response write deadline = %v, want %v", got, 2*time.Second)
	}

	server := (&Servers{IdleTimeout: 3 * time.Second, ReadHeaderTimeout: 4 * time.Second}).newServer(nil)
	if got := server.IdleTimeout; got != 3*time.Second {
		t.Errorf("the idle deadline = %v, want %v", got, 3*time.Second)
	}
	if got := server.ReadHeaderTimeout; got != 4*time.Second {
		t.Errorf("the header deadline = %v, want %v", got, 4*time.Second)
	}
}
