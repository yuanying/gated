package accesstoken

import (
	"sync"
	"time"
)

// DefaultUsageResolution is how close together two recorded uses of the same
// token are allowed to be.
//
// The last-used time answers "is anybody still using this?", which is a
// question about days. Recording every use would mean a write to the API
// server on every request to a protected registry — a cost paid for a
// precision nobody reads (ADR 0004 asks only that the time be recorded).
const DefaultUsageResolution = time.Minute

// Ref locates an AccessToken.
type Ref struct {
	Namespace string
	Name      string
}

// Uses buffers the tokens that were presented, so that the request path never
// waits on the API server.
//
// The request path writes here and a loop elsewhere drains it. What is kept is
// one time per token rather than one per request, so a token used continuously
// costs one entry.
type Uses struct {
	// Now reads the clock. Nil means time.Now.
	Now func() time.Time

	mu      sync.Mutex
	pending map[Ref]time.Time
}

// Used records that a token was presented just now. It is called while a
// request is being served and does nothing that can block.
func (u *Uses) Used(namespace, name string) {
	if namespace == "" || name == "" {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.pending == nil {
		u.pending = make(map[Ref]time.Time)
	}
	u.pending[Ref{Namespace: namespace, Name: name}] = u.now()
}

// Take returns what has been buffered and empties the buffer.
//
// Emptying is the point: what is taken is about to be written, and anything
// used again afterwards is buffered again. A write that fails is not put back
// — the next use will report a fresher time than the one that was lost.
func (u *Uses) Take() map[Ref]time.Time {
	u.mu.Lock()
	defer u.mu.Unlock()
	pending := u.pending
	u.pending = nil
	if pending == nil {
		return map[Ref]time.Time{}
	}
	return pending
}

func (u *Uses) now() time.Time {
	if u.Now == nil {
		return time.Now()
	}
	return u.Now()
}

// ShouldRecord reports whether a use is far enough from what is already
// recorded to be worth writing.
//
// A zero recorded time means nothing has been written yet. A recorded time in
// the future means another replica got there first, or the clock moved; either
// way the later value stands.
func ShouldRecord(recorded, used time.Time, resolution time.Duration) bool {
	if recorded.IsZero() {
		return true
	}
	return used.Sub(recorded) >= resolution
}
