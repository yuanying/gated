package accesstoken

import (
	"reflect"
	"testing"
	"time"
)

var epoch = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

// Uses is written to from the request path and read from a loop that talks to
// the API server. What it buffers is one time per token, not one per request:
// a token used a thousand times in a minute is one write.
func TestUsesCollapseRepeatsIntoOne(t *testing.T) {
	now := epoch
	uses := &Uses{Now: func() time.Time { return now }}

	uses.Used("shop", "registry")
	now = now.Add(time.Second)
	uses.Used("shop", "registry")
	uses.Used("shop", "backup")

	want := map[Ref]time.Time{
		{Namespace: "shop", Name: "registry"}: epoch.Add(time.Second),
		{Namespace: "shop", Name: "backup"}:   epoch.Add(time.Second),
	}
	if got := uses.Take(); !reflect.DeepEqual(got, want) {
		t.Errorf("Take() = %v, want %v", got, want)
	}

	// Taking empties the buffer: what was taken is about to be written, and
	// writing it twice would be two writes saying the same thing.
	if got := uses.Take(); len(got) != 0 {
		t.Errorf("Take() a second time = %v, want nothing", got)
	}

	uses.Used("shop", "registry")
	if got := uses.Take(); len(got) != 1 {
		t.Errorf("Take() after another use = %v, want one entry", got)
	}
}

func TestUsesIgnoresATokenItCannotName(t *testing.T) {
	uses := &Uses{Now: func() time.Time { return epoch }}
	uses.Used("", "registry")
	uses.Used("shop", "")

	if got := uses.Take(); len(got) != 0 {
		t.Errorf("Take() = %v, want nothing", got)
	}
}

// The last-used time says that a token is in use, not exactly when. Writing
// every use would put one API server write on every request to a protected
// registry, which is a cost paid for a precision nobody reads.
func TestShouldRecordRateLimits(t *testing.T) {
	tests := []struct {
		name     string
		recorded time.Time
		used     time.Time
		want     bool
	}{
		{name: "never recorded", used: epoch, want: true},
		{name: "recorded long ago", recorded: epoch.Add(-time.Hour), used: epoch, want: true},
		{name: "recorded exactly a resolution ago", recorded: epoch.Add(-time.Minute), used: epoch, want: true},
		{name: "recorded moments ago", recorded: epoch.Add(-time.Second), used: epoch, want: false},
		{name: "recorded at the same instant", recorded: epoch, used: epoch, want: false},
		// A clock that went backwards, or a use that raced a write from
		// another replica. Leave the later value alone.
		{name: "recorded after the use", recorded: epoch.Add(time.Minute), used: epoch, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ShouldRecord(tt.recorded, tt.used, time.Minute); got != tt.want {
				t.Errorf("ShouldRecord(%v, %v, 1m) = %v, want %v", tt.recorded, tt.used, got, tt.want)
			}
		})
	}
}
