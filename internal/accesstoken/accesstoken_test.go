package accesstoken

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
)

func TestNewMintsAnUnguessableToken(t *testing.T) {
	const count = 64

	seen := make(map[string]bool, count)
	for range count {
		token, err := New()
		if err != nil {
			t.Fatalf("New() = %v, want nil", err)
		}
		if !strings.HasPrefix(token, Prefix) {
			t.Fatalf("New() = %q, want it to start with %q", token, Prefix)
		}
		// The prefix is what lets a leaked token be recognised for what
		// it is; the rest has to be full-entropy random.
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, Prefix))
		if err != nil {
			t.Fatalf("decoding %q: %v", token, err)
		}
		if len(raw) != tokenBytes {
			t.Errorf("token carries %d bytes, want %d", len(raw), tokenBytes)
		}
		if seen[token] {
			t.Fatalf("New() returned %q twice", token)
		}
		seen[token] = true
	}
}

func TestHashIsTheDigestTheStatusHolds(t *testing.T) {
	const token = Prefix + "not-a-real-token"

	sum := sha256.Sum256([]byte(token))
	if got, want := Hash(token), hex.EncodeToString(sum[:]); got != want {
		t.Errorf("Hash(%q) = %q, want %q", token, got, want)
	}
	if got := Hash(token); len(got) != 64 || strings.ToLower(got) != got {
		t.Errorf("Hash() = %q, want 64 lower-case hex characters", got)
	}
}

func TestCredentialReadsBothDoors(t *testing.T) {
	basic := func(user, password string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
	}

	tests := []struct {
		name   string
		header string
		want   string
	}{
		{name: "no header", header: "", want: ""},
		{name: "a bearer token", header: "Bearer " + Prefix + "abc", want: Prefix + "abc"},
		// Schemes are case-insensitive in RFC 7235, and clients differ.
		{name: "a lower-case scheme", header: "bearer " + Prefix + "abc", want: Prefix + "abc"},
		{name: "extra spaces around the scheme", header: "Bearer    " + Prefix + "abc", want: Prefix + "abc"},
		{name: "a bearer with nothing after it", header: "Bearer", want: ""},
		{name: "a bearer with an empty credential", header: "Bearer ", want: ""},

		// The password field, which is the door docker login can use
		// without being changed (ADR 0004).
		{name: "a basic password", header: basic("anything", Prefix+"abc"), want: Prefix + "abc"},
		{name: "a basic password with no user name", header: basic("", Prefix+"abc"), want: Prefix + "abc"},
		// A password may contain a colon; the first one separates.
		{name: "a colon in the password", header: basic("user", "a:b"), want: "a:b"},
		{name: "an empty password", header: basic("user", ""), want: ""},
		{name: "no colon at all", header: "Basic " + base64.StdEncoding.EncodeToString([]byte("user")), want: ""},
		{name: "not base64", header: "Basic ???", want: ""},

		// The user name field is never read as a credential: one door
		// per scheme, so that what was presented is unambiguous.
		{name: "a token in the user name", header: basic(Prefix+"abc", ""), want: ""},

		{name: "another scheme", header: "Negotiate abc", want: ""},
		{name: "no scheme", header: Prefix + "abc", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Credential(tt.header)
			if tt.want == "" {
				if ok {
					t.Errorf("Credential(%q) = %q, true, want false", tt.header, got)
				}
				return
			}
			if !ok || got != tt.want {
				t.Errorf("Credential(%q) = %q, %v, want %q, true", tt.header, got, ok, tt.want)
			}
		})
	}
}

// The snapshot matches on the digest in the status, never on a stored token:
// the proxy is not allowed to hold the Secrets (ADR 0013).
func TestSnapshotMatchesOnTheDigest(t *testing.T) {
	const (
		mine   = Prefix + "mine"
		theirs = Prefix + "theirs"
		stale  = Prefix + "stale"
	)

	snapshot := NewSnapshot([]Entry{
		{Identity: Identity{Subject: "github:octocat", Namespace: "shop", Name: "registry"}, Hash: Hash(mine)},
		{Identity: Identity{Subject: "google:someone@example.com", Namespace: "shop", Name: "backup"}, Hash: Hash(theirs)},

		// Entries that cannot be believed are dropped when the snapshot
		// is built, so that the request path has nothing to decide.
		{Identity: Identity{Subject: "github:hubot", Namespace: "shop", Name: "no-hash"}},
		{Identity: Identity{Subject: "github:hubot", Namespace: "shop", Name: "short-hash"}, Hash: "abcd"},
		{Identity: Identity{Subject: "github:hubot", Namespace: "shop", Name: "not-hex"}, Hash: strings.Repeat("z", 64)},
		{Identity: Identity{Namespace: "shop", Name: "no-subject"}, Hash: Hash(stale)},
		// A token may not act as a class of caller (ADR 0010). The CRD
		// refuses one at admission; this is the second lock.
		{Identity: Identity{Subject: "system:authenticated", Namespace: "shop", Name: "everyone"}, Hash: Hash(stale)},
	})

	if got, want := snapshot.Len(), 2; got != want {
		t.Errorf("Len() = %d, want %d", got, want)
	}

	tests := []struct {
		name      string
		presented string
		want      Identity
	}{
		{
			name:      "a known token",
			presented: mine,
			want:      Identity{Subject: "github:octocat", Namespace: "shop", Name: "registry"},
		},
		{
			name:      "another known token",
			presented: theirs,
			want:      Identity{Subject: "google:someone@example.com", Namespace: "shop", Name: "backup"},
		},
		{name: "a token nobody issued", presented: Prefix + "unknown"},
		{name: "nothing", presented: ""},
		{name: "a credential that is not one of ours", presented: "hunter2"},
		// The digest itself is not a credential: presenting it must not
		// pass, or the status would be as sensitive as the Secret.
		{name: "the digest of a known token", presented: Hash(mine)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := snapshot.Lookup(tt.presented)
			if (tt.want == Identity{}) {
				if ok {
					t.Errorf("Lookup(%q) = %+v, true, want false", tt.presented, got)
				}
				return
			}
			if !ok || got != tt.want {
				t.Errorf("Lookup(%q) = %+v, %v, want %+v, true", tt.presented, got, ok, tt.want)
			}
		})
	}
}

// A digest written in upper case is the same digest. The controller writes
// lower case and the CRD enforces it, so this is only about not depending on
// that in two places.
func TestSnapshotAcceptsAnUpperCaseDigest(t *testing.T) {
	const token = Prefix + "case"

	snapshot := NewSnapshot([]Entry{{
		Identity: Identity{Subject: "github:octocat", Namespace: "shop", Name: "registry"},
		Hash:     strings.ToUpper(Hash(token)),
	}})
	if _, ok := snapshot.Lookup(token); !ok {
		t.Error("Lookup() did not match a digest written in upper case")
	}
}

func TestEmptySnapshotMatchesNothing(t *testing.T) {
	if _, ok := NewSnapshot(nil).Lookup(Prefix + "anything"); ok {
		t.Error("an empty snapshot matched a token")
	}
	// The nil snapshot is what a Store holds before the first one arrives.
	var nilSnapshot *Snapshot
	if _, ok := nilSnapshot.Lookup(Prefix + "anything"); ok {
		t.Error("the nil snapshot matched a token")
	}
}

// The store must distinguish "no tokens exist" from "no tokens have been read
// yet". The first is ordinary; the second would turn a valid token into an
// anonymous request, which reads to the caller as the token being wrong.
func TestStoreReportsWhetherItHasRead(t *testing.T) {
	var store Store

	if _, ok := store.Load(); ok {
		t.Error("Load() reported a snapshot before one was stored")
	}
	if err := store.Ready(&http.Request{}); err == nil {
		t.Error("Ready() = nil before a snapshot was stored, want an error")
	}

	store.Store(NewSnapshot(nil))
	if _, ok := store.Load(); !ok {
		t.Error("Load() reported no snapshot after one was stored")
	}
	if err := store.Ready(&http.Request{}); err != nil {
		t.Errorf("Ready() = %v, want nil", err)
	}
}
