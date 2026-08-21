// Package accesstoken mints and checks the credential clients that cannot
// follow a redirect present (ADR 0004).
//
// A token arrives through one of two doors — an Authorization: Bearer header,
// or the password field of BASIC authentication — and leaves through one: the
// subject the AccessToken names. Nothing downstream can tell which door was
// used, because the authorisation decision must not depend on it. There is one
// way in for a browser and one for everything else, and one set of rules.
//
// What the request path holds is deliberately not the tokens. It holds their
// SHA-256 digests, taken from the status of each AccessToken, because the
// alternative is caching every Secret in the cluster (ADR 0013). A digest is
// enough to recognise a token that is presented and not enough to produce one.
package accesstoken

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"

	gatev1alpha1 "github.com/yuanying/gated/internal/apis/gate/v1alpha1"
)

// Prefix marks a value as a gated access token. It is the same constant the
// CRD documents; having it fixed and public lets a leaked token be recognised
// for what it is, by a secret scanner or by whoever finds it in a log.
const Prefix = gatev1alpha1.TokenPrefix

// SecretKey is the entry of the Secret the generated token is written to.
const SecretKey = gatev1alpha1.TokenSecretKey

// tokenBytes is how much randomness a token carries. Thirty-two bytes is the
// output width of the digest that stands in for it; making the token itself
// narrower would make the digest the harder half to attack, which is
// backwards.
const tokenBytes = 32

// New mints a token.
//
// The value is returned once and never again: what is kept is the Secret it is
// written to and the digest in the status. Nothing in gated can recover a
// token from either.
func New() (string, error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating an access token: %w", err)
	}
	return Prefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// Hash returns the digest of a token in the form the status holds: SHA-256, in
// lower-case hex.
func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Credential returns the token an Authorization header carries.
//
// Two schemes are read. Bearer is the ordinary one. BASIC is read because
// `docker login` and the clients like it cannot be taught anything else
// (ADR 0004); what is on the wire looks like BASIC authentication, but the
// password field carries a revocable credential belonging to one person, not
// a password shared by everybody who pushes.
//
// Only the password field is read, never the user name. See ADR 0022 for why
// the user name is not checked and not accepted as a credential.
func Credential(header string) (string, bool) {
	scheme, rest, found := strings.Cut(header, " ")
	if !found {
		return "", false
	}
	rest = strings.TrimLeft(rest, " ")

	switch {
	case strings.EqualFold(scheme, "Bearer"):
		return rest, rest != ""
	case strings.EqualFold(scheme, "Basic"):
		decoded, err := base64.StdEncoding.DecodeString(rest)
		if err != nil {
			return "", false
		}
		_, password, found := strings.Cut(string(decoded), ":")
		if !found {
			return "", false
		}
		return password, password != ""
	default:
		return "", false
	}
}

// Identity is what a token stands for: the subject it acts as, and the
// AccessToken that says so.
//
// The name is carried alongside the subject because the last-used time is
// written back to that object, and because a refusal is only diagnosable if
// the log can name which token was presented.
type Identity struct {
	// Subject is the principal, in the vocabulary of ADR 0002.
	Subject string
	// Namespace and Name locate the AccessToken.
	Namespace string
	Name      string
}

// Entry is one AccessToken as the request path sees it: an identity and the
// digest from its status.
type Entry struct {
	Identity
	// Hash is the SHA-256 of the token, in hex.
	Hash string
}

// Snapshot is the set of tokens in force.
//
// It is immutable and swapped in whole, the way the routing table and the
// permissions are (see proxy.TableStore): a request that is being
// authenticated finishes against the set it started with, and the read side
// takes no locks.
type Snapshot struct {
	entries []snapshotEntry
}

type snapshotEntry struct {
	identity Identity
	digest   []byte
}

// NewSnapshot builds the set from what the AccessTokens say.
//
// Entries that cannot be believed are dropped here rather than at lookup time,
// so that the request path has nothing left to decide. Dropped are: a token
// with no digest yet, a digest that is not one, a token that names nobody, and
// a token that claims a system: subject. The last is refused by the CRD at
// admission (ADR 0010) and refused again here, because a token acting as
// "anyone who logged in" would hand its holder whatever every account has.
func NewSnapshot(entries []Entry) *Snapshot {
	snapshot := &Snapshot{}
	for _, e := range entries {
		if e.Subject == "" || strings.HasPrefix(e.Subject, "system:") {
			continue
		}
		digest, err := hex.DecodeString(strings.ToLower(e.Hash))
		if err != nil || len(digest) != sha256.Size {
			continue
		}
		snapshot.entries = append(snapshot.entries, snapshotEntry{identity: e.Identity, digest: digest})
	}
	return snapshot
}

// Len is how many tokens the snapshot holds.
func (s *Snapshot) Len() int {
	if s == nil {
		return 0
	}
	return len(s.entries)
}

// Lookup returns the identity behind a presented token.
//
// The presented value is hashed and the digest compared against every entry,
// in constant time and without stopping at the first match. Comparing digests
// rather than tokens is what lets the proxy do this at all without holding the
// Secrets; comparing them all the way through is what keeps how long the
// answer took from saying which token was close.
//
// The nil snapshot matches nothing, which is what a store holds before it has
// read anything.
func (s *Snapshot) Lookup(presented string) (Identity, bool) {
	if s == nil || presented == "" || !strings.HasPrefix(presented, Prefix) {
		return Identity{}, false
	}

	sum := sha256.Sum256([]byte(presented))
	var found Identity
	matched := 0
	for i := range s.entries {
		if subtle.ConstantTimeCompare(sum[:], s.entries[i].digest) == 1 {
			found = s.entries[i].identity
			matched = 1
		}
	}
	if matched == 0 {
		return Identity{}, false
	}
	return found, true
}

// Store holds the snapshot currently in force.
//
// As with the permissions, an empty set and an unread set must not be the same
// value. An empty set means nobody has issued a token; an unread one means
// this replica cannot yet tell a real token from a forged one, and answering
// as though the token were wrong would be a lie.
type Store struct {
	current atomic.Pointer[Snapshot]
}

// Store puts a snapshot into force.
func (s *Store) Store(snapshot *Snapshot) {
	if s == nil {
		return
	}
	s.current.Store(snapshot)
}

// Load returns the snapshot in force. The second result is false until the
// first one has been stored.
func (s *Store) Load() (*Snapshot, bool) {
	if s == nil {
		return nil, false
	}
	snapshot := s.current.Load()
	return snapshot, snapshot != nil
}

// Ready reports whether the tokens have been read, in the shape a health check
// wants. A replica that has not read them turns every valid token into an
// anonymous request, which the client sees as its credential being rejected.
func (s *Store) Ready(*http.Request) error {
	if _, ok := s.Load(); !ok {
		return fmt.Errorf("the access tokens have not been loaded yet")
	}
	return nil
}
