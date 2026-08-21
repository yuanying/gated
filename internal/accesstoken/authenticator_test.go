package accesstoken

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// recordedUse is what the middleware reports to whatever writes lastUsedTime.
type recordedUse struct {
	mu   sync.Mutex
	seen []Identity
}

func (r *recordedUse) Used(namespace, name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, Identity{Namespace: namespace, Name: name})
}

func (r *recordedUse) all() []Identity {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Identity(nil), r.seen...)
}

const knownToken = Prefix + "known"

var knownIdentity = Identity{Subject: "github:octocat", Namespace: "shop", Name: "registry"}

func newAuthenticator(t *testing.T, loaded bool) (*Authenticator, *recordedUse) {
	t.Helper()

	store := &Store{}
	if loaded {
		store.Store(NewSnapshot([]Entry{{Identity: knownIdentity, Hash: Hash(knownToken)}}))
	}
	usage := &recordedUse{}
	return &Authenticator{Tokens: store, Usage: usage}, usage
}

// served is what the handler behind the middleware saw.
type served struct {
	subject       string
	authenticated bool
	authorization string
}

func run(t *testing.T, a *Authenticator, header string) served {
	t.Helper()

	var got served
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.subject, got.authenticated = SubjectFromContext(r.Context())
		got.authorization = r.Header.Get("Authorization")
	})

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	if header != "" {
		req.Header.Set("Authorization", header)
	}
	a.Wrap(next).ServeHTTP(httptest.NewRecorder(), req)
	return got
}

func basicHeader(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

// Both doors lead to the same place: the subject the AccessToken names, and
// nothing else about how it arrived (ADR 0004).
func TestAuthenticatorAcceptsBothDoors(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{name: "a bearer token", header: "Bearer " + knownToken},
		{name: "the password field of BASIC", header: basicHeader("anything", knownToken)},
		{name: "the password field with no user name", header: basicHeader("", knownToken)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, usage := newAuthenticator(t, true)
			got := run(t, a, tt.header)

			if !got.authenticated || got.subject != knownIdentity.Subject {
				t.Errorf("subject = %q, %v, want %q, true", got.subject, got.authenticated, knownIdentity.Subject)
			}
			// A credential gated spent is gated's, not the backend's.
			// Forwarding it would let anything behind the proxy act as
			// whoever presented it.
			if got.authorization != "" {
				t.Errorf("the backend was given Authorization: %q, want it removed", got.authorization)
			}
			if used := usage.all(); len(used) != 1 ||
				used[0].Namespace != knownIdentity.Namespace || used[0].Name != knownIdentity.Name {
				t.Errorf("recorded uses = %+v, want one of %s/%s",
					used, knownIdentity.Namespace, knownIdentity.Name)
			}
		})
	}
}

// Anything gated did not issue is left exactly as it arrived. A backend that
// does its own authentication goes on doing it.
func TestAuthenticatorLeavesForeignCredentialsAlone(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{name: "no header at all", header: ""},
		{name: "a token nobody issued", header: "Bearer " + Prefix + "unissued"},
		{name: "an ordinary BASIC password", header: basicHeader("someone", "hunter2")},
		{name: "another scheme", header: "Negotiate abcdef"},
		// Presenting the digest must not work; it is in a status that is
		// far more widely readable than the Secret.
		{name: "the digest of a real token", header: "Bearer " + Hash(knownToken)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, usage := newAuthenticator(t, true)
			got := run(t, a, tt.header)

			if got.authenticated {
				t.Errorf("subject = %q, want the request to stay anonymous", got.subject)
			}
			if got.authorization != tt.header {
				t.Errorf("Authorization = %q, want it untouched as %q", got.authorization, tt.header)
			}
			if used := usage.all(); len(used) != 0 {
				t.Errorf("recorded uses = %+v, want none", used)
			}
		})
	}
}

// Before the tokens have been read, a valid token is not one. Saying so is the
// readiness check's job; the request path only has to not invent an identity.
func TestAuthenticatorTrustsNothingBeforeItHasRead(t *testing.T) {
	a, usage := newAuthenticator(t, false)
	got := run(t, a, "Bearer "+knownToken)

	if got.authenticated {
		t.Errorf("subject = %q, want the request to stay anonymous", got.subject)
	}
	if len(usage.all()) != 0 {
		t.Error("a use was recorded against a snapshot that was never read")
	}
}

// The middleware is also the resolver the authorisation decision asks, so that
// a token and a session cookie arrive at exactly the same decision (ADR 0004).
func TestAuthenticatorAnswersAsASubjectResolver(t *testing.T) {
	a, _ := newAuthenticator(t, true)

	var subject string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject = a.Subject(r)
	})
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	req.Header.Set("Authorization", "Bearer "+knownToken)
	a.Wrap(next).ServeHTTP(httptest.NewRecorder(), req)

	if subject != knownIdentity.Subject {
		t.Errorf("Subject() = %q, want %q", subject, knownIdentity.Subject)
	}

	// Outside the middleware there is nothing on the context to read, and
	// the resolver must not go looking at the header itself: one place
	// spends a credential.
	unwrapped := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	unwrapped.Header.Set("Authorization", "Bearer "+knownToken)
	if got := a.Subject(unwrapped); got != "" {
		t.Errorf("Subject() outside the middleware = %q, want %q", got, "")
	}
}

// A nil Usage is a token that is checked but whose use is not recorded, which
// is what a test wiring and a degraded deployment both look like.
func TestAuthenticatorWithoutAUsageRecorder(t *testing.T) {
	store := &Store{}
	store.Store(NewSnapshot([]Entry{{Identity: knownIdentity, Hash: Hash(knownToken)}}))
	a := &Authenticator{Tokens: store}

	if got := run(t, a, "Bearer "+knownToken); got.subject != knownIdentity.Subject {
		t.Errorf("subject = %q, want %q", got.subject, knownIdentity.Subject)
	}
}
