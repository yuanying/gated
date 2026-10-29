package serviceaccount

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr/funcr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// fakeReviewer stands in for the API server. It answers from a table keyed by
// token and counts how often it was asked.
type fakeReviewer struct {
	mu       sync.Mutex
	answers  map[string]Review
	err      error
	asked    int
	audience []string
}

func (f *fakeReviewer) Review(_ context.Context, token, audience string) (Review, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked++
	f.audience = append(f.audience, audience)
	if f.err != nil {
		return Review{}, f.err
	}
	return f.answers[token], nil
}

func (f *fakeReviewer) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.asked
}

// clock is a time a test can move.
type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

type fixture struct {
	auth     *Authenticator
	reviewer *fakeReviewer
	clock    *clock
	registry *prometheus.Registry
	logged   *strings.Builder
}

const subject = "system:serviceaccount:natsumi:assistant"

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{
		reviewer: &fakeReviewer{answers: map[string]Review{}},
		clock:    &clock{now: time.Unix(1_800_000_000, 0)},
		registry: prometheus.NewRegistry(),
		logged:   &strings.Builder{},
	}
	var mu sync.Mutex
	log := funcr.New(func(prefix, args string) {
		mu.Lock()
		defer mu.Unlock()
		f.logged.WriteString(prefix + " " + args + "\n")
	}, funcr.Options{Verbosity: 10})

	f.auth = &Authenticator{
		Audience: audience,
		Reviewer: f.reviewer,
		TTL:      time.Minute,
		Now:      f.clock.Now,
		Metrics:  NewMetrics(f.registry),
		Log:      log,
	}
	return f
}

// token mints one in the shape the API server would, valid for an hour from
// the fixture's clock, and tells the fake API server what to say about it.
func (f *fixture) token(t *testing.T, audiences []string, review Review) string {
	t.Helper()
	token := jwt(t, map[string]any{
		"aud": audiences,
		"exp": f.clock.now.Add(time.Hour).Unix(),
		// Something to tell two tokens for the same account apart.
		"jti": t.Name() + time.Now().String(),
	})
	f.reviewer.answers[token] = review
	return token
}

func (f *fixture) accepted(t *testing.T) string {
	t.Helper()
	return f.token(t, []string{audience}, Review{
		Authenticated: true,
		Username:      subject,
		Audiences:     []string{audience},
	})
}

// served is what the handler behind the middleware saw.
type served struct {
	subject       string
	authenticated bool
	authorization string
}

func (f *fixture) send(t *testing.T, header string) served {
	t.Helper()
	var got served
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.subject, got.authenticated = SubjectFromContext(r.Context())
		if s := f.auth.Subject(r); s != got.subject {
			t.Errorf("Subject() = %q, but the context says %q", s, got.subject)
		}
		got.authorization = r.Header.Get("Authorization")
	})
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/api", nil)
	if header != "" {
		req.Header.Set("Authorization", header)
	}
	f.auth.Wrap(next).ServeHTTP(httptest.NewRecorder(), req)
	return got
}

func (f *fixture) counted(result Reason) float64 {
	return testutil.ToFloat64(f.auth.Metrics.tokens.WithLabelValues(string(result)))
}

func TestAnAcceptedTokenNamesItsServiceAccountAndIsSpent(t *testing.T) {
	f := newFixture(t)
	token := f.accepted(t)

	got := f.send(t, "Bearer "+token)

	if !got.authenticated || got.subject != subject {
		t.Errorf("the subject is %q (%v), want %q", got.subject, got.authenticated, subject)
	}
	// It is gated's credential, not the backend's (ADR 0022).
	if got.authorization != "" {
		t.Errorf("the backend was handed Authorization %q", got.authorization)
	}
	if len(f.reviewer.audience) != 1 || f.reviewer.audience[0] != audience {
		t.Errorf("the API server was asked about audiences %v, want [%s]", f.reviewer.audience, audience)
	}
	if n := f.counted(Accepted); n != 1 {
		t.Errorf("%s was counted %v times, want 1", Accepted, n)
	}
}

// Everything gated does not accept goes on to the backend as it came, and the
// request is decided as anonymous (ADR 0022: what gated does not spend is not
// gated's).
func TestATokenThatIsNotAcceptedIsPassedOnUntouched(t *testing.T) {
	tests := []struct {
		name      string
		audiences []string
		review    Review
		expired   bool
		err       error
		want      Reason
		asked     int
	}{
		{
			name:      "for another audience",
			audiences: []string{"a2a"},
			want:      WrongAudience,
		},
		{
			// A token that claims gated's audience and that the API
			// server says is meant for something else.
			name:      "the API server disagrees about the audience",
			audiences: []string{audience},
			review:    Review{Authenticated: true, Username: subject, Audiences: []string{"a2a"}},
			want:      WrongAudience,
			asked:     1,
		},
		{
			name:      "expired",
			audiences: []string{audience},
			expired:   true,
			want:      Expired,
		},
		{
			name:      "forged",
			audiences: []string{audience},
			review:    Review{Authenticated: false, Error: "invalid bearer token"},
			want:      Rejected,
			asked:     1,
		},
		{
			name:      "a user rather than a service account",
			audiences: []string{audience},
			review:    Review{Authenticated: true, Username: "kubernetes-admin", Audiences: []string{audience}},
			want:      NotServiceAccount,
			asked:     1,
		},
		{
			name:      "the API server cannot be reached",
			audiences: []string{audience},
			err:       errors.New("connection refused"),
			want:      ReviewFailed,
			asked:     1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			f.reviewer.err = tt.err
			token := f.token(t, tt.audiences, tt.review)
			if tt.expired {
				f.clock.now = f.clock.now.Add(2 * time.Hour)
			}

			got := f.send(t, "Bearer "+token)

			if got.authenticated {
				t.Errorf("the request was authenticated as %q", got.subject)
			}
			if got.authorization != "Bearer "+token {
				t.Errorf("the backend was handed Authorization %q, want the token as it came", got.authorization)
			}
			if n := f.counted(tt.want); n != 1 {
				t.Errorf("%s was counted %v times, want 1", tt.want, n)
			}
			if n := f.reviewer.calls(); n != tt.asked {
				t.Errorf("the API server was asked %d times, want %d", n, tt.asked)
			}
			// The reason is in the log, the token is not.
			if !strings.Contains(f.logged.String(), string(tt.want)) {
				t.Errorf("the log does not say %q:\n%s", tt.want, f.logged)
			}
			if strings.Contains(f.logged.String(), token) {
				t.Errorf("the token was written to the log:\n%s", f.logged)
			}
		})
	}
}

func TestOnlyServiceAccountTokensAreLookedAt(t *testing.T) {
	for name, header := range map[string]string{
		"no credential":   "",
		"an access token": "Bearer gat_abcdef",
		"BASIC":           "Basic dXNlcjpwYXNz",
		"an opaque token": "Bearer opaque",
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			got := f.send(t, header)
			if got.authenticated {
				t.Errorf("the request was authenticated as %q", got.subject)
			}
			if got.authorization != header {
				t.Errorf("Authorization = %q, want %q passed on", got.authorization, header)
			}
			if n := f.reviewer.calls(); n != 0 {
				t.Errorf("the API server was asked %d times about something that is not a service account token", n)
			}
		})
	}
}

func TestAnAnswerIsRememberedForTheTTL(t *testing.T) {
	f := newFixture(t)
	token := f.accepted(t)

	f.send(t, "Bearer "+token)
	f.clock.now = f.clock.now.Add(59 * time.Second)
	if got := f.send(t, "Bearer "+token); got.subject != subject {
		t.Fatalf("the remembered token named %q, want %q", got.subject, subject)
	}
	if n := f.reviewer.calls(); n != 1 {
		t.Fatalf("the API server was asked %d times within the TTL, want 1", n)
	}

	f.clock.now = f.clock.now.Add(time.Second)
	if got := f.send(t, "Bearer "+token); got.subject != subject {
		t.Fatalf("the token named %q once it was asked about again, want %q", got.subject, subject)
	}
	if n := f.reviewer.calls(); n != 2 {
		t.Errorf("the API server was asked %d times after the TTL, want 2", n)
	}
	if n := f.counted(Accepted); n != 3 {
		t.Errorf("%s was counted %v times, want once for every request", Accepted, n)
	}
}

func TestARememberedAnswerDoesNotOutliveTheToken(t *testing.T) {
	f := newFixture(t)
	expires := f.clock.now.Add(30 * time.Second)
	token := jwt(t, map[string]any{"aud": []string{audience}, "exp": expires.Unix()})
	f.reviewer.answers[token] = Review{Authenticated: true, Username: subject, Audiences: []string{audience}}

	if got := f.send(t, "Bearer "+token); got.subject != subject {
		t.Fatalf("the token named %q, want %q", got.subject, subject)
	}

	// Inside the TTL, past the token's own end.
	f.clock.now = expires
	got := f.send(t, "Bearer "+token)
	if got.authenticated {
		t.Errorf("an expired token was still believed as %q", got.subject)
	}
	if got.authorization != "Bearer "+token {
		t.Errorf("the expired token was not passed on: Authorization = %q", got.authorization)
	}
	if n := f.counted(Expired); n != 1 {
		t.Errorf("%s was counted %v times, want 1", Expired, n)
	}
}

func TestARefusalIsRememberedButAFailureIsNot(t *testing.T) {
	t.Run("refused", func(t *testing.T) {
		f := newFixture(t)
		token := f.token(t, []string{audience}, Review{Authenticated: false})
		f.send(t, "Bearer "+token)
		f.send(t, "Bearer "+token)
		if n := f.reviewer.calls(); n != 1 {
			t.Errorf("the API server was asked %d times about a token it refused, want 1", n)
		}
		if n := f.counted(Rejected); n != 2 {
			t.Errorf("%s was counted %v times, want 2", Rejected, n)
		}
	})

	t.Run("failed", func(t *testing.T) {
		// Not an answer about the token, so nothing to remember: the
		// next request asks again, and is believed once the API server
		// is back.
		f := newFixture(t)
		token := f.accepted(t)
		f.reviewer.err = errors.New("connection refused")
		f.send(t, "Bearer "+token)

		f.reviewer.err = nil
		if got := f.send(t, "Bearer "+token); got.subject != subject {
			t.Errorf("the token named %q once the API server was back, want %q", got.subject, subject)
		}
		if n := f.reviewer.calls(); n != 2 {
			t.Errorf("the API server was asked %d times, want 2", n)
		}
	})
}

func TestARememberedTokenSurvivesTheAPIServerGoingAway(t *testing.T) {
	f := newFixture(t)
	token := f.accepted(t)
	f.send(t, "Bearer "+token)

	f.reviewer.err = errors.New("connection refused")
	if got := f.send(t, "Bearer "+token); got.subject != subject {
		t.Errorf("a remembered token named %q while the API server was away, want %q", got.subject, subject)
	}
}

func TestTheReviewIsCountedByWhatTheAPIServerSaid(t *testing.T) {
	f := newFixture(t)
	f.send(t, "Bearer "+f.accepted(t))
	f.send(t, "Bearer "+f.token(t, []string{audience}, Review{Authenticated: false}))
	f.reviewer.err = errors.New("connection refused")
	f.send(t, "Bearer "+f.accepted(t))

	for result, want := range map[string]float64{"authenticated": 1, "unauthenticated": 1, "error": 1} {
		if n := testutil.ToFloat64(f.auth.Metrics.reviews.WithLabelValues(result)); n != want {
			t.Errorf("reviews{result=%q} = %v, want %v", result, n, want)
		}
	}
}

func TestTheMemoryIsBounded(t *testing.T) {
	f := newFixture(t)
	f.auth.MaxEntries = 2

	first, second, third := f.accepted(t), f.accepted(t), f.accepted(t)
	for _, token := range []string{first, second, third} {
		f.send(t, "Bearer "+token)
	}
	// The third did not fit and is asked about again; the first two are
	// remembered.
	for _, token := range []string{first, second, third} {
		f.send(t, "Bearer "+token)
	}
	if n := f.reviewer.calls(); n != 4 {
		t.Errorf("the API server was asked %d times, want 4", n)
	}

	// Once the first two have lapsed there is room again.
	f.clock.now = f.clock.now.Add(time.Minute)
	f.send(t, "Bearer "+third)
	f.send(t, "Bearer "+third)
	if n := f.reviewer.calls(); n != 5 {
		t.Errorf("the API server was asked %d times once there was room, want 5", n)
	}
}
