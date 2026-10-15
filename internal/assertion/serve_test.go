package assertion_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yuanying/gated/internal/assertion"
	"github.com/yuanying/gated/internal/assertion/assertiontest"
)

// The two places the key set is used on a request: signing what is forwarded,
// and publishing what a backend verifies with. Both read the keys through a
// source that may not have them yet, because they live in a Secret that every
// replica reads for itself (ADR 0006).

type noKeys struct{}

func (noKeys) KeySet(context.Context) (*assertion.KeySet, error) {
	return nil, errors.New("not read yet")
}

func TestTheSignerVouchesForASubjectAtAHost(t *testing.T) {
	keys := keySet(t, map[string][]byte{assertion.SigningKeyEntry: privatePEM(t, newKey(t))})
	signer := &assertion.Signer{
		Keys:   assertion.StaticKeys{Set: keys},
		Issuer: assertion.Issuer("auth.example.com"),
		Now:    func() time.Time { return issuedAt },
	}

	signed, err := signer.Assert(context.Background(), "github:octocat", "Shop.Example.com:443")
	if err != nil {
		t.Fatalf("Assert() = %v", err)
	}
	got, err := assertiontest.Verify(jwks(t, keys), signed, expect)
	if err != nil {
		t.Fatalf("Verify() = %v", err)
	}
	if got.Subject != "github:octocat" || got.Audience != "shop.example.com" {
		t.Errorf("the assertion is about %q at %q", got.Subject, got.Audience)
	}
}

func TestTheSignerSaysSoWhenItHasNoKey(t *testing.T) {
	signer := &assertion.Signer{Keys: noKeys{}, Issuer: "https://auth.example.com"}
	if signed, err := signer.Assert(context.Background(), "github:octocat", "shop.example.com"); err == nil {
		t.Errorf("Assert() = %q, nil; want an error", signed)
	}
}

func TestTheKeySetIsServedForFiveMinutes(t *testing.T) {
	keys := keySet(t, map[string][]byte{assertion.SigningKeyEntry: privatePEM(t, newKey(t))})
	handler := &assertion.JWKSHandler{Keys: assertion.StaticKeys{Set: keys}}

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(method, "https://auth.example.com/__gated/jwks.json", nil))

			if rec.Code != http.StatusOK {
				t.Fatalf("answered %d, want 200", rec.Code)
			}
			if got := rec.Header().Get("Content-Type"); got != "application/jwk-set+json" {
				t.Errorf("Content-Type = %q, want application/jwk-set+json", got)
			}
			if got := rec.Header().Get("Cache-Control"); got != "public, max-age=300" {
				t.Errorf("Cache-Control = %q, want five minutes", got)
			}
			if method == http.MethodHead {
				return
			}
			if got, want := rec.Body.String(), string(jwks(t, keys)); got != want {
				t.Errorf("the body is %s, want %s", got, want)
			}
		})
	}
}

func TestTheKeySetIsOnlyRead(t *testing.T) {
	handler := &assertion.JWKSHandler{Keys: assertion.StaticKeys{}}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "https://auth.example.com/__gated/jwks.json", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("a POST was answered %d, want 405", rec.Code)
	}
}

// Before the keys are read there is nothing true to say. A cached empty set
// would leave a backend unable to verify anything for five minutes.
func TestNoKeySetIsServedBeforeTheKeysAreRead(t *testing.T) {
	handler := &assertion.JWKSHandler{Keys: noKeys{}}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://auth.example.com/__gated/jwks.json", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("answered %d, want 503", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}
