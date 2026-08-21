package authn

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The key the table below signs with, and one that differs from it in a single
// byte, so that "the key was rotated" is tested as a real rotation rather than
// as a length mismatch.
var (
	testKey    = []byte("0123456789abcdef0123456789abcdef")
	rotatedKey = []byte("0123456789abcdef0123456789abcdeg")
)

func testTime() time.Time { return time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC) }

func TestSignRejectsTokensItCouldNotVerify(t *testing.T) {
	now := testTime()
	valid := Token{
		Kind:      KindSession,
		Subject:   "github:octocat",
		Audience:  "app.example.com",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}

	tests := map[string]struct {
		key   []byte
		token Token
	}{
		"no key": {
			key:   nil,
			token: valid,
		},
		"key shorter than the minimum": {
			key:   []byte("too short"),
			token: valid,
		},
		"unknown kind": {
			key:   testKey,
			token: withToken(valid, func(tk *Token) { tk.Kind = "x" }),
		},
		"no subject": {
			key:   testKey,
			token: withToken(valid, func(tk *Token) { tk.Subject = "" }),
		},
		"no audience": {
			key:   testKey,
			token: withToken(valid, func(tk *Token) { tk.Audience = "" }),
		},
		"expires before it is issued": {
			key:   testKey,
			token: withToken(valid, func(tk *Token) { tk.ExpiresAt = now.Add(-time.Second) }),
		},
		"never expires": {
			key:   testKey,
			token: withToken(valid, func(tk *Token) { tk.ExpiresAt = time.Time{} }),
		},
		"a handoff that leaves the host": {
			key: testKey,
			token: withToken(valid, func(tk *Token) {
				tk.Kind = KindHandoff
				tk.Next = "//elsewhere.example.net/"
			}),
		},
		"a handoff carrying an absolute URL": {
			key: testKey,
			token: withToken(valid, func(tk *Token) {
				tk.Kind = KindHandoff
				tk.Next = "https://elsewhere.example.net/"
			}),
		},
		"a handoff carrying a relative path": {
			key: testKey,
			token: withToken(valid, func(tk *Token) {
				tk.Kind = KindHandoff
				tk.Next = "somewhere"
			}),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got, err := Sign(tc.key, tc.token); err == nil {
				t.Fatalf("Sign() = %q, nil; want an error", got)
			}
		})
	}
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	now := testTime()
	tests := map[string]Token{
		"a session": {
			Kind:      KindSession,
			Subject:   "google:someone@example.com",
			Audience:  "app.example.com",
			IssuedAt:  now,
			ExpiresAt: now.Add(12 * time.Hour),
		},
		"a handoff": {
			Kind:      KindHandoff,
			Subject:   "github:octocat",
			Audience:  "app.example.com",
			Next:      "/reports?page=2",
			Binding:   "Zm9v",
			IssuedAt:  now,
			ExpiresAt: now.Add(30 * time.Second),
		},
		"an OAuth state": {
			Kind:      KindState,
			Subject:   "bm9uY2U",
			Audience:  "auth.example.com",
			Next:      "https://app.example.com/reports",
			Binding:   "Zm9v",
			Provider:  "github",
			IssuedAt:  now,
			ExpiresAt: now.Add(10 * time.Minute),
		},
	}

	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			raw, err := Sign(testKey, token)
			if err != nil {
				t.Fatalf("Sign() = %v", err)
			}

			got, err := Verify(testKey, raw, Expect{Kind: token.Kind, Audience: token.Audience, Now: now})
			if err != nil {
				t.Fatalf("Verify() = %v", err)
			}
			if got.Subject != token.Subject {
				t.Errorf("Subject = %q, want %q", got.Subject, token.Subject)
			}
			if got.Next != token.Next {
				t.Errorf("Next = %q, want %q", got.Next, token.Next)
			}
			if got.Binding != token.Binding {
				t.Errorf("Binding = %q, want %q", got.Binding, token.Binding)
			}
			if got.Provider != token.Provider {
				t.Errorf("Provider = %q, want %q", got.Provider, token.Provider)
			}
			if !got.ExpiresAt.Equal(token.ExpiresAt) {
				t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, token.ExpiresAt)
			}
			if !got.IssuedAt.Equal(token.IssuedAt) {
				t.Errorf("IssuedAt = %v, want %v", got.IssuedAt, token.IssuedAt)
			}
		})
	}
}

// TestVerifyRefusesAnythingItWasNotHanded is the whole point of the signature:
// a cookie is written by whoever holds the browser, so every way of handing
// back something other than what was issued has to end in a refusal.
func TestVerifyRefusesAnythingItWasNotHanded(t *testing.T) {
	now := testTime()
	issued := Token{
		Kind:      KindSession,
		Subject:   "github:octocat",
		Audience:  "app.example.com",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}
	raw, err := Sign(testKey, issued)
	if err != nil {
		t.Fatalf("Sign() = %v", err)
	}
	body, signature, _ := strings.Cut(raw, ".")

	tests := map[string]struct {
		key   []byte
		raw   string
		want  Expect
		check func(t *testing.T, err error)
	}{
		"the subject was rewritten": {
			key: testKey,
			raw: repack(t, body, func(p map[string]any) { p["sub"] = "github:someone-else" }) + "." + signature,
		},
		"the expiry was pushed out": {
			key: testKey,
			raw: repack(t, body, func(p map[string]any) { p["exp"] = now.Add(100 * 24 * time.Hour).Unix() }) + "." + signature,
		},
		"the signature was replaced": {
			key: testKey,
			raw: body + "." + base64.RawURLEncoding.EncodeToString([]byte("not a signature at all............")),
		},
		"the signature was truncated": {
			key: testKey,
			raw: body + "." + signature[:len(signature)-2],
		},
		"the signature was dropped": {
			key: testKey,
			raw: body + ".",
		},
		"the key was rotated": {
			key: rotatedKey,
			raw: raw,
		},
		"the verifier has no key": {
			key: nil,
			raw: raw,
		},
		"nothing at all": {
			key: testKey,
			raw: "",
		},
		"no separator": {
			key: testKey,
			raw: body + signature,
		},
		"too many separators": {
			key: testKey,
			raw: body + "." + signature + "." + signature,
		},
		"the body is not base64": {
			key: testKey,
			raw: "!!!!." + signature,
		},
		"the body is not JSON": {
			key: testKey,
			raw: signWith(t, testKey, []byte("this is not JSON")),
		},
		"absurdly long": {
			key: testKey,
			raw: strings.Repeat("a", 1<<20) + "." + signature,
		},
		"a handoff offered as a session": {
			key: testKey,
			raw: mustSign(t, Token{
				Kind: KindHandoff, Subject: "github:octocat", Audience: "app.example.com",
				Next: "/", IssuedAt: now, ExpiresAt: now.Add(30 * time.Second),
			}),
		},
		"issued for another host": {
			key: testKey,
			raw: mustSign(t, Token{
				Kind: KindSession, Subject: "github:octocat", Audience: "other.example.com",
				IssuedAt: now, ExpiresAt: now.Add(time.Hour),
			}),
		},
		"expired": {
			key:  testKey,
			raw:  raw,
			want: Expect{Kind: KindSession, Audience: "app.example.com", Now: now.Add(2 * time.Hour)},
		},
		"expired one second ago": {
			key:  testKey,
			raw:  raw,
			want: Expect{Kind: KindSession, Audience: "app.example.com", Now: now.Add(time.Hour + time.Second)},
		},
		"issued far in the future": {
			key: testKey,
			raw: mustSign(t, Token{
				Kind: KindSession, Subject: "github:octocat", Audience: "app.example.com",
				IssuedAt: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour),
			}),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			want := tc.want
			if want.Kind == "" {
				want = Expect{Kind: KindSession, Audience: "app.example.com", Now: now}
			}
			got, err := Verify(tc.key, tc.raw, want)
			if err == nil {
				t.Fatalf("Verify() = %+v, nil; want an error", got)
			}
		})
	}
}

// TestVerifyAcceptsTheHostInAnySpelling keeps the audience check from turning
// into an accidental refusal: a Host header carries the port and whatever case
// the visitor typed.
func TestVerifyAcceptsTheHostInAnySpelling(t *testing.T) {
	now := testTime()
	raw := mustSign(t, Token{
		Kind: KindSession, Subject: "github:octocat", Audience: "app.example.com",
		IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	})

	for _, audience := range []string{"app.example.com", "APP.example.com", "app.example.com:443", "app.example.com."} {
		if _, err := Verify(testKey, raw, Expect{Kind: KindSession, Audience: audience, Now: now}); err != nil {
			t.Errorf("Verify(audience=%q) = %v", audience, err)
		}
	}
}

// TestVerifyRequiresAnAudience refuses to check a token against "any host".
func TestVerifyRequiresAnAudience(t *testing.T) {
	now := testTime()
	raw := mustSign(t, Token{
		Kind: KindSession, Subject: "github:octocat", Audience: "app.example.com",
		IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	if _, err := Verify(testKey, raw, Expect{Kind: KindSession, Now: now}); err == nil {
		t.Fatal("Verify() with no expected audience = nil; want an error")
	}
}

// TestSignIsDeterministic is what lets a replica verify what another replica
// signed: the same key and the same token produce the same string.
func TestSignIsDeterministic(t *testing.T) {
	now := testTime()
	token := Token{
		Kind: KindSession, Subject: "github:octocat", Audience: "app.example.com",
		IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	first, err := Sign(testKey, token)
	if err != nil {
		t.Fatalf("Sign() = %v", err)
	}
	second, err := Sign(testKey, token)
	if err != nil {
		t.Fatalf("Sign() = %v", err)
	}
	if first != second {
		t.Errorf("Sign() = %q then %q; want the same token", first, second)
	}
	if _, err := Verify(rotatedKey, first, Expect{Kind: KindSession, Audience: "app.example.com", Now: now}); err == nil {
		t.Error("a token signed with one key verified under another")
	}
}

// TestTheTokenCarriesNoPermissions is ADR 0003 written as a test: what is in
// the cookie is who you are, never what you may do. Permissions are evaluated
// per request so that revoking one takes effect at once.
func TestTheTokenCarriesNoPermissions(t *testing.T) {
	now := testTime()
	raw := mustSign(t, Token{
		Kind: KindSession, Subject: "github:octocat", Audience: "app.example.com",
		IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	body, _, _ := strings.Cut(raw, ".")
	decoded, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("decoding the body: %v", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(decoded, &claims); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	allowed := map[string]bool{"k": true, "sub": true, "aud": true, "nxt": true, "bnd": true, "prv": true, "iat": true, "exp": true}
	for name := range claims {
		if !allowed[name] {
			t.Errorf("the token carries a %q claim; a session says who, never what (ADR 0003)", name)
		}
	}
}

func withToken(t Token, f func(*Token)) Token {
	f(&t)
	return t
}

func mustSign(t *testing.T, token Token) string {
	t.Helper()
	raw, err := Sign(testKey, token)
	if err != nil {
		t.Fatalf("Sign() = %v", err)
	}
	return raw
}

// repack rewrites one claim of an already encoded body, leaving the signature
// of the original in place.
func repack(t *testing.T, body string, f func(map[string]any)) string {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("decoding the body: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(decoded, &claims); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	f(claims)
	encoded, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("re-encoding the body: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

// signWith produces a correctly signed token over an arbitrary body, so that a
// body which is not a token can be presented with a signature that holds.
func signWith(t *testing.T, key, body []byte) string {
	t.Helper()
	encoded := base64.RawURLEncoding.EncodeToString(body)
	signed, err := signEncoded(key, encoded)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	return signed
}
