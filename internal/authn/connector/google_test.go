package connector

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"go/ast"
	"go/parser"
	"go/token"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func newGoogleUnderTest(t *testing.T, fake *fakeOIDC) *Google {
	t.Helper()
	return &Google{
		ClientID:     fake.clientID,
		ClientSecret: StaticSecret(fake.clientSecret),
		Issuer:       fake.URL,
		HTTPClient:   fake.Client(),
	}
}

func TestGoogleAuthorizeURLAsksForAnIdentity(t *testing.T) {
	fake := newFakeOIDC(t)
	g := newGoogleUnderTest(t, fake)

	raw, err := g.AuthCodeURL(context.Background(), Request{
		RedirectURI: "https://auth.example.com/__gated/idp/google/callback",
		State:       "the-state",
		Nonce:       "the-nonce",
	})
	if err != nil {
		t.Fatalf("AuthCodeURL() = %v", err)
	}
	if strings.Contains(raw, fake.clientSecret) {
		t.Fatal("the authorize URL carries the client secret")
	}

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parsing %q: %v", raw, err)
	}
	q := u.Query()
	if got, want := q.Get("response_type"), "code"; got != want {
		t.Errorf("response_type = %q, want %q", got, want)
	}
	if got, want := q.Get("state"), "the-state"; got != want {
		t.Errorf("state = %q, want %q", got, want)
	}
	if got, want := q.Get("nonce"), "the-nonce"; got != want {
		t.Errorf("nonce = %q, want %q", got, want)
	}
	scope := strings.Fields(q.Get("scope"))
	for _, want := range []string{"openid", "email"} {
		if !contains(scope, want) {
			t.Errorf("scope = %q, want it to include %q", q.Get("scope"), want)
		}
	}
}

func TestGoogleIdentifiesByVerifiedAddress(t *testing.T) {
	fake := newFakeOIDC(t)
	g := newGoogleUnderTest(t, fake)

	id, err := g.Identify(context.Background(), fake.code, Request{
		RedirectURI: "https://auth.example.com/cb",
		Nonce:       "",
	})
	if err != nil {
		t.Fatalf("Identify() = %v", err)
	}
	if want := "google:someone@example.com"; id.Subject != want {
		t.Errorf("Subject = %q, want %q", id.Subject, want)
	}
}

// TestGoogleRefusesAnAddressNobodyVerified is the case ADR 0003 names by
// itself. The address is the identifier, so believing an unverified one hands
// whatever it was granted to whoever typed it into their profile.
func TestGoogleRefusesAnAddressNobodyVerified(t *testing.T) {
	tests := map[string]any{
		"the provider says it is not verified": false,
		"the provider says nothing about it":   nil,
		"the provider says the string true":    "true",
		"the provider says the number one":     1,
	}

	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			fake := newFakeOIDC(t)
			g := newGoogleUnderTest(t, fake)
			if value == nil {
				delete(fake.claims, "email_verified")
			} else {
				fake.claims["email_verified"] = value
			}

			id, err := g.Identify(context.Background(), fake.code, Request{RedirectURI: "https://auth.example.com/cb"})
			if err == nil {
				t.Fatalf("Identify() = %q, nil; want a refusal", id.Subject)
			}
			if id.Subject != "" {
				t.Errorf("Identify() returned the subject %q alongside an error", id.Subject)
			}
		})
	}
}

func TestGoogleRefusesAnIDTokenItCannotTrust(t *testing.T) {
	tests := map[string]func(*testing.T, *fakeOIDC){
		"signed by somebody else": func(t *testing.T, f *fakeOIDC) {
			other, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("generating a key: %v", err)
			}
			f.signWith = other
		},
		"not signed at all": func(t *testing.T, f *fakeOIDC) {
			f.alg = "none"
		},
		"signed with a symmetric algorithm": func(t *testing.T, f *fakeOIDC) {
			f.alg = "HS256"
		},
		"signed with a key that is not published": func(t *testing.T, f *fakeOIDC) {
			f.kid = "some-other-key"
		},
		"issued by another issuer": func(t *testing.T, f *fakeOIDC) {
			f.claims["iss"] = "https://issuer.example.net"
		},
		"issued for another client": func(t *testing.T, f *fakeOIDC) {
			f.claims["aud"] = "somebody-elses-client-id"
		},
		"expired": func(t *testing.T, f *fakeOIDC) {
			f.claims["exp"] = time.Now().Add(-time.Minute).Unix()
			f.claims["iat"] = time.Now().Add(-time.Hour).Unix()
		},
		"issued far in the future": func(t *testing.T, f *fakeOIDC) {
			f.claims["iat"] = time.Now().Add(time.Hour).Unix()
			f.claims["exp"] = time.Now().Add(2 * time.Hour).Unix()
		},
		"carrying no address": func(t *testing.T, f *fakeOIDC) {
			delete(f.claims, "email")
		},
		"not a token at all": func(t *testing.T, f *fakeOIDC) {
			f.idToken = "this is not a JWT"
		},
		"missing from the exchange": func(t *testing.T, f *fakeOIDC) {
			f.idToken = " "
		},
		"a discovery document that claims another issuer": func(t *testing.T, f *fakeOIDC) {
			f.issuerOverride = "https://issuer.example.net"
		},
		"an exchange that failed": func(t *testing.T, f *fakeOIDC) {
			f.tokenStatus = 500
		},
	}

	for name, break_ := range tests {
		t.Run(name, func(t *testing.T) {
			fake := newFakeOIDC(t)
			g := newGoogleUnderTest(t, fake)
			break_(t, fake)

			id, err := g.Identify(context.Background(), fake.code, Request{RedirectURI: "https://auth.example.com/cb"})
			if err == nil {
				t.Fatalf("Identify() = %q, nil; want a refusal", id.Subject)
			}
			if id.Subject != "" {
				t.Errorf("Identify() returned the subject %q alongside an error", id.Subject)
			}
		})
	}
}

// TestGoogleChecksTheNonceItAskedFor closes the loop on the OAuth round trip:
// an ID token obtained for another login must not be usable in this one.
func TestGoogleChecksTheNonceItAskedFor(t *testing.T) {
	fake := newFakeOIDC(t)
	g := newGoogleUnderTest(t, fake)
	fake.claims["nonce"] = "the-nonce"

	if _, err := g.Identify(context.Background(), fake.code, Request{
		RedirectURI: "https://auth.example.com/cb", Nonce: "the-nonce",
	}); err != nil {
		t.Fatalf("Identify() with the matching nonce = %v", err)
	}
	if _, err := g.Identify(context.Background(), fake.code, Request{
		RedirectURI: "https://auth.example.com/cb", Nonce: "another-nonce",
	}); err == nil {
		t.Fatal("Identify() accepted an ID token issued for another login")
	}

	fake2 := newFakeOIDC(t)
	g2 := newGoogleUnderTest(t, fake2)
	if _, err := g2.Identify(context.Background(), fake2.code, Request{
		RedirectURI: "https://auth.example.com/cb", Nonce: "the-nonce",
	}); err == nil {
		t.Fatal("Identify() accepted an ID token carrying no nonce when one was asked for")
	}
}

func TestGoogleNeedsItsClientSecret(t *testing.T) {
	fake := newFakeOIDC(t)
	g := newGoogleUnderTest(t, fake)
	g.ClientSecret = failingSecret{}

	if _, err := g.Identify(context.Background(), fake.code, Request{RedirectURI: "https://auth.example.com/cb"}); err == nil {
		t.Fatal("Identify() = nil; want an error when the client secret cannot be read")
	}
}

// TestNoCodePathReachesAGoogleSubjectWithoutTheVerifiedFlag is the structural
// half of the check ADR 0003 asks for. The table above enumerates the answers;
// this reads the package's own source and shows there is nowhere else to go.
//
// Two things are asserted. The prefix that makes a Google subject is written
// in exactly one function, and that function takes a value of a type only the
// verification produces. Together with the compiler, that leaves no path to a
// Google subject that did not go through the check.
func TestNoCodePathReachesAGoogleSubjectWithoutTheVerifiedFlag(t *testing.T) {
	const (
		prefixIdent  = "googleSubjectPrefix"
		builder      = "googleSubject"
		witnessType  = "verifiedAddress"
		witnessMaker = "requireVerifiedEmail"
	)

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	files := map[string]*ast.File{}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		files[name] = file
	}

	var (
		usesOutsideBuilder []string
		foundBuilder       bool
		foundMaker         bool
	)
	for path, file := range files {
		{
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				switch fn.Name.Name {
				case builder:
					foundBuilder = true
					assertTakesWitness(t, fn, witnessType)
				case witnessMaker:
					foundMaker = true
					assertReturnsWitness(t, fn, witnessType)
				}
				ast.Inspect(fn, func(n ast.Node) bool {
					id, ok := n.(*ast.Ident)
					if !ok || id.Name != prefixIdent {
						return true
					}
					if fn.Name.Name != builder {
						usesOutsideBuilder = append(usesOutsideBuilder,
							path+":"+fset.Position(id.Pos()).String()+" in "+fn.Name.Name)
					}
					return true
				})
			}
			// A literal "google:" written anywhere would sidestep the
			// constant entirely.
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				if strings.Contains(lit.Value, `google:`) && !strings.Contains(lit.Value, prefixIdent) {
					if !isDeclarationOf(file, lit, prefixIdent) {
						usesOutsideBuilder = append(usesOutsideBuilder,
							"a literal "+lit.Value+" at "+fset.Position(lit.Pos()).String())
					}
				}
				return true
			})
		}
	}

	if !foundBuilder {
		t.Fatalf("there is no %s function; the check this test makes no longer applies", builder)
	}
	if !foundMaker {
		t.Fatalf("there is no %s function; the check this test makes no longer applies", witnessMaker)
	}
	for _, use := range usesOutsideBuilder {
		t.Errorf("a Google subject is built at %s, outside %s; "+
			"every Google identity must come from an address the ID token said was verified (ADR 0003)", use, builder)
	}
}

// assertTakesWitness checks that the subject builder can only be handed a
// value the verification produced.
func assertTakesWitness(t *testing.T, fn *ast.FuncDecl, witness string) {
	t.Helper()
	if fn.Type.Params == nil || len(fn.Type.Params.List) != 1 {
		t.Fatalf("%s takes %d parameters, want exactly one of type %s", fn.Name.Name, len(fn.Type.Params.List), witness)
	}
	id, ok := fn.Type.Params.List[0].Type.(*ast.Ident)
	if !ok || id.Name != witness {
		t.Fatalf("%s takes a %v, want a %s", fn.Name.Name, fn.Type.Params.List[0].Type, witness)
	}
}

func assertReturnsWitness(t *testing.T, fn *ast.FuncDecl, witness string) {
	t.Helper()
	if fn.Type.Results == nil || len(fn.Type.Results.List) == 0 {
		t.Fatalf("%s returns nothing, want a %s", fn.Name.Name, witness)
	}
	id, ok := fn.Type.Results.List[0].Type.(*ast.Ident)
	if !ok || id.Name != witness {
		t.Fatalf("%s returns a %v, want a %s", fn.Name.Name, fn.Type.Results.List[0].Type, witness)
	}
}

// isDeclarationOf reports whether a literal is the right-hand side of the
// named constant, which is the one place the prefix is allowed to be spelled.
func isDeclarationOf(file *ast.File, lit *ast.BasicLit, name string) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, ident := range spec.Names {
			if ident.Name != name || i >= len(spec.Values) {
				continue
			}
			if spec.Values[i] == ast.Expr(lit) {
				found = true
			}
		}
		return true
	})
	return found
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
