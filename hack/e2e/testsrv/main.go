// Command testsrv is the two servers the end-to-end tests need inside the
// cluster: a stand-in identity provider, and an application to be protected.
//
// Both live in one program because they are the same kind of thing — a few
// handlers with no state worth keeping — and one image is one build and one
// `kind load`. Which role a Deployment plays is a flag.
//
// The identity provider speaks GitHub's OAuth exchange rather than OIDC: it is
// the shorter of the two protocols gated implements, and the tests are here to
// exercise gated's login flow end to end, not to re-test the connectors
// (ADR 0007 leaves that to the integration layer). Nothing here talks to
// github.com, and nothing here is reachable from outside the test cluster.
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// LoginHeader is how a test says who is about to log in. A real provider asks
// the visitor; this one is told, because the test is the visitor.
const LoginHeader = "X-Mock-Login"

func main() {
	var (
		addr         = flag.String("addr", ":8080", "Listen address.")
		mode         = flag.String("mode", "backend", `What to serve: "idp" or "backend".`)
		clientID     = flag.String("client-id", "", "OAuth client ID the exchange must present.")
		clientSecret = flag.String("client-secret", "", "OAuth client secret the exchange must present.")
		defaultLogin = flag.String("default-login", "octocat", "Account name to log in as when a request does not name one.")
	)
	flag.Parse()

	var handler http.Handler
	switch *mode {
	case "idp":
		handler = &idp{clientID: *clientID, clientSecret: *clientSecret, defaultLogin: *defaultLogin}
	case "backend":
		handler = http.HandlerFunc(echo)
	default:
		fmt.Fprintf(os.Stderr, "unknown -mode %q\n", *mode)
		os.Exit(1)
	}

	server := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("testsrv listening on %s in %s mode", *addr, *mode)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// echo answers as the application behind an Ingress would.
//
// It reports what it was asked, so that a test can tell a reply that came
// from here from one gated produced itself.
func echo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "gated-e2e backend\nmethod=%s\nhost=%s\npath=%s\n", r.Method, r.Host, r.URL.Path)
}

// idp answers the three requests gated's GitHub connector makes.
type idp struct {
	clientID     string
	clientSecret string
	defaultLogin string
}

func (p *idp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/login/oauth/authorize":
		p.authorize(w, r)
	case "/login/oauth/access_token":
		p.token(w, r)
	case "/user":
		p.user(w, r)
	default:
		http.NotFound(w, r)
	}
}

// authorize sends the visitor straight back with a code. There is no consent
// screen: whoever the request says it is, is who it is.
func (p *idp) authorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if got := query.Get("client_id"); got != p.clientID {
		http.Error(w, fmt.Sprintf("unknown client_id %q", got), http.StatusBadRequest)
		return
	}
	redirect, err := url.Parse(query.Get("redirect_uri"))
	if err != nil || redirect.Scheme == "" || redirect.Host == "" {
		http.Error(w, "redirect_uri is not an absolute address", http.StatusBadRequest)
		return
	}

	// The code carries the account name, so that the exchange that follows
	// needs no memory of this request.
	back := *redirect
	back.RawQuery = url.Values{
		"code":  {encodeCode(p.login(r))},
		"state": {query.Get("state")},
	}.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound)
}

// token trades the code for an access token, checking the client credentials
// the way GitHub does: a bad one is a 200 with an error in the body.
func (p *idp) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if r.PostForm.Get("client_id") != p.clientID || r.PostForm.Get("client_secret") != p.clientSecret {
		writeJSON(w, map[string]string{"error": "incorrect_client_credentials"})
		return
	}
	login, ok := decodeCode(r.PostForm.Get("code"))
	if !ok {
		writeJSON(w, map[string]string{"error": "bad_verification_code"})
		return
	}
	writeJSON(w, map[string]string{"access_token": "gho_" + encodeCode(login), "token_type": "bearer"})
}

// user says whose token this is.
func (p *idp) user(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer gho_")
	if !ok {
		http.Error(w, "bad credentials", http.StatusUnauthorized)
		return
	}
	login, ok := decodeCode(token)
	if !ok {
		http.Error(w, "bad credentials", http.StatusUnauthorized)
		return
	}
	writeJSON(w, map[string]any{"login": login, "id": 1})
}

// login is the account this request logs in as.
func (p *idp) login(r *http.Request) string {
	if named := r.Header.Get(LoginHeader); named != "" {
		return named
	}
	return p.defaultLogin
}

func encodeCode(login string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(login))
}

func decodeCode(code string) (string, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(code)
	if err != nil || len(raw) == 0 {
		return "", false
	}
	return string(raw), true
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}
