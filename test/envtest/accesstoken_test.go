//go:build envtest

package envtest_test

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/yuanying/gated/internal/accesstoken"
	gatev1alpha1 "github.com/yuanying/gated/internal/apis/gate/v1alpha1"
	"github.com/yuanying/gated/internal/controller"
	"github.com/yuanying/gated/internal/proxy"
)

const minimalAccessToken = `
apiVersion: gate.unstable.cloud/v1alpha1
kind: AccessToken
metadata:
  name: registry
spec:
  subject: github:octocat
`

func TestAccessTokenMinimalSpec(t *testing.T) {
	ns := newNamespace(t)
	got := mustCreate(t, ns, minimalAccessToken)

	if v := field(t, got, "spec", "subject"); v != "github:octocat" {
		t.Errorf("spec.subject = %q, want %q", v, "github:octocat")
	}

	// secretName stays unset so the controller can fall back to the
	// AccessToken's own name; defaulting it here would freeze the choice.
	if _, found, _ := unstructured.NestedString(got.Object, "spec", "secretName"); found {
		t.Error("spec.secretName was defaulted, want it left unset")
	}
}

func TestAccessTokenRejectsInvalidSpecs(t *testing.T) {
	tests := []struct {
		name     string
		manifest string
	}{
		{
			name: "no subject",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: AccessToken
metadata:
  name: no-subject
spec: {}
`,
		},
		{
			name: "no spec at all",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: AccessToken
metadata:
  name: no-spec
`,
		},
		{
			// A token has to belong to someone. Acting as "anyone"
			// would hand every holder whatever the anonymous rules
			// already grant, which needs no token.
			name: "an authenticated system subject",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: AccessToken
metadata:
  name: system-authenticated
spec:
  subject: system:authenticated
`,
		},
		{
			name: "an unauthenticated system subject",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: AccessToken
metadata:
  name: system-unauthenticated
spec:
  subject: system:unauthenticated
`,
		},
		{
			name: "a subject without a provider prefix",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: AccessToken
metadata:
  name: bare-subject
spec:
  subject: octocat
`,
		},
		{
			name: "a secretName that is not a resource name",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: AccessToken
metadata:
  name: bad-secret-name
spec:
  subject: github:octocat
  secretName: Registry_Token
`,
		},
	}

	ns := newNamespace(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := create(t, ns, tt.manifest)
			assertRejected(t, err)
		})
	}
}

func TestAccessTokenStatusHoldsOnlyTheHash(t *testing.T) {
	ns := newNamespace(t)
	obj := mustCreate(t, ns, minimalAccessToken)

	const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	setStatus(t, obj, map[string]any{
		"observedGeneration": int64(1),
		"secretRef":          map[string]any{"name": "registry"},
		"tokenHash":          hash,
		"lastUsedTime":       "2026-08-21T00:00:00Z",
	})
	if err := k8sClient.Status().Update(context.Background(), obj); err != nil {
		t.Fatalf("Status().Update() = %v, want nil", err)
	}

	reread := object(t, ns, minimalAccessToken)
	if err := k8sClient.Get(context.Background(), client.ObjectKeyFromObject(obj), reread); err != nil {
		t.Fatalf("Get() = %v, want nil", err)
	}
	if v := field(t, reread, "status", "tokenHash"); v != hash {
		t.Errorf("status.tokenHash = %q, want %q", v, hash)
	}
	if v := field(t, reread, "status", "secretRef", "name"); v != "registry" {
		t.Errorf("status.secretRef.name = %q, want %q", v, "registry")
	}

	// The proxy matches presented tokens against this hash, so a value that
	// is not a SHA-256 digest can only be a mistake.
	setStatus(t, obj, map[string]any{"tokenHash": "not-a-sha-256-digest"})
	assertRejected(t, k8sClient.Status().Update(context.Background(), obj))
}

func setStatus(t *testing.T, obj *unstructured.Unstructured, status map[string]any) {
	t.Helper()

	if err := unstructured.SetNestedMap(obj.Object, status, "status"); err != nil {
		t.Fatalf("setting the status: %v", err)
	}
}

// The tests below are about the join between the two controllers and the
// request path: the token is minted by one, recognised by another out of a
// status rather than a Secret (ADR 0013), and then decided upon by exactly the
// machinery a browser's cookie goes through (ADR 0004).

// tokenFixture is one manager carrying the whole token path — routing, the
// permission snapshot, the issuer, the set the proxy matches against and the
// recorder that writes back when a token was used — in front of a backend that
// reports what it was handed.
type tokenFixture struct {
	front   *httptest.Server
	backend *echoBackend
}

// echoBackend reports the credentials it was given, so that a test can assert
// on what did not reach it.
type echoBackend struct {
	addr string

	mu   sync.Mutex
	last string
}

func newEchoBackend(t *testing.T) *echoBackend {
	t.Helper()

	backend := &echoBackend{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backend.mu.Lock()
		backend.last = r.Header.Get("Authorization")
		backend.mu.Unlock()
		io.WriteString(w, "from the backend")
	}))
	t.Cleanup(server.Close)

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parsing %q: %v", server.URL, err)
	}
	backend.addr = u.Host
	return backend
}

func (b *echoBackend) lastAuthorization() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.last
}

// startTokens builds the manager, scoped to one namespace so that objects left
// behind by another test — envtest runs nothing that empties a namespace — are
// not reconciled by this one.
func startTokens(t *testing.T, ns string, backend *echoBackend) *tokenFixture {
	t.Helper()

	mgr, err := ctrl.NewManager(restCfg, ctrl.Options{
		Scheme:                 testScheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		LeaderElection:         false,
		Controller:             ctrlconfig.Controller{SkipNameValidation: ptr.To(true)},
		Cache:                  cache.Options{DefaultNamespaces: map[string]cache.Config{ns: {}}},
		Client: client.Options{
			// The same arrangement the binary uses: Secrets are read
			// straight from the API server, because the cache it
			// keeps of them holds TLS Secrets only (ADR 0013).
			Cache: &client.CacheOptions{DisableFor: []client.Object{&corev1.Secret{}}},
		},
	})
	if err != nil {
		t.Fatalf("building the manager: %v", err)
	}

	tables := &proxy.TableStore{}
	routes := &controller.RoutingReconciler{
		Reader:       mgr.GetCache(),
		IngressClass: ingressClass,
		Tables:       tables,
	}
	if err := routes.SetupWithManager(mgr); err != nil {
		t.Fatalf("registering the routing controller: %v", err)
	}

	policies := &proxy.PolicyStore{}
	authorization := &controller.AuthorizationReconciler{Reader: mgr.GetCache(), Policies: policies}
	if err := authorization.SetupWithManager(mgr); err != nil {
		t.Fatalf("registering the authorisation controller: %v", err)
	}

	issuer := &controller.AccessTokenReconciler{
		Client:   mgr.GetClient(),
		Recorder: mgr.GetEventRecorderFor("gated-accesstokens"),
		// Short, because one of the tests deletes a Secret and waits
		// for the token to be minted again. In the binary this is the
		// interval at which a Secret that cannot be watched is looked
		// at anyway.
		Resync: 200 * time.Millisecond,
	}
	if err := issuer.SetupWithManager(mgr); err != nil {
		t.Fatalf("registering the AccessToken controller: %v", err)
	}

	tokens := &accesstoken.Store{}
	set := &controller.TokenSetReconciler{Reader: mgr.GetCache(), Tokens: tokens}
	if err := set.SetupWithManager(mgr); err != nil {
		t.Fatalf("registering the token set controller: %v", err)
	}

	uses := &accesstoken.Uses{}
	if err := mgr.Add(&controller.AccessTokenUsageRecorder{
		Client:   mgr.GetClient(),
		Uses:     uses,
		Interval: 100 * time.Millisecond,
	}); err != nil {
		t.Fatalf("registering the usage recorder: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("the manager did not stop")
		}
	})
	if !mgr.GetCache().WaitForCacheSync(ctx) {
		t.Fatal("the cache never synced")
	}

	fixture := &tokenFixture{backend: backend}
	if backend != nil {
		dialer := &dialRecorder{to: backend.addr}
		authenticator := &accesstoken.Authenticator{Tokens: tokens, Usage: uses}
		decision := &proxy.Authorization{
			Policies: policies,
			Subjects: proxy.SubjectResolvers{authenticator},
			AuthHost: authHost,
		}
		fixture.front = httptest.NewServer(&proxy.Handler{
			Tables:    tables,
			Backends:  &controller.ServiceResolver{Reader: mgr.GetCache()},
			Transport: &http.Transport{DialContext: dialer.DialContext},
			Middleware: func(next http.Handler) http.Handler {
				return authenticator.Wrap(decision.Wrap(next))
			},
		})
		t.Cleanup(fixture.front.Close)
	}
	return fixture
}

// get sends one request through the proxy carrying whatever Authorization
// header is given, as a client that cannot follow a redirect to a login.
func (f *tokenFixture) get(t *testing.T, host, path, authorization string) int {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, f.front.URL+path, nil)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	req.Host = host
	req.Header.Set("Accept", clientAccept)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := f.front.Client().Do(req)
	if err != nil {
		t.Fatalf("Do() = %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func basicAuthorization(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

// newAccessToken creates an AccessToken that lives as long as the test.
func newAccessToken(t *testing.T, ns, name, subject, secretName string) *gatev1alpha1.AccessToken {
	t.Helper()

	token := &gatev1alpha1.AccessToken{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       gatev1alpha1.AccessTokenSpec{Subject: subject, SecretName: secretName},
	}
	if err := k8sClient.Create(context.Background(), token); err != nil {
		t.Fatalf("creating the AccessToken: %v", err)
	}
	t.Cleanup(func() {
		if err := k8sClient.Delete(context.Background(), token); err != nil && !apierrors.IsNotFound(err) {
			t.Logf("deleting AccessToken %s/%s: %v", ns, name, err)
		}
	})
	return token
}

func readAccessToken(t *testing.T, ns, name string) *gatev1alpha1.AccessToken {
	t.Helper()

	var token gatev1alpha1.AccessToken
	if err := k8sClient.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &token); err != nil {
		t.Fatalf("reading AccessToken %s/%s: %v", ns, name, err)
	}
	return &token
}

// issuedToken waits until a token has been minted and returns its value and
// the digest the status advertises.
func issuedToken(t *testing.T, ns, name, secretName string) (string, string) {
	t.Helper()

	waitFor(t, "the token to be issued", func() bool {
		return readAccessToken(t, ns, name).Status.TokenHash != ""
	})
	token := readAccessToken(t, ns, name)

	var secret corev1.Secret
	key := types.NamespacedName{Namespace: ns, Name: secretName}
	if err := k8sClient.Get(context.Background(), key, &secret); err != nil {
		t.Fatalf("reading Secret %s: %v", key, err)
	}
	return string(secret.Data[accesstoken.SecretKey]), token.Status.TokenHash
}

// TestAccessTokenIsMintedIntoASecret is the half nobody types: the value is
// invented by the controller, the status carries only its digest, and the
// Secret belongs to the AccessToken that declared it.
func TestAccessTokenIsMintedIntoASecret(t *testing.T) {
	ns := newNamespace(t)
	startTokens(t, ns, nil)

	declared := newAccessToken(t, ns, "registry", "github:octocat", "")
	value, hash := issuedToken(t, ns, "registry", "registry")

	if !strings.HasPrefix(value, accesstoken.Prefix) {
		t.Errorf("the issued token = %q, want it to start with %q", value, accesstoken.Prefix)
	}
	if got := accesstoken.Hash(value); got != hash {
		t.Errorf("status.tokenHash = %q, want the digest of the issued token %q", hash, got)
	}

	token := readAccessToken(t, ns, "registry")
	if token.Status.SecretRef == nil || token.Status.SecretRef.Name != "registry" {
		t.Errorf("status.secretRef = %+v, want the AccessToken's own name", token.Status.SecretRef)
	}
	if !meta.IsStatusConditionTrue(token.Status.Conditions, gatev1alpha1.ConditionTokenIssued) {
		t.Errorf("conditions = %+v, want %s to be True", token.Status.Conditions, gatev1alpha1.ConditionTokenIssued)
	}
	if token.Status.ObservedGeneration != token.Generation {
		t.Errorf("observedGeneration = %d, want %d", token.Status.ObservedGeneration, token.Generation)
	}

	var secret corev1.Secret
	key := types.NamespacedName{Namespace: ns, Name: "registry"}
	if err := k8sClient.Get(context.Background(), key, &secret); err != nil {
		t.Fatalf("reading Secret %s: %v", key, err)
	}
	if secret.Type != corev1.SecretTypeOpaque {
		t.Errorf("the Secret is of type %q, want %q", secret.Type, corev1.SecretTypeOpaque)
	}
	// The Secret belongs to the AccessToken, so deleting the declaration
	// takes the credential with it. That is what "delete it to revoke it"
	// has to mean once the request path stops matching (ADR 0004).
	owner := metav1.GetControllerOf(&secret)
	if owner == nil || owner.Kind != "AccessToken" || owner.Name != "registry" || owner.UID != declared.UID {
		t.Errorf("the Secret's controller reference = %+v, want the AccessToken", owner)
	}

	// Deleting the Secret is the one way to rotate: the value cannot be
	// recovered from its digest, so there is nothing to put back.
	if err := k8sClient.Delete(context.Background(), &secret); err != nil {
		t.Fatalf("deleting the Secret: %v", err)
	}
	waitFor(t, "the token to be minted again", func() bool {
		got := readAccessToken(t, ns, "registry").Status.TokenHash
		return got != "" && got != hash
	})
	rotated, rotatedHash := issuedToken(t, ns, "registry", "registry")
	if rotated == value {
		t.Error("the rotated token is the one that was deleted")
	}
	if got := accesstoken.Hash(rotated); got != rotatedHash {
		t.Errorf("status.tokenHash = %q, want the digest of the rotated token %q", rotatedHash, got)
	}
}

// TestAccessTokenOpensBothDoors is the requirement of ADR 0004 in one test:
// two ways to present a credential, one set of rules behind them, and a
// deletion that stops the next request.
func TestAccessTokenOpensBothDoors(t *testing.T) {
	ns := newNamespace(t)
	backend := newEchoBackend(t)
	newService(t, ns, "web", 80, "http")
	fixture := startTokens(t, ns, backend)

	const host = "token-doors.example.com"
	newProtectedIngress(t, ns, "registry", host)
	newNetworkRole(t, ns, "pusher", "registry", rule([]string{"*"}, "*"))
	newNetworkRoleBinding(t, ns, "pushers", "pusher", "github:octocat")

	// Nobody may in without a credential, and a client that cannot follow a
	// redirect is challenged rather than sent to a login (ADR 0002).
	waitFor(t, "the role to take effect", func() bool {
		return fixture.get(t, host, "/v2/", "") == http.StatusUnauthorized
	})

	newAccessToken(t, ns, "push", "github:octocat", "")
	value, _ := issuedToken(t, ns, "push", "push")
	waitFor(t, "the token to be accepted", func() bool {
		return fixture.get(t, host, "/v2/", "Bearer "+value) == http.StatusOK
	})

	// A credential gated spent is not forwarded. It authenticates as a
	// person, and anything behind the proxy that received it could turn
	// round and be that person somewhere else.
	if got := backend.lastAuthorization(); got != "" {
		t.Errorf("the backend was handed Authorization: %q, want it removed", got)
	}

	tests := []struct {
		name          string
		authorization string
		want          int
	}{
		{name: "a bearer token", authorization: "Bearer " + value, want: http.StatusOK},
		// The door docker login can use without being changed. The user
		// name is not read at all, so whatever was typed goes through.
		{name: "the password field of BASIC", authorization: basicAuthorization("octocat", value), want: http.StatusOK},
		{name: "a BASIC password with any user name", authorization: basicAuthorization("whoever", value), want: http.StatusOK},
		{name: "a BASIC password with no user name", authorization: basicAuthorization("", value), want: http.StatusOK},
		// The token in the user name field is not a credential: one
		// place per scheme, so that what was presented is unambiguous.
		{name: "the token in the user name", authorization: basicAuthorization(value, ""), want: http.StatusUnauthorized},
		{name: "a token nobody issued", authorization: "Bearer " + accesstoken.Prefix + "forged", want: http.StatusUnauthorized},
		// The digest is in a status, which is far more widely readable
		// than the Secret. Presenting it must not work.
		{name: "the digest of the real token", authorization: "Bearer " + accesstoken.Hash(value), want: http.StatusUnauthorized},
		{name: "an ordinary BASIC password", authorization: basicAuthorization("octocat", "hunter2"), want: http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fixture.get(t, host, "/v2/", tt.authorization); got != tt.want {
				t.Errorf("status = %d, want %d", got, tt.want)
			}
		})
	}

	// A token for somebody the role does not name is authenticated and
	// then refused, by the same rules that refuse a logged-in browser.
	// Logging in would not help either of them, so it is 403 and not a
	// challenge.
	newAccessToken(t, ns, "read", "github:hubot", "")
	other, _ := issuedToken(t, ns, "read", "read")
	waitFor(t, "the second token to be recognised", func() bool {
		return fixture.get(t, host, "/v2/", "Bearer "+other) == http.StatusForbidden
	})

	// Deleting the AccessToken revokes it. Nothing about the Secret or the
	// value changes; the set the proxy matches against no longer holds the
	// digest, so the next request does not get in (ADR 0004).
	if err := k8sClient.Delete(context.Background(), readAccessToken(t, ns, "push")); err != nil {
		t.Fatalf("deleting the AccessToken: %v", err)
	}
	waitFor(t, "the deleted token to stop working", func() bool {
		return fixture.get(t, host, "/v2/", "Bearer "+value) == http.StatusUnauthorized
	})
	if got := fixture.get(t, host, "/v2/", basicAuthorization("octocat", value)); got != http.StatusUnauthorized {
		t.Errorf("status for the revoked token in the password field = %d, want %d",
			got, http.StatusUnauthorized)
	}
}

// TestAccessTokenRecordsWhenItWasUsed is what makes an abandoned token
// findable (ADR 0004). The write happens away from the request path, so what
// is asserted is that it happens at all.
func TestAccessTokenRecordsWhenItWasUsed(t *testing.T) {
	ns := newNamespace(t)
	backend := newEchoBackend(t)
	newService(t, ns, "web", 80, "http")
	fixture := startTokens(t, ns, backend)

	const host = "token-used.example.com"
	newProtectedIngress(t, ns, "registry", host)
	newNetworkRole(t, ns, "pusher", "registry", rule([]string{"*"}, "*"))
	newNetworkRoleBinding(t, ns, "pushers", "pusher", "github:octocat")
	newAccessToken(t, ns, "push", "github:octocat", "")
	value, _ := issuedToken(t, ns, "push", "push")

	before := time.Now().Add(-time.Minute)
	waitFor(t, "the token to be accepted", func() bool {
		return fixture.get(t, host, "/v2/", "Bearer "+value) == http.StatusOK
	})
	waitFor(t, "the use to be written back", func() bool {
		used := readAccessToken(t, ns, "push").Status.LastUsedTime
		return used != nil && used.After(before)
	})

	// The issuer writes the same status. Neither controller may erase what
	// the other put there.
	token := readAccessToken(t, ns, "push")
	if token.Status.TokenHash == "" {
		t.Error("recording the use erased status.tokenHash")
	}
	if !meta.IsStatusConditionTrue(token.Status.Conditions, gatev1alpha1.ConditionTokenIssued) {
		t.Error("recording the use erased the TokenIssued condition")
	}
}

// TestAccessTokenLeavesAForeignSecretAlone is about a name collision that
// would otherwise be silent and destructive: spec.secretName naming something
// somebody else put there.
func TestAccessTokenLeavesAForeignSecretAlone(t *testing.T) {
	ns := newNamespace(t)
	startTokens(t, ns, nil)

	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "registry-credentials"},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"password": []byte("somebody else's")},
	}
	if err := k8sClient.Create(context.Background(), existing); err != nil {
		t.Fatalf("creating the Secret: %v", err)
	}
	t.Cleanup(func() {
		if err := k8sClient.Delete(context.Background(), existing); err != nil && !apierrors.IsNotFound(err) {
			t.Logf("deleting the Secret: %v", err)
		}
	})

	newAccessToken(t, ns, "collides", "github:octocat", "registry-credentials")
	waitFor(t, "the collision to be reported", func() bool {
		condition := meta.FindStatusCondition(
			readAccessToken(t, ns, "collides").Status.Conditions, gatev1alpha1.ConditionTokenIssued)
		return condition != nil && condition.Status == metav1.ConditionFalse
	})

	if got := readAccessToken(t, ns, "collides").Status.TokenHash; got != "" {
		t.Errorf("status.tokenHash = %q, want it empty while nothing was issued", got)
	}

	var secret corev1.Secret
	key := types.NamespacedName{Namespace: ns, Name: "registry-credentials"}
	if err := k8sClient.Get(context.Background(), key, &secret); err != nil {
		t.Fatalf("reading Secret %s: %v", key, err)
	}
	if _, found := secret.Data[accesstoken.SecretKey]; found {
		t.Error("a token was written into a Secret gated did not create")
	}
	if got := string(secret.Data["password"]); got != "somebody else's" {
		t.Errorf("the Secret's own contents = %q, want them untouched", got)
	}
}
