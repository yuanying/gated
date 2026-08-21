//go:build envtest

package envtest_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	gatev1alpha1 "github.com/yuanying/gated/internal/apis/gate/v1alpha1"
	"github.com/yuanying/gated/internal/controller"
	"github.com/yuanying/gated/internal/proxy"
)

// These tests are about the join ADR 0007 warns is invisible to both a table
// test and a schema test: the pure decision may be right while the permissions
// handed to it are assembled wrongly. So the NetworkRoles here are applied to a
// real API server, and what is asserted is what the proxy answers.

// authHost is the central authentication host used in these tests. It names
// nothing outside the example domain.
const authHost = "auth.example.com"

// headerSubject stands in for authentication, which arrives in stage 6. It is
// the same seam the session cookie will plug into.
type headerSubject struct{}

func (headerSubject) Subject(r *http.Request) string { return r.Header.Get("X-Test-Subject") }

// authorizationFixture is one manager carrying the whole authorisation path:
// the routing table, the permission snapshot and the two status writers.
type authorizationFixture struct {
	front    *httptest.Server
	policies *proxy.PolicyStore
}

func startAuthorization(t *testing.T, backendAddr string) *authorizationFixture {
	t.Helper()

	mgr, err := ctrl.NewManager(restCfg, ctrl.Options{
		Scheme:                 testScheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		LeaderElection:         false,
		Controller:             ctrlconfig.Controller{SkipNameValidation: ptr.To(true)},
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
	authorization := &controller.AuthorizationReconciler{
		Reader:   mgr.GetCache(),
		Policies: policies,
	}
	if err := authorization.SetupWithManager(mgr); err != nil {
		t.Fatalf("registering the authorisation controller: %v", err)
	}

	roles := &controller.NetworkRoleReconciler{
		Client:   mgr.GetClient(),
		Reader:   mgr.GetCache(),
		Recorder: mgr.GetEventRecorderFor("gated-authorization"),
	}
	if err := roles.SetupWithManager(mgr); err != nil {
		t.Fatalf("registering the NetworkRole controller: %v", err)
	}
	bindings := &controller.NetworkRoleBindingReconciler{
		Client:   mgr.GetClient(),
		Reader:   mgr.GetCache(),
		Recorder: mgr.GetEventRecorderFor("gated-authorization"),
	}
	if err := bindings.SetupWithManager(mgr); err != nil {
		t.Fatalf("registering the NetworkRoleBinding controller: %v", err)
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

	fixture := &authorizationFixture{policies: policies}
	if backendAddr != "" {
		dialer := &dialRecorder{to: backendAddr}
		fixture.front = httptest.NewServer(&proxy.Handler{
			Tables:    tables,
			Backends:  &controller.ServiceResolver{Reader: mgr.GetCache()},
			Transport: &http.Transport{DialContext: dialer.DialContext},
			Middleware: (&proxy.Authorization{
				Policies: policies,
				Subjects: headerSubject{},
				AuthHost: authHost,
			}).Wrap,
		})
		t.Cleanup(fixture.front.Close)
	}
	return fixture
}

// get sends one request through the proxy, as a browser unless a subject or an
// Accept header says otherwise.
func (f *authorizationFixture) get(t *testing.T, method, host, path, subject, accept string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(method, f.front.URL+path, nil)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	req.Host = host
	req.Header.Set("Accept", accept)
	if subject != "" {
		req.Header.Set("X-Test-Subject", subject)
	}
	// The redirect to the login host is the thing under test, so it is not
	// followed.
	client := &http.Client{
		Transport: f.front.Client().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() = %v", err)
	}
	resp.Body.Close()
	return resp
}

const (
	browserAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	clientAccept  = "*/*"
)

// newProtectedIngress creates an Ingress that lives as long as the test.
//
// envtest runs no controller that reclaims a namespace, so an Ingress left
// behind goes on being routed by every other suite's table. It is deleted
// explicitly, and each test uses a host of its own.
func newProtectedIngress(t *testing.T, ns, name, host string) *networkingv1.Ingress {
	t.Helper()

	ing := newIngress(ns, name, ingressClass, host, "/", "web", 80)
	ing.Spec.TLS = []networkingv1.IngressTLS{{Hosts: []string{host}, SecretName: name + "-tls"}}
	if err := k8sClient.Create(context.Background(), ing); err != nil {
		t.Fatalf("creating the Ingress: %v", err)
	}
	t.Cleanup(func() {
		if err := k8sClient.Delete(context.Background(), ing); err != nil {
			t.Logf("deleting Ingress %s/%s: %v", ns, name, err)
		}
	})
	return ing
}

// newNetworkRole creates a role that lives as long as the test.
func newNetworkRole(t *testing.T, ns, name, target string, rules ...gatev1alpha1.NetworkRoleRule) *gatev1alpha1.NetworkRole {
	t.Helper()

	role := &gatev1alpha1.NetworkRole{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: gatev1alpha1.NetworkRoleSpec{
			TargetRef: gatev1alpha1.TargetReference{Name: target},
			Rules:     rules,
		},
	}
	if err := k8sClient.Create(context.Background(), role); err != nil {
		t.Fatalf("creating the NetworkRole: %v", err)
	}
	t.Cleanup(func() {
		if err := k8sClient.Delete(context.Background(), role); err != nil && !apierrors.IsNotFound(err) {
			t.Logf("deleting NetworkRole %s/%s: %v", ns, name, err)
		}
	})
	return role
}

// newNetworkRoleBinding creates a binding that lives as long as the test.
func newNetworkRoleBinding(t *testing.T, ns, name, roleName string, subjects ...string) *gatev1alpha1.NetworkRoleBinding {
	t.Helper()

	binding := &gatev1alpha1.NetworkRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: gatev1alpha1.NetworkRoleBindingSpec{
			RoleRef: gatev1alpha1.RoleReference{Name: roleName},
		},
	}
	for _, s := range subjects {
		binding.Spec.Subjects = append(binding.Spec.Subjects, gatev1alpha1.Subject{Name: s})
	}
	if err := k8sClient.Create(context.Background(), binding); err != nil {
		t.Fatalf("creating the NetworkRoleBinding: %v", err)
	}
	t.Cleanup(func() {
		if err := k8sClient.Delete(context.Background(), binding); err != nil && !apierrors.IsNotFound(err) {
			t.Logf("deleting NetworkRoleBinding %s/%s: %v", ns, name, err)
		}
	})
	return binding
}

func rule(paths []string, methods ...gatev1alpha1.HTTPMethod) gatev1alpha1.NetworkRoleRule {
	return gatev1alpha1.NetworkRoleRule{Paths: paths, Methods: methods}
}

// TestAuthorizationDecidesWhatTheProxyAnswers walks one Ingress from
// unprotected to protected and back.
func TestAuthorizationDecidesWhatTheProxyAnswers(t *testing.T) {
	ns := newNamespace(t)
	backendAddr := newBackend(t, "from the backend")
	newService(t, ns, "web", 80, "http")
	fixture := startAuthorization(t, backendAddr)

	const host = "authz-proxy.example.com"
	newProtectedIngress(t, ns, "storefront", host)

	// Nothing names this Ingress, so it is served without authentication
	// (ADR 0002).
	waitFor(t, "the Ingress to be routed and served", func() bool {
		return fixture.get(t, http.MethodGet, host, "/", "", browserAccept).StatusCode == http.StatusOK
	})

	// A role that grants everything to one account. Until it is bound,
	// nobody may in — and logging in would not help, so it is a refusal.
	newNetworkRole(t, ns, "owner", "storefront", rule([]string{"*"}, "*"))
	waitFor(t, "the role to take effect", func() bool {
		return fixture.get(t, http.MethodGet, host, "/", "", browserAccept).StatusCode == http.StatusForbidden
	})

	newNetworkRoleBinding(t, ns, "owners", "owner", "github:octocat")
	waitFor(t, "the binding to take effect", func() bool {
		return fixture.get(t, http.MethodGet, host, "/", "", browserAccept).StatusCode == http.StatusFound
	})

	// A browser is sent to the login; a program is challenged instead.
	resp := fixture.get(t, http.MethodGet, host, "/orders", "", browserAccept)
	if got, want := resp.Header.Get("Location"),
		"https://"+authHost+"/__gated/login?next=https%3A%2F%2F"+host+"%2Forders"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
	if got := fixture.get(t, http.MethodGet, host, "/", "", clientAccept); got.StatusCode != http.StatusUnauthorized {
		t.Errorf("status for a non-browser = %d, want %d", got.StatusCode, http.StatusUnauthorized)
	}

	// The bound subject gets through; another logged in account does not.
	if got := fixture.get(t, http.MethodGet, host, "/", "github:octocat", browserAccept); got.StatusCode != http.StatusOK {
		t.Errorf("status for the bound subject = %d, want %d", got.StatusCode, http.StatusOK)
	}
	if got := fixture.get(t, http.MethodGet, host, "/", "github:hubot", browserAccept); got.StatusCode != http.StatusForbidden {
		t.Errorf("status for another account = %d, want %d", got.StatusCode, http.StatusForbidden)
	}

	// Reading is opened to everyone, writing is not. This is the case
	// ADR 0007 names: the anonymous GET passes and the anonymous POST is
	// refused rather than sent to a login, because nobody may POST.
	newNetworkRole(t, ns, "public", "storefront", rule([]string{"*"}, "GET"))
	newNetworkRoleBinding(t, ns, "everyone", "public", gatev1alpha1.SubjectUnauthenticated)
	waitFor(t, "anonymous reads to be allowed", func() bool {
		return fixture.get(t, http.MethodGet, host, "/", "", browserAccept).StatusCode == http.StatusOK
	})
	// The two roles are unioned: the owner may still write, and an
	// anonymous write is offered a login because the owner could do it.
	if got := fixture.get(t, http.MethodPost, host, "/", "github:octocat", browserAccept); got.StatusCode != http.StatusOK {
		t.Errorf("status for the owner writing = %d, want %d", got.StatusCode, http.StatusOK)
	}
	if got := fixture.get(t, http.MethodPost, host, "/", "", browserAccept); got.StatusCode != http.StatusFound {
		t.Errorf("status for an anonymous write = %d, want %d", got.StatusCode, http.StatusFound)
	}

	// Removing the roles removes the protection.
	for _, name := range []string{"owner", "public"} {
		role := &gatev1alpha1.NetworkRole{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
		if err := k8sClient.Delete(context.Background(), role); err != nil {
			t.Fatalf("deleting NetworkRole %s: %v", name, err)
		}
	}
	waitFor(t, "the protection to be lifted", func() bool {
		return fixture.get(t, http.MethodPost, host, "/", "", clientAccept).StatusCode == http.StatusOK
	})
}

// TestNetworkRoleStatusReportsWhatItResolved is what makes the fail-open hole
// visible: a reference that resolves to nothing protects nothing, and nothing
// else in the system says so (ADR 0002).
func TestNetworkRoleStatusReportsWhatItResolved(t *testing.T) {
	ns := newNamespace(t)
	startAuthorization(t, "")

	const host = "authz-status.example.com"
	newProtectedIngress(t, ns, "storefront", host)

	resolved := newNetworkRole(t, ns, "resolved", "storefront", rule([]string{"*"}, "GET"))
	waitFor(t, "the resolved target to be written back", func() bool {
		role := readRole(t, ns, resolved.Name)
		return meta.IsStatusConditionTrue(role.Status.Conditions, gatev1alpha1.ConditionTargetResolved)
	})

	role := readRole(t, ns, resolved.Name)
	if len(role.Status.ResolvedTargets) != 1 {
		t.Fatalf("status.resolvedTargets = %+v, want one target", role.Status.ResolvedTargets)
	}
	target := role.Status.ResolvedTargets[0]
	if target.Namespace != ns || target.Name != "storefront" {
		t.Errorf("resolved target = %s/%s, want %s/storefront", target.Namespace, target.Name, ns)
	}
	// The hosts are what makes the status legible: a person reads the name
	// they typed into the Ingress, not only the name of an object.
	if len(target.Hosts) != 1 || target.Hosts[0] != host {
		t.Errorf("resolved hosts = %v, want [%s]", target.Hosts, host)
	}
	if role.Status.ObservedGeneration != role.Generation {
		t.Errorf("observedGeneration = %d, want %d", role.Status.ObservedGeneration, role.Generation)
	}

	// A reference that names nothing. The Ingress it meant to protect goes
	// on being served to everybody, so the failure has to be loud.
	broken := newNetworkRole(t, ns, "broken", "storefrnot", rule([]string{"*"}, "GET"))
	waitFor(t, "the broken reference to be reported", func() bool {
		role := readRole(t, ns, broken.Name)
		condition := meta.FindStatusCondition(role.Status.Conditions, gatev1alpha1.ConditionTargetResolved)
		return condition != nil && condition.Status == metav1.ConditionFalse
	})
	if got := readRole(t, ns, broken.Name); len(got.Status.ResolvedTargets) != 0 {
		t.Errorf("status.resolvedTargets of a broken reference = %+v, want none", got.Status.ResolvedTargets)
	}
	// The condition is durable and an event is what a person watching the
	// namespace sees go by. Both, because either alone is missable.
	waitFor(t, "an event about the broken reference", func() bool {
		return hasEvent(t, ns, broken.Name, "TargetNotFound")
	})

	// Creating the missing Ingress fixes it without anything touching the
	// role: the resolution follows the target.
	newProtectedIngress(t, ns, "storefrnot", "authz-status-late.example.com")
	waitFor(t, "the late Ingress to resolve the reference", func() bool {
		role := readRole(t, ns, broken.Name)
		return meta.IsStatusConditionTrue(role.Status.Conditions, gatev1alpha1.ConditionTargetResolved)
	})
}

// TestNetworkRoleBindingStatusReportsItsRole is the same requirement for the
// other resource: a binding that grants a role nobody wrote grants nothing.
func TestNetworkRoleBindingStatusReportsItsRole(t *testing.T) {
	ns := newNamespace(t)
	startAuthorization(t, "")

	const host = "authz-binding.example.com"
	newProtectedIngress(t, ns, "storefront", host)

	binding := newNetworkRoleBinding(t, ns, "owners", "owner", "github:octocat")
	waitFor(t, "the missing role to be reported", func() bool {
		got := readBinding(t, ns, binding.Name)
		condition := meta.FindStatusCondition(got.Status.Conditions, gatev1alpha1.ConditionRoleResolved)
		return condition != nil && condition.Status == metav1.ConditionFalse
	})
	waitFor(t, "an event about the missing role", func() bool {
		return hasEvent(t, ns, binding.Name, "RoleNotFound")
	})

	newNetworkRole(t, ns, "owner", "storefront", rule([]string{"*"}, "*"))
	waitFor(t, "the role to resolve the binding", func() bool {
		got := readBinding(t, ns, binding.Name)
		return meta.IsStatusConditionTrue(got.Status.Conditions, gatev1alpha1.ConditionRoleResolved)
	})
	if got := readBinding(t, ns, binding.Name); got.Status.ObservedGeneration != got.Generation {
		t.Errorf("observedGeneration = %d, want %d", got.Status.ObservedGeneration, got.Generation)
	}
}

func readRole(t *testing.T, ns, name string) *gatev1alpha1.NetworkRole {
	t.Helper()
	var role gatev1alpha1.NetworkRole
	if err := k8sClient.Get(context.Background(), keyOf(&gatev1alpha1.NetworkRole{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
	}), &role); err != nil {
		t.Fatalf("reading NetworkRole %s/%s: %v", ns, name, err)
	}
	return &role
}

func readBinding(t *testing.T, ns, name string) *gatev1alpha1.NetworkRoleBinding {
	t.Helper()
	var binding gatev1alpha1.NetworkRoleBinding
	if err := k8sClient.Get(context.Background(), keyOf(&gatev1alpha1.NetworkRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
	}), &binding); err != nil {
		t.Fatalf("reading NetworkRoleBinding %s/%s: %v", ns, name, err)
	}
	return &binding
}

// hasEvent reports whether an event with this reason was recorded against an
// object in the namespace.
func hasEvent(t *testing.T, ns, name, reason string) bool {
	t.Helper()

	var events corev1.EventList
	if err := k8sClient.List(context.Background(), &events, client.InNamespace(ns)); err != nil {
		t.Fatalf("listing events: %v", err)
	}
	for i := range events.Items {
		e := &events.Items[i]
		if e.InvolvedObject.Name == name && e.Reason == reason {
			return true
		}
	}
	return false
}
