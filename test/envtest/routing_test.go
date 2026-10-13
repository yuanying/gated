//go:build envtest

package envtest_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/yuanying/gated/internal/controller"
	"github.com/yuanying/gated/internal/proxy"
)

// ingressClass is the class the controller under test is responsible for. It
// names gated itself, not any deployment.
const ingressClass = "gated"

// dialRecorder dials one fixed address and remembers what it was asked for.
//
// The routing table, the Service and EndpointSlice lookup and the proxy are all
// the real thing here; only the last hop is redirected, because an endpoint
// address published for a test points at a network that does not exist. What
// the resolver produced is asserted on instead of being thrown away.
type dialRecorder struct {
	to string

	mu     sync.Mutex
	wanted []string
}

func (d *dialRecorder) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.wanted = append(d.wanted, addr)
	d.mu.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, d.to)
}

// dialled returns every address asked for so far, in order.
func (d *dialRecorder) dialled() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.wanted...)
}

func (d *dialRecorder) lastAddress() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.wanted) == 0 {
		return ""
	}
	return d.wanted[len(d.wanted)-1]
}

// startRoutingController runs a manager carrying only the routing controller,
// and returns the table it keeps up to date.
func startRoutingController(t *testing.T) (*proxy.TableStore, *controller.ServiceResolver) {
	t.Helper()

	mgr, err := ctrl.NewManager(restCfg, ctrl.Options{
		Scheme:                 testScheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		LeaderElection:         false,
		// Controller names are registered process-wide so that two of them
		// cannot report the same metric. Each test builds its own manager,
		// so the name repeats here and nowhere else.
		Controller: ctrlconfig.Controller{SkipNameValidation: ptr.To(true)},
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
	return tables, &controller.ServiceResolver{Reader: mgr.GetCache()}
}

// newBackend starts an HTTP server standing in for a pod.
func newBackend(t *testing.T, body string) string {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo-Host", r.Host)
		io.WriteString(w, body)
	}))
	t.Cleanup(s.Close)
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatalf("parsing %q: %v", s.URL, err)
	}
	return u.Host
}

// newService creates a Service with one ready endpoint behind it, and returns
// the address that endpoint is dialled at.
//
// envtest runs no controller-manager, so nothing would publish the
// EndpointSlice a real cluster would; the test does it in its place. Without
// one, every request to the Service is answered 503 (ADR 0033).
func newService(t *testing.T, ns, name string, port int32, portName string) string {
	t.Helper()

	createService(t, ns, name, port, portName)
	newEndpointSlice(t, ns, name, name+"-ready", portName, 8080, readyAt(endpointIP(1)))
	return net.JoinHostPort(endpointIP(1), "8080")
}

// createService creates a Service and nothing behind it.
func createService(t *testing.T, ns, name string, port int32, portName string) {
	t.Helper()

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{
				Name:       portName,
				Port:       port,
				TargetPort: intstrFromInt(8080),
				Protocol:   corev1.ProtocolTCP,
			}},
			Selector: map[string]string{"app": name},
		},
	}
	if err := k8sClient.Create(context.Background(), svc); err != nil {
		t.Fatalf("creating the Service: %v", err)
	}
	if svc.Spec.ClusterIP == "" {
		t.Fatalf("the API server allocated no cluster IP for %s/%s", ns, name)
	}
}

// endpointIP is an address in a range that is never routed anywhere, so that
// only the dial recorder could ever reach it.
func endpointIP(n int) string {
	return fmt.Sprintf("192.0.2.%d", n)
}

// readyAt and unreadyAt describe one Pod as the EndpointSlice controller would.
func readyAt(ip string) discoveryv1.Endpoint {
	return discoveryv1.Endpoint{
		Addresses:  []string{ip},
		Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true), Serving: ptr.To(true), Terminating: ptr.To(false)},
	}
}

func unreadyAt(ip string) discoveryv1.Endpoint {
	return discoveryv1.Endpoint{
		Addresses:  []string{ip},
		Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(false), Serving: ptr.To(false), Terminating: ptr.To(false)},
	}
}

// newEndpointSlice publishes the Pods behind a Service, as the EndpointSlice
// controller would: under the Service port's name, at the target port the
// Pods resolved it to.
func newEndpointSlice(t *testing.T, ns, service, name, portName string, port int32, endpoints ...discoveryv1.Endpoint) *discoveryv1.EndpointSlice {
	t.Helper()

	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
			Labels:    map[string]string{discoveryv1.LabelServiceName: service},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports: []discoveryv1.EndpointPort{{
			Name:     ptr.To(portName),
			Port:     ptr.To(port),
			Protocol: ptr.To(corev1.ProtocolTCP),
		}},
		Endpoints: endpoints,
	}
	if err := k8sClient.Create(context.Background(), es); err != nil {
		t.Fatalf("creating the EndpointSlice: %v", err)
	}
	return es
}

// newIngress builds an Ingress routing one host and path to one Service port.
func newIngress(ns, name, class, host, path, service string, port int32) *networkingv1.Ingress {
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{{
				Host: host,
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{{
							Path:     path,
							PathType: ptr.To(networkingv1.PathTypePrefix),
							Backend: networkingv1.IngressBackend{
								Service: &networkingv1.IngressServiceBackend{
									Name: service,
									Port: networkingv1.ServiceBackendPort{Number: port},
								},
							},
						}},
					},
				},
			}},
		},
	}
	if class != "" {
		ing.Spec.IngressClassName = ptr.To(class)
	}
	return ing
}

func TestIngressChangesReachTheProxy(t *testing.T) {
	ns := newNamespace(t)
	tables, resolver := startRoutingController(t)

	backendAddr := newBackend(t, "from the backend")
	endpointAddr := newService(t, ns, "web", 80, "http")

	dialer := &dialRecorder{to: backendAddr}
	front := httptest.NewServer(&proxy.Handler{
		Tables:    tables,
		Backends:  resolver,
		Transport: &http.Transport{DialContext: dialer.DialContext},
	})
	defer front.Close()

	get := func(host, path string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, front.URL+path, nil)
		if err != nil {
			t.Fatalf("building the request: %v", err)
		}
		req.Host = host
		resp, err := front.Client().Do(req)
		if err != nil {
			t.Fatalf("Do() = %v", err)
		}
		return resp
	}

	// Nothing is routed yet.
	resp := get("app.example.com", "/")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status before any Ingress = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}

	ing := newIngress(ns, "app", ingressClass, "app.example.com", "/shop", "web", 80)
	if err := k8sClient.Create(context.Background(), ing); err != nil {
		t.Fatalf("creating the Ingress: %v", err)
	}

	waitFor(t, "the Ingress to be routed", func() bool {
		resp := get("app.example.com", "/shop/cart")
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})

	resp = get("app.example.com", "/shop/cart")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "from the backend" {
		t.Errorf("body = %q, want %q", body, "from the backend")
	}
	// The Service, its port and its EndpointSlice were resolved for real:
	// the proxy asked to dial the ready endpoint at its target port, not the
	// cluster IP (ADR 0033).
	if got, want := dialer.lastAddress(), endpointAddr; got != want {
		t.Errorf("dialled %q, want %q", got, want)
	}
	if got := resp.Header.Get("X-Echo-Host"); got != "app.example.com" {
		t.Errorf("the backend saw Host %q, want %q", got, "app.example.com")
	}

	// A path the Ingress does not claim is still a 404.
	resp = get("app.example.com", "/admin")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status for an unclaimed path = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}

	// Editing the Ingress moves the route.
	if err := k8sClient.Get(context.Background(), keyOf(ing), ing); err != nil {
		t.Fatalf("re-reading the Ingress: %v", err)
	}
	ing.Spec.Rules[0].HTTP.Paths[0].Path = "/admin"
	if err := k8sClient.Update(context.Background(), ing); err != nil {
		t.Fatalf("updating the Ingress: %v", err)
	}
	waitFor(t, "the moved path to be routed", func() bool {
		resp := get("app.example.com", "/admin")
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
	waitFor(t, "the old path to stop being routed", func() bool {
		resp := get("app.example.com", "/shop")
		resp.Body.Close()
		return resp.StatusCode == http.StatusNotFound
	})

	// Deleting it takes the route with it.
	if err := k8sClient.Delete(context.Background(), ing); err != nil {
		t.Fatalf("deleting the Ingress: %v", err)
	}
	waitFor(t, "the route to disappear", func() bool {
		resp := get("app.example.com", "/admin")
		resp.Body.Close()
		return resp.StatusCode == http.StatusNotFound
	})
}

func TestIngressesOfAnotherClassAreNotRouted(t *testing.T) {
	ns := newNamespace(t)
	tables, resolver := startRoutingController(t)

	backendAddr := newBackend(t, "from the backend")
	newService(t, ns, "web", 80, "http")

	dialer := &dialRecorder{to: backendAddr}
	front := httptest.NewServer(&proxy.Handler{
		Tables:    tables,
		Backends:  resolver,
		Transport: &http.Transport{DialContext: dialer.DialContext},
	})
	defer front.Close()

	// One Ingress for somebody else's controller, one with no class at all
	// and no default IngressClass to claim it.
	for _, ing := range []*networkingv1.Ingress{
		newIngress(ns, "theirs", "another-controller", "theirs.example.com", "/", "web", 80),
		newIngress(ns, "classless", "", "classless.example.com", "/", "web", 80),
		newIngress(ns, "ours", ingressClass, "ours.example.com", "/", "web", 80),
	} {
		if err := k8sClient.Create(context.Background(), ing); err != nil {
			t.Fatalf("creating Ingress %s: %v", ing.Name, err)
		}
	}

	get := func(host string) int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, front.URL+"/", nil)
		req.Host = host
		resp, err := front.Client().Do(req)
		if err != nil {
			t.Fatalf("Do() = %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	waitFor(t, "our Ingress to be routed", func() bool {
		return get("ours.example.com") == http.StatusOK
	})

	// By the time ours is routed the others have been seen too, since one
	// rebuild covers them all.
	for _, host := range []string{"theirs.example.com", "classless.example.com"} {
		if got := get(host); got != http.StatusNotFound {
			t.Errorf("status for %s = %d, want %d", host, got, http.StatusNotFound)
		}
	}
}

func TestTLSTerminationUsesTheSecretTheIngressNames(t *testing.T) {
	ns := newNamespace(t)
	tables, _ := startRoutingController(t)

	cert, pemCert, pemKey := issueSelfSigned(t, "tls.example.com")

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "tls-example"},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{corev1.TLSCertKey: pemCert, corev1.TLSPrivateKeyKey: pemKey},
	}
	if err := k8sClient.Create(context.Background(), secret); err != nil {
		t.Fatalf("creating the Secret: %v", err)
	}

	ing := newIngress(ns, "tls", ingressClass, "tls.example.com", "/", "web", 80)
	ing.Spec.TLS = []networkingv1.IngressTLS{{
		Hosts:      []string{"tls.example.com"},
		SecretName: secret.Name,
	}}
	if err := k8sClient.Create(context.Background(), ing); err != nil {
		t.Fatalf("creating the Ingress: %v", err)
	}

	// The certificates are read straight from the API server here: the
	// manager's cache is restricted to TLS Secrets in the real process, and
	// this test is about the Ingress-to-Secret link, not about caching.
	certificates := &proxy.Certificates{
		Tables: tables,
		Store:  &controller.SecretCertificates{Reader: k8sClient},
	}

	waitFor(t, "the TLS block to be routed", func() bool {
		_, err := certificates.GetCertificate(clientHello("tls.example.com"))
		return err == nil
	})

	got, err := certificates.GetCertificate(clientHello("tls.example.com"))
	if err != nil {
		t.Fatalf("GetCertificate() = _, %v", err)
	}
	if got.Leaf == nil || got.Leaf.Subject.CommonName != cert.Leaf.Subject.CommonName {
		t.Errorf("GetCertificate() returned a certificate for %v, want the one in the Secret", got.Leaf)
	}

	if _, err := certificates.GetCertificate(clientHello("other.example.org")); err == nil {
		t.Error("GetCertificate() for a host with no TLS block = nil error, want a failure")
	}
}

// waitFor polls until the condition holds, and fails the test if it never
// does. Informer propagation has no completion signal to wait on.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
