//go:build envtest

package envtest_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"

	"github.com/yuanying/gated/internal/proxy"
)

// podDialer stands one backend in for each endpoint address, so that which
// Pod answered can be read off the response — including when the request went
// over a connection pooled earlier rather than one dialled for it.
type podDialer struct {
	dialRecorder
	pods map[string]string
}

func (d *podDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.wanted = append(d.wanted, addr)
	to, ok := d.pods[addr]
	d.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no Pod stands at %s", addr)
	}
	return (&net.Dialer{}).DialContext(ctx, network, to)
}

// endpointFront runs the proxy in front of one Ingress, with a backend
// answering its own address for each of pods. The returned function sends one
// request and says what answered it.
//
// Every Ingress is in force for the rest of the run: envtest runs no namespace
// controller, so nothing a test creates is ever deleted. Each test here routes
// a host of its own for that reason.
func endpointFront(t *testing.T, ing *networkingv1.Ingress, pods ...string) (*podDialer, func() (int, string)) {
	t.Helper()

	tables, resolver := startRoutingController(t)
	dialer := &podDialer{pods: map[string]string{}}
	for _, pod := range pods {
		dialer.pods[pod] = newBackend(t, pod)
	}
	front := httptest.NewServer(&proxy.Handler{
		Tables:    tables,
		Backends:  resolver,
		Transport: &http.Transport{DialContext: dialer.DialContext},
	})
	t.Cleanup(front.Close)

	if err := k8sClient.Create(context.Background(), ing); err != nil {
		t.Fatalf("creating the Ingress: %v", err)
	}

	get := func() (int, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, front.URL+"/", nil)
		req.Host = ing.Spec.Rules[0].Host
		resp, err := front.Client().Do(req)
		if err != nil {
			t.Fatalf("Do() = %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	waitFor(t, "the Ingress to be routed", func() bool {
		status, _ := get()
		return status != http.StatusNotFound
	})
	return dialer, get
}

// A Pod that is not ready is never sent a request, and one that stops being
// ready stops being sent them as soon as gated hears of it — the pooled
// connection to it included, which is what forwarding to the cluster IP could
// not do (ADR 0033).
func TestOnlyReadyEndpointsAreForwardedTo(t *testing.T) {
	ns := newNamespace(t)
	createService(t, ns, "web", 80, "http")
	es := newEndpointSlice(t, ns, "web", "web-abc", "http", 8080,
		readyAt(endpointIP(1)),
		unreadyAt(endpointIP(2)),
	)
	first := net.JoinHostPort(endpointIP(1), "8080")
	second := net.JoinHostPort(endpointIP(2), "8080")

	dialer, get := endpointFront(t, newIngress(ns, "app", ingressClass, "ready.example.com", "/", "web", 80), first, second)

	for range 20 {
		if status, pod := get(); status != http.StatusOK || pod != first {
			t.Fatalf("answered %d by %q, want %d by the ready endpoint %q", status, pod, http.StatusOK, first)
		}
	}
	for _, addr := range dialer.dialled() {
		if addr != first {
			t.Fatalf("dialled %q, want only the ready endpoint %q", addr, first)
		}
	}

	// The first Pod goes unready and the second becomes ready. The
	// connection already pooled to the first must not carry what follows.
	if err := k8sClient.Get(context.Background(), keyOf(es), es); err != nil {
		t.Fatalf("re-reading the EndpointSlice: %v", err)
	}
	es.Endpoints = []discoveryv1.Endpoint{unreadyAt(endpointIP(1)), readyAt(endpointIP(2))}
	if err := k8sClient.Update(context.Background(), es); err != nil {
		t.Fatalf("updating the EndpointSlice: %v", err)
	}
	waitFor(t, "the second endpoint to answer", func() bool {
		_, pod := get()
		return pod == second
	})

	// From here on the first Pod is out of the picture, although an idle
	// connection to it is still sitting in the pool.
	for range 20 {
		if status, pod := get(); status != http.StatusOK || pod != second {
			t.Fatalf("answered %d by %q after the first went unready, want %d by %q", status, pod, http.StatusOK, second)
		}
	}
}

// An Ingress may name the Service port, and the Service may name its target
// port. Both are resolved: the port by name on the Service, the number from the
// EndpointSlice under that name.
func TestANamedPortIsResolvedThroughTheEndpointSlice(t *testing.T) {
	ns := newNamespace(t)
	createService(t, ns, "web", 80, "http")
	newEndpointSlice(t, ns, "web", "web-abc", "http", 9090, readyAt(endpointIP(1)))

	ing := newIngress(ns, "app", ingressClass, "named-port.example.com", "/", "web", 0)
	ing.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port = networkingv1.ServiceBackendPort{Name: "http"}

	want := net.JoinHostPort(endpointIP(1), "9090")
	dialer, get := endpointFront(t, ing, want)

	if status, pod := get(); status != http.StatusOK || pod != want {
		t.Fatalf("answered %d by %q, want %d by %q", status, pod, http.StatusOK, want)
	}
	if got := dialer.lastAddress(); got != want {
		t.Errorf("dialled %q, want %q", got, want)
	}
}

// A Service with nobody ready behind it is answered 503 without dialling
// anything, and serves again once somebody is.
func TestNoReadyEndpointIsServiceUnavailable(t *testing.T) {
	ns := newNamespace(t)
	createService(t, ns, "web", 80, "http")
	es := newEndpointSlice(t, ns, "web", "web-abc", "http", 8080, unreadyAt(endpointIP(1)))

	pod := net.JoinHostPort(endpointIP(1), "8080")
	dialer, get := endpointFront(t, newIngress(ns, "app", ingressClass, "unavailable.example.com", "/", "web", 80), pod)

	if status, _ := get(); status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", status, http.StatusServiceUnavailable)
	}
	if got := dialer.dialled(); len(got) != 0 {
		t.Errorf("dialled %v with nothing ready, want nothing", got)
	}

	if err := k8sClient.Get(context.Background(), keyOf(es), es); err != nil {
		t.Fatalf("re-reading the EndpointSlice: %v", err)
	}
	es.Endpoints = []discoveryv1.Endpoint{readyAt(endpointIP(1))}
	if err := k8sClient.Update(context.Background(), es); err != nil {
		t.Fatalf("updating the EndpointSlice: %v", err)
	}
	waitFor(t, "the endpoint to be served again", func() bool {
		status, _ := get()
		return status == http.StatusOK
	})
}
