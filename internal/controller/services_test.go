package controller

import (
	"context"
	"errors"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/yuanying/gated/internal/proxy"
	"github.com/yuanying/gated/internal/routing"
)

// httpPort is the Service port most cases forward to: named, and pointing at a
// target port the Pods may number differently.
var httpPort = corev1.ServicePort{Name: "http", Port: 80, Protocol: corev1.ProtocolTCP}

// endpoint is one address in a slice, with the three conditions as given. A
// nil condition is one the publisher left unset.
func endpoint(addr string, ready, serving, terminating *bool) discoveryv1.Endpoint {
	return discoveryv1.Endpoint{
		Addresses: []string{addr},
		Conditions: discoveryv1.EndpointConditions{
			Ready:       ready,
			Serving:     serving,
			Terminating: terminating,
		},
	}
}

func readyEndpoint(addr string) discoveryv1.Endpoint {
	return endpoint(addr, ptr.To(true), ptr.To(true), ptr.To(false))
}

func unreadyEndpoint(addr string) discoveryv1.Endpoint {
	return endpoint(addr, ptr.To(false), ptr.To(false), ptr.To(false))
}

// terminatingEndpoint is a Pod that has been asked to stop and is still
// answering while it does.
func terminatingEndpoint(addr string) discoveryv1.Endpoint {
	return endpoint(addr, ptr.To(false), ptr.To(true), ptr.To(true))
}

// slice builds an EndpointSlice of one address type carrying one named port.
func slice(name string, family discoveryv1.AddressType, portName string, port int32, eps ...discoveryv1.Endpoint) discoveryv1.EndpointSlice {
	return discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps",
			Name:      name,
			Labels:    map[string]string{discoveryv1.LabelServiceName: "web"},
		},
		AddressType: family,
		Ports: []discoveryv1.EndpointPort{{
			Name:     ptr.To(portName),
			Port:     ptr.To(port),
			Protocol: ptr.To(corev1.ProtocolTCP),
		}},
		Endpoints: eps,
	}
}

var ipv4Only = []corev1.IPFamily{corev1.IPv4Protocol}

func TestCandidatesAreTheReadyEndpoints(t *testing.T) {
	slices := []discoveryv1.EndpointSlice{
		slice("web-1", discoveryv1.AddressTypeIPv4, "http", 8080,
			readyEndpoint("10.0.0.2"),
			unreadyEndpoint("10.0.0.3"),
			readyEndpoint("10.0.0.1"),
			// Terminating while others are ready: not chosen.
			terminatingEndpoint("10.0.0.4"),
		),
	}

	got := candidateEndpoints(slices, httpPort, ipv4Only)
	want := []string{"10.0.0.1:8080", "10.0.0.2:8080"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("candidateEndpoints() = %v, want %v", got, want)
	}
}

// An unset condition is read the way the API says to read it: ready unless
// told otherwise, and serving as ready says.
func TestAnUnsetConditionIsReady(t *testing.T) {
	slices := []discoveryv1.EndpointSlice{
		slice("web-1", discoveryv1.AddressTypeIPv4, "http", 8080,
			endpoint("10.0.0.1", nil, nil, nil),
		),
	}

	got := candidateEndpoints(slices, httpPort, ipv4Only)
	want := []string{"10.0.0.1:8080"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("candidateEndpoints() = %v, want %v", got, want)
	}
}

// When every Pod is on its way out at once, the ones still answering are
// better than none, as kube-proxy has it. One that has stopped answering is
// not.
func TestTerminatingEndpointsStandInWhenNoneIsReady(t *testing.T) {
	slices := []discoveryv1.EndpointSlice{
		slice("web-1", discoveryv1.AddressTypeIPv4, "http", 8080,
			terminatingEndpoint("10.0.0.1"),
			unreadyEndpoint("10.0.0.2"),
			endpoint("10.0.0.3", ptr.To(false), ptr.To(false), ptr.To(true)),
		),
	}

	got := candidateEndpoints(slices, httpPort, ipv4Only)
	want := []string{"10.0.0.1:8080"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("candidateEndpoints() = %v, want %v", got, want)
	}
}

func TestNoCandidateWhenNothingAnswers(t *testing.T) {
	slices := []discoveryv1.EndpointSlice{
		slice("web-1", discoveryv1.AddressTypeIPv4, "http", 8080, unreadyEndpoint("10.0.0.1")),
	}

	if got := candidateEndpoints(slices, httpPort, ipv4Only); len(got) != 0 {
		t.Errorf("candidateEndpoints() = %v, want none", got)
	}
	if got := candidateEndpoints(nil, httpPort, ipv4Only); len(got) != 0 {
		t.Errorf("candidateEndpoints(nil) = %v, want none", got)
	}
}

// A named target port can be a different number on different Pods. The slices
// are split by that number, and each one says what it is under the Service
// port's name.
func TestTheTargetPortIsReadPerSliceByName(t *testing.T) {
	slices := []discoveryv1.EndpointSlice{
		slice("web-1", discoveryv1.AddressTypeIPv4, "http", 8080, readyEndpoint("10.0.0.1")),
		slice("web-2", discoveryv1.AddressTypeIPv4, "http", 9090, readyEndpoint("10.0.0.2")),
		// Another port of the same Service.
		slice("web-3", discoveryv1.AddressTypeIPv4, "metrics", 9100, readyEndpoint("10.0.0.3")),
	}

	got := candidateEndpoints(slices, httpPort, ipv4Only)
	want := []string{"10.0.0.1:8080", "10.0.0.2:9090"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("candidateEndpoints() = %v, want %v", got, want)
	}
}

// A Service with a single port may leave it unnamed, and its slices do too.
func TestAnUnnamedPortMatchesAnUnnamedPort(t *testing.T) {
	slices := []discoveryv1.EndpointSlice{
		slice("web-1", discoveryv1.AddressTypeIPv4, "", 8080, readyEndpoint("10.0.0.1")),
	}

	got := candidateEndpoints(slices, corev1.ServicePort{Port: 80}, ipv4Only)
	want := []string{"10.0.0.1:8080"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("candidateEndpoints() = %v, want %v", got, want)
	}
}

// The address family is the Service's primary one, which is what its cluster
// IP was. A family the Service has not named, and FQDN slices, are not used.
func TestOnlyThePrimaryFamilyIsUsed(t *testing.T) {
	slices := []discoveryv1.EndpointSlice{
		slice("web-v4", discoveryv1.AddressTypeIPv4, "http", 8080, readyEndpoint("10.0.0.1")),
		slice("web-v6", discoveryv1.AddressTypeIPv6, "http", 8080, readyEndpoint("fd00::1")),
		slice("web-fqdn", discoveryv1.AddressTypeFQDN, "http", 8080, readyEndpoint("web.example.com")),
	}

	got := candidateEndpoints(slices, httpPort, []corev1.IPFamily{corev1.IPv6Protocol, corev1.IPv4Protocol})
	want := []string{"[fd00::1]:8080"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("candidateEndpoints() = %v, want %v", got, want)
	}

	got = candidateEndpoints(slices, httpPort, nil)
	want = []string{"10.0.0.1:8080", "[fd00::1]:8080"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("candidateEndpoints() with no family = %v, want %v", got, want)
	}
}

// One endpoint can show up in two slices while they are being rearranged, and
// it is still one endpoint.
func TestAnEndpointInTwoSlicesIsOneCandidate(t *testing.T) {
	slices := []discoveryv1.EndpointSlice{
		slice("web-1", discoveryv1.AddressTypeIPv4, "http", 8080, readyEndpoint("10.0.0.1")),
		slice("web-2", discoveryv1.AddressTypeIPv4, "http", 8080, readyEndpoint("10.0.0.1"), readyEndpoint("10.0.0.2")),
	}

	got := candidateEndpoints(slices, httpPort, ipv4Only)
	want := []string{"10.0.0.1:8080", "10.0.0.2:8080"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("candidateEndpoints() = %v, want %v", got, want)
	}
}

// service builds a Service with a cluster IP and the http port above.
func service() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web"},
		Spec: corev1.ServiceSpec{
			ClusterIP:  "10.96.0.10",
			IPFamilies: ipv4Only,
			Ports:      []corev1.ServicePort{httpPort},
		},
	}
}

func resolverOver(objs ...client.Object) *ServiceResolver {
	reader := fake.NewClientBuilder().WithScheme(clientgoscheme.Scheme).WithObjects(objs...).Build()
	return &ServiceResolver{Reader: reader}
}

func TestResolveForwardsToAReadyEndpoint(t *testing.T) {
	ready := slice("web-1", discoveryv1.AddressTypeIPv4, "http", 8080,
		readyEndpoint("10.0.0.1"),
		unreadyEndpoint("10.0.0.2"),
		readyEndpoint("10.0.0.3"),
	)
	// Somebody else's slice in the same namespace.
	other := slice("db-1", discoveryv1.AddressTypeIPv4, "http", 5432, readyEndpoint("10.0.0.9"))
	other.Labels[discoveryv1.LabelServiceName] = "db"

	r := resolverOver(service(), &ready, &other)

	for _, tc := range []struct {
		pick int
		want string
	}{
		{0, "10.0.0.1:8080"},
		{1, "10.0.0.3:8080"},
	} {
		r.Pick = func(n int) int {
			if n != 2 {
				t.Errorf("asked to pick among %d, want 2", n)
			}
			return tc.pick
		}
		got, err := r.Resolve(context.Background(), routing.Backend{Namespace: "apps", Service: "web", PortName: "http"})
		if err != nil {
			t.Fatalf("Resolve() = _, %v", err)
		}
		if got != tc.want {
			t.Errorf("Resolve() picking %d = %q, want %q", tc.pick, got, tc.want)
		}
	}
}

// Without a Pick of its own, the resolver still only ever answers with a
// ready endpoint.
func TestResolveNeverPicksAnUnreadyEndpoint(t *testing.T) {
	ready := slice("web-1", discoveryv1.AddressTypeIPv4, "http", 8080,
		readyEndpoint("10.0.0.1"),
		unreadyEndpoint("10.0.0.2"),
	)
	r := resolverOver(service(), &ready)

	for range 50 {
		got, err := r.Resolve(context.Background(), routing.Backend{Namespace: "apps", Service: "web", PortNumber: 80})
		if err != nil {
			t.Fatalf("Resolve() = _, %v", err)
		}
		if got != "10.0.0.1:8080" {
			t.Fatalf("Resolve() = %q, want the ready endpoint", got)
		}
	}
}

func TestResolveSaysWhenNothingIsReady(t *testing.T) {
	unready := slice("web-1", discoveryv1.AddressTypeIPv4, "http", 8080, unreadyEndpoint("10.0.0.1"))

	for name, r := range map[string]*ServiceResolver{
		"every endpoint unready": resolverOver(service(), &unready),
		"no EndpointSlice":       resolverOver(service()),
	} {
		_, err := r.Resolve(context.Background(), routing.Backend{Namespace: "apps", Service: "web", PortNumber: 80})
		if !errors.Is(err, proxy.ErrNoReadyEndpoints) {
			t.Errorf("%s: Resolve() = _, %v, want ErrNoReadyEndpoints", name, err)
		}
	}
}

// A backend that names something that is not there is a configuration
// mistake, and must not read as a Service waiting for its Pods.
func TestResolveRefusesAMisconfiguredBackend(t *testing.T) {
	headless := service()
	headless.Name = "headless"
	headless.Spec.ClusterIP = corev1.ClusterIPNone

	external := service()
	external.Name = "external"
	external.Spec.Type = corev1.ServiceTypeExternalName
	external.Spec.ClusterIP = ""
	external.Spec.ExternalName = "example.com"

	r := resolverOver(service(), headless, external)

	for name, backend := range map[string]routing.Backend{
		"missing Service":      {Namespace: "apps", Service: "nothing", PortNumber: 80},
		"headless Service":     {Namespace: "apps", Service: "headless", PortNumber: 80},
		"ExternalName Service": {Namespace: "apps", Service: "external", PortNumber: 80},
		"unknown port number":  {Namespace: "apps", Service: "web", PortNumber: 81},
		"unknown port name":    {Namespace: "apps", Service: "web", PortName: "https"},
	} {
		_, err := r.Resolve(context.Background(), backend)
		if err == nil {
			t.Errorf("%s: Resolve() = _, nil, want an error", name)
			continue
		}
		if errors.Is(err, proxy.ErrNoReadyEndpoints) {
			t.Errorf("%s: Resolve() = _, %v, which reads as nothing being ready", name, err)
		}
	}
}
