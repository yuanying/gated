//go:build envtest

package envtest_test

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/yuanying/gated/internal/controller"
)

// startIngressStatus runs a manager carrying only the status writer.
func startIngressStatus(t *testing.T, services []types.NamespacedName, addresses []string) {
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

	status := &controller.IngressStatusReconciler{
		Client:       mgr.GetClient(),
		Reader:       mgr.GetCache(),
		IngressClass: ingressClass,
		Services:     services,
		Addresses:    addresses,
	}
	if err := status.SetupWithManager(mgr); err != nil {
		t.Fatalf("registering the Ingress status controller: %v", err)
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
}

// newLoadBalancer creates a Service of the kind that carries an external
// address, without a status: in a cluster that is written by whatever
// implements the load balancer, and here by the test.
func newLoadBalancer(t *testing.T, ns, name string) *corev1.Service {
	t.Helper()

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: corev1.ServiceSpec{
			Type:  corev1.ServiceTypeLoadBalancer,
			Ports: []corev1.ServicePort{{Name: "https", Port: 443, TargetPort: intstrFromInt(8443), Protocol: corev1.ProtocolTCP}},
		},
	}
	if err := k8sClient.Create(context.Background(), svc); err != nil {
		t.Fatalf("creating the Service: %v", err)
	}
	t.Cleanup(func() {
		if err := k8sClient.Delete(context.Background(), svc); err != nil {
			t.Logf("deleting the Service: %v", err)
		}
	})
	return svc
}

// publish puts external addresses on a Service, as a load balancer would.
func publish(t *testing.T, svc *corev1.Service, addresses ...string) {
	t.Helper()

	var ingress []corev1.LoadBalancerIngress
	for _, address := range addresses {
		ingress = append(ingress, corev1.LoadBalancerIngress{IP: address})
	}
	svc.Status.LoadBalancer.Ingress = ingress
	if err := k8sClient.Status().Update(context.Background(), svc); err != nil {
		t.Fatalf("writing the Service status: %v", err)
	}
}

// addressesOf reads back what an Ingress says it is reachable at.
func addressesOf(t *testing.T, ns, name string) []string {
	t.Helper()

	var ing networkingv1.Ingress
	if err := k8sClient.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &ing); err != nil {
		t.Fatalf("reading the Ingress: %v", err)
	}
	var out []string
	for _, entry := range ing.Status.LoadBalancer.Ingress {
		if entry.IP != "" {
			out = append(out, entry.IP)
			continue
		}
		out = append(out, entry.Hostname)
	}
	return out
}

func sameAddresses(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// The address a Service is published at is what somebody reading the Ingress
// wants to know, and until this it was either empty or whatever the previous
// controller left behind (ADR 0032).
func TestIngressStatusCarriesTheServiceAddress(t *testing.T) {
	ns := newNamespace(t)
	svc := newLoadBalancer(t, ns, "gated-v4")
	startIngressStatus(t, []types.NamespacedName{{Namespace: ns, Name: "gated-v4"}}, nil)

	ing := newIngress(ns, "app", ingressClass, "status.example.com", "/", "web", 80)
	if err := k8sClient.Create(context.Background(), ing); err != nil {
		t.Fatalf("creating the Ingress: %v", err)
	}
	t.Cleanup(func() {
		if err := k8sClient.Delete(context.Background(), ing); err != nil {
			t.Logf("deleting the Ingress: %v", err)
		}
	})

	// Nothing is written while the Service has no address: writing an
	// empty list would take away whatever the Ingress was carrying and
	// put it back a moment later.
	time.Sleep(500 * time.Millisecond)
	if got := addressesOf(t, ns, "app"); len(got) != 0 {
		t.Fatalf("the status carries %v before the Service has an address, want nothing", got)
	}

	publish(t, svc, "203.0.113.10")
	waitFor(t, "the Service address to reach the Ingress", func() bool {
		return sameAddresses(addressesOf(t, ns, "app"), []string{"203.0.113.10"})
	})

	// A load balancer that changes its mind is followed, which is the
	// reason for watching the Service rather than reading it once.
	publish(t, svc, "203.0.113.20", "203.0.113.11")
	waitFor(t, "the new Service address to reach the Ingress", func() bool {
		// Sorted, so that two replicas and two reconciles do not
		// rewrite the same set in a different order.
		return sameAddresses(addressesOf(t, ns, "app"), []string{"203.0.113.11", "203.0.113.20"})
	})
}

// An Ingress that has moved to another controller keeps what gated wrote.
// Clearing it is indistinguishable from clearing what its new controller has
// just written (ADR 0032).
func TestIngressStatusStaysWhenTheClassMovesAway(t *testing.T) {
	ns := newNamespace(t)
	svc := newLoadBalancer(t, ns, "gated-v4")
	publish(t, svc, "203.0.113.10")
	startIngressStatus(t, []types.NamespacedName{{Namespace: ns, Name: "gated-v4"}}, nil)

	ing := newIngress(ns, "leaving", ingressClass, "leaving.example.com", "/", "web", 80)
	if err := k8sClient.Create(context.Background(), ing); err != nil {
		t.Fatalf("creating the Ingress: %v", err)
	}
	t.Cleanup(func() {
		if err := k8sClient.Delete(context.Background(), ing); err != nil {
			t.Logf("deleting the Ingress: %v", err)
		}
	})
	waitFor(t, "the address to be written", func() bool {
		return sameAddresses(addressesOf(t, ns, "leaving"), []string{"203.0.113.10"})
	})

	var current networkingv1.Ingress
	if err := k8sClient.Get(context.Background(), keyOf(ing), &current); err != nil {
		t.Fatalf("reading the Ingress: %v", err)
	}
	current.Spec.IngressClassName = ptr.To("somebody-else")
	if err := k8sClient.Update(context.Background(), &current); err != nil {
		t.Fatalf("moving the Ingress to another class: %v", err)
	}

	time.Sleep(500 * time.Millisecond)
	if got := addressesOf(t, ns, "leaving"); !sameAddresses(got, []string{"203.0.113.10"}) {
		t.Errorf("the status carries %v after the class moved away, want the address gated wrote left alone", got)
	}
}

// An Ingress gated is not responsible for is never written to in the first
// place: that is the only way not to fight the controller that is.
func TestAnotherControllersIngressIsLeftAlone(t *testing.T) {
	ns := newNamespace(t)
	svc := newLoadBalancer(t, ns, "gated-v4")
	publish(t, svc, "203.0.113.10")
	startIngressStatus(t, []types.NamespacedName{{Namespace: ns, Name: "gated-v4"}}, nil)

	ing := newIngress(ns, "theirs", "somebody-else", "theirs.example.com", "/", "web", 80)
	if err := k8sClient.Create(context.Background(), ing); err != nil {
		t.Fatalf("creating the Ingress: %v", err)
	}
	t.Cleanup(func() {
		if err := k8sClient.Delete(context.Background(), ing); err != nil {
			t.Logf("deleting the Ingress: %v", err)
		}
	})

	time.Sleep(500 * time.Millisecond)
	if got := addressesOf(t, ns, "theirs"); len(got) != 0 {
		t.Errorf("the status of another controller's Ingress carries %v, want nothing", got)
	}
}

// A deployment that is not published through a Service names its addresses
// instead, and one that is published through both gets the two added together.
func TestNamedAddressesAreAddedToTheServiceAddresses(t *testing.T) {
	ns := newNamespace(t)
	svc := newLoadBalancer(t, ns, "gated-v6")
	publish(t, svc, "2001:db8::1")
	startIngressStatus(t, []types.NamespacedName{{Namespace: ns, Name: "gated-v6"}}, []string{"gated.example.com", "203.0.113.10"})

	ing := newIngress(ns, "both", ingressClass, "both.example.com", "/", "web", 80)
	if err := k8sClient.Create(context.Background(), ing); err != nil {
		t.Fatalf("creating the Ingress: %v", err)
	}
	t.Cleanup(func() {
		if err := k8sClient.Delete(context.Background(), ing); err != nil {
			t.Logf("deleting the Ingress: %v", err)
		}
	})

	waitFor(t, "both kinds of address to be written", func() bool {
		return sameAddresses(addressesOf(t, ns, "both"), []string{"2001:db8::1", "203.0.113.10", "gated.example.com"})
	})

	// A hostname goes in as a hostname and an address as an address: the
	// API server validates the two fields differently.
	var current networkingv1.Ingress
	if err := k8sClient.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: "both"}, &current); err != nil {
		t.Fatalf("reading the Ingress: %v", err)
	}
	for _, entry := range current.Status.LoadBalancer.Ingress {
		if entry.IP != "" && entry.Hostname != "" {
			t.Errorf("status entry %v carries both an address and a hostname", entry)
		}
		if entry.Hostname != "" && entry.Hostname != "gated.example.com" {
			t.Errorf("status entry %v names a hostname that was never published", entry)
		}
	}
}
