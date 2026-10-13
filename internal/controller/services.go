package controller

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"slices"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/yuanying/gated/internal/proxy"
	"github.com/yuanying/gated/internal/routing"
)

// ServiceResolver turns a routed backend into the address to dial.
//
// It resolves to one ready endpoint of the Service, read from its
// EndpointSlices, and not to the cluster IP (ADR 0033). A pooled connection to
// a cluster IP stays pinned to the Pod kube-proxy picked when it was opened,
// and goes on carrying requests after that Pod stops being ready. Choosing the
// endpoint here, per request, keys the pool by Pod instead.
type ServiceResolver struct {
	// Reader reads Services and EndpointSlices, from the manager's cache.
	Reader client.Reader
	// Pick chooses one of n candidates. A nil Pick chooses uniformly at
	// random, which needs no state per backend and evens out over many
	// requests.
	Pick func(n int) int
}

// Resolve returns "endpointIP:targetPort" for a backend, or an error wrapping
// proxy.ErrNoReadyEndpoints when the Service is there but nothing behind it can
// take a request.
func (r *ServiceResolver) Resolve(ctx context.Context, backend routing.Backend) (string, error) {
	var svc corev1.Service
	key := types.NamespacedName{Namespace: backend.Namespace, Name: backend.Service}
	if err := r.Reader.Get(ctx, key, &svc); err != nil {
		return "", fmt.Errorf("reading Service %s: %w", key, err)
	}

	// A headless Service has chosen to go without a virtual address, and an
	// ExternalName Service is a DNS alias rather than a destination. Both
	// are a configuration mistake here, not a transient failure.
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == corev1.ClusterIPNone {
		return "", fmt.Errorf("Service %s has no cluster IP", key)
	}

	port, err := servicePort(&svc, backend)
	if err != nil {
		return "", err
	}

	var endpoints discoveryv1.EndpointSliceList
	if err := r.Reader.List(ctx, &endpoints,
		client.InNamespace(backend.Namespace),
		client.MatchingLabels{discoveryv1.LabelServiceName: backend.Service},
	); err != nil {
		return "", fmt.Errorf("reading the EndpointSlices of Service %s: %w", key, err)
	}

	candidates := candidateEndpoints(endpoints.Items, port, svc.Spec.IPFamilies)
	if len(candidates) == 0 {
		return "", fmt.Errorf("Service %s port %d: %w", key, port.Port, proxy.ErrNoReadyEndpoints)
	}
	return candidates[r.pick(len(candidates))], nil
}

func (r *ServiceResolver) pick(n int) int {
	if r.Pick != nil {
		return r.Pick(n)
	}
	return rand.IntN(n)
}

// servicePort finds the port the backend names, by name or by number.
func servicePort(svc *corev1.Service, backend routing.Backend) (corev1.ServicePort, error) {
	for _, p := range svc.Spec.Ports {
		if backend.PortName != "" {
			if p.Name == backend.PortName {
				return p, nil
			}
			continue
		}
		if p.Port == backend.PortNumber {
			return p, nil
		}
	}
	if backend.PortName != "" {
		return corev1.ServicePort{}, fmt.Errorf("Service %s/%s has no port named %q", svc.Namespace, svc.Name, backend.PortName)
	}
	return corev1.ServicePort{}, fmt.Errorf("Service %s/%s does not expose port %d", svc.Namespace, svc.Name, backend.PortNumber)
}

// candidateEndpoints lists the addresses a request for the Service port may be
// sent to, sorted and without repeats.
//
// It follows kube-proxy (ADR 0033): the ready endpoints, or, only when there is
// none, the ones that are terminating and still serving. Only slices of the
// Service's primary address family are read, which is the family its cluster
// IP was; with no family given, either IP family will do.
//
// The target port is read per slice, under the Service port's name. A named
// target port can be a different number on different Pods, and the slices are
// split by that number.
func candidateEndpoints(endpointSlices []discoveryv1.EndpointSlice, port corev1.ServicePort, families []corev1.IPFamily) []string {
	var ready, terminating []string
	for i := range endpointSlices {
		es := &endpointSlices[i]
		if !usableFamily(es.AddressType, families) {
			continue
		}
		target, ok := targetPort(es, port)
		if !ok {
			continue
		}
		for _, ep := range es.Endpoints {
			// The API says the first address is the one to use.
			if len(ep.Addresses) == 0 {
				continue
			}
			addr := net.JoinHostPort(ep.Addresses[0], strconv.Itoa(int(target)))
			switch c := ep.Conditions; {
			case isReady(c):
				ready = append(ready, addr)
			case isServing(c) && c.Terminating != nil && *c.Terminating:
				terminating = append(terminating, addr)
			}
		}
	}

	candidates := ready
	if len(candidates) == 0 {
		candidates = terminating
	}
	slices.Sort(candidates)
	return slices.Compact(candidates)
}

// isReady reads an unset condition as ready, as the API asks consumers to.
func isReady(c discoveryv1.EndpointConditions) bool {
	return c.Ready == nil || *c.Ready
}

// isServing reads an unset condition as whatever ready says.
func isServing(c discoveryv1.EndpointConditions) bool {
	if c.Serving == nil {
		return isReady(c)
	}
	return *c.Serving
}

func usableFamily(addressType discoveryv1.AddressType, families []corev1.IPFamily) bool {
	if len(families) == 0 {
		return addressType == discoveryv1.AddressTypeIPv4 || addressType == discoveryv1.AddressTypeIPv6
	}
	switch families[0] {
	case corev1.IPv4Protocol:
		return addressType == discoveryv1.AddressTypeIPv4
	case corev1.IPv6Protocol:
		return addressType == discoveryv1.AddressTypeIPv6
	default:
		return false
	}
}

// targetPort finds the number a slice gives the Service port, by its name. An
// unnamed Service port matches an unnamed slice port.
func targetPort(es *discoveryv1.EndpointSlice, port corev1.ServicePort) (int32, bool) {
	for _, p := range es.Ports {
		if p.Port == nil || ptr.Deref(p.Name, "") != port.Name {
			continue
		}
		if protocolOf(p.Protocol) != protocolOf(&port.Protocol) {
			continue
		}
		return *p.Port, true
	}
	return 0, false
}

// protocolOf reads an unset protocol as TCP, as both the Service and the
// EndpointSlice APIs default it.
func protocolOf(p *corev1.Protocol) corev1.Protocol {
	if p == nil || *p == "" {
		return corev1.ProtocolTCP
	}
	return *p
}
