package controller

import (
	"context"
	"fmt"
	"net"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/yuanying/gated/internal/routing"
)

// ServiceResolver turns a routed backend into the address to dial.
//
// It resolves to the Service's cluster IP and stops there: kube-proxy already
// balances across ready endpoints, and doing it again here would mean tracking
// EndpointSlices, readiness and topology to arrive at the same answer (ADR
// 0001).
type ServiceResolver struct {
	// Reader reads Services, from the manager's cache.
	Reader client.Reader
}

// Resolve returns "clusterIP:port" for a backend.
func (r *ServiceResolver) Resolve(ctx context.Context, backend routing.Backend) (string, error) {
	var svc corev1.Service
	key := types.NamespacedName{Namespace: backend.Namespace, Name: backend.Service}
	if err := r.Reader.Get(ctx, key, &svc); err != nil {
		return "", fmt.Errorf("reading Service %s: %w", key, err)
	}

	// A headless Service has no address to forward to, and an ExternalName
	// Service is a DNS alias rather than a destination. Both are a
	// configuration mistake here, not a transient failure.
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == corev1.ClusterIPNone {
		return "", fmt.Errorf("Service %s has no cluster IP", key)
	}

	port, err := servicePort(&svc, backend)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(svc.Spec.ClusterIP, strconv.Itoa(int(port))), nil
}

// servicePort finds the port the backend names, by name or by number.
func servicePort(svc *corev1.Service, backend routing.Backend) (int32, error) {
	for _, p := range svc.Spec.Ports {
		if backend.PortName != "" {
			if p.Name == backend.PortName {
				return p.Port, nil
			}
			continue
		}
		if p.Port == backend.PortNumber {
			return p.Port, nil
		}
	}
	if backend.PortName != "" {
		return 0, fmt.Errorf("Service %s/%s has no port named %q", svc.Namespace, svc.Name, backend.PortName)
	}
	return 0, fmt.Errorf("Service %s/%s does not expose port %d", svc.Namespace, svc.Name, backend.PortNumber)
}
