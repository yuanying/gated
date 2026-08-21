// Package ingress translates Kubernetes Ingress objects into the neutral form
// the routing table is built from, and decides which of them gated is
// responsible for.
//
// The translation is a pure function over the API types: it reads no cache and
// contacts no server, so the class-selection rules and the shape of the
// conversion are covered by table tests. Keeping it out of internal/routing is
// what lets that package stay free of Kubernetes types (ADR 0007).
package ingress

import (
	networkingv1 "k8s.io/api/networking/v1"

	"github.com/yuanying/gated/internal/routing"
)

// ControllerName is the value an IngressClass must carry in spec.controller
// for gated to recognise the class as its own.
const ControllerName = "gate.unstable.cloud/ingress-controller"

// defaultClassAnnotation marks the IngressClass that claims Ingresses which
// name no class at all. The key is defined by Kubernetes, not by gated.
const defaultClassAnnotation = "ingressclass.kubernetes.io/is-default-class"

// Selected reports whether this process is responsible for an Ingress.
//
// An Ingress that names a class is ours when the name matches the one gated
// was started with. The IngressClass object is not consulted for that case on
// purpose: the flag is the contract, and an Ingress must keep working when
// nobody remembered to create the IngressClass object.
//
// An Ingress that names no class is ours only when the cluster's default class
// is both named after us and driven by us. Claiming class-less Ingresses on
// name alone would let a class somebody else owns hand us their traffic.
func Selected(ing *networkingv1.Ingress, classes []networkingv1.IngressClass, className string) bool {
	if name := ing.Spec.IngressClassName; name != nil {
		return *name != "" && *name == className
	}
	for i := range classes {
		c := &classes[i]
		if c.Name != className || c.Spec.Controller != ControllerName {
			continue
		}
		return c.Annotations[defaultClassAnnotation] == "true"
	}
	return false
}

// Build converts every Ingress this process is responsible for. The result is
// ready to hand to routing.BuildTable.
func Build(ingresses []networkingv1.Ingress, classes []networkingv1.IngressClass, className string) []routing.Ingress {
	out := make([]routing.Ingress, 0, len(ingresses))
	for i := range ingresses {
		if !Selected(&ingresses[i], classes, className) {
			continue
		}
		out = append(out, Convert(&ingresses[i]))
	}
	return out
}

// Convert copies one Ingress into the neutral form, dropping the parts gated
// cannot act on.
//
// Anything dropped is dropped narrowly: a path whose backend names a resource
// rather than a Service disappears, but the paths beside it keep working. A
// rule that declares only a host and no paths is kept, because the host itself
// carries meaning for certificates and for bounding login redirects.
func Convert(ing *networkingv1.Ingress) routing.Ingress {
	out := routing.Ingress{
		Namespace: ing.Namespace,
		Name:      ing.Name,
		CreatedAt: ing.CreationTimestamp.Time,
	}

	if b, ok := convertBackend(ing.Namespace, ing.Spec.DefaultBackend); ok {
		out.DefaultBackend = &b
	}

	for _, rule := range ing.Spec.Rules {
		hostRule := routing.HostRule{Host: rule.Host}
		if rule.HTTP != nil {
			for _, p := range rule.HTTP.Paths {
				backend, ok := convertBackend(ing.Namespace, &p.Backend)
				if !ok {
					continue
				}
				hostRule.Paths = append(hostRule.Paths, routing.PathRule{
					Path:     p.Path,
					PathType: convertPathType(p.PathType),
					Backend:  backend,
				})
			}
		}
		out.Rules = append(out.Rules, hostRule)
	}

	for _, t := range ing.Spec.TLS {
		out.TLS = append(out.TLS, routing.TLSBlock{
			Hosts:      append([]string(nil), t.Hosts...),
			SecretName: t.SecretName,
		})
	}

	return out
}

// convertBackend keeps Service backends and discards everything else.
func convertBackend(namespace string, b *networkingv1.IngressBackend) (routing.Backend, bool) {
	if b == nil || b.Service == nil || b.Service.Name == "" {
		return routing.Backend{}, false
	}
	return routing.Backend{
		Namespace:  namespace,
		Service:    b.Service.Name,
		PortName:   b.Service.Port.Name,
		PortNumber: b.Service.Port.Number,
	}, true
}

// convertPathType maps the API's path types one to one. An absent type is what
// the API server leaves on manifests written before the field existed, and
// means the controller decides.
func convertPathType(t *networkingv1.PathType) routing.PathType {
	if t == nil {
		return routing.PathTypeImplementationSpecific
	}
	switch *t {
	case networkingv1.PathTypeExact:
		return routing.PathTypeExact
	case networkingv1.PathTypePrefix:
		return routing.PathTypePrefix
	default:
		return routing.PathTypeImplementationSpecific
	}
}
