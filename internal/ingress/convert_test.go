package ingress_test

import (
	"reflect"
	"testing"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/yuanying/gated/internal/ingress"
	"github.com/yuanying/gated/internal/routing"
)

// ourClass is the IngressClass gated is started with in these tests. The name
// is gated's own, not a deployment's, so it is safe to spell out.
const ourClass = "gated"

func classes(specs ...networkingv1.IngressClass) []networkingv1.IngressClass { return specs }

func ingressClass(name, controller string, isDefault bool) networkingv1.IngressClass {
	c := networkingv1.IngressClass{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       networkingv1.IngressClassSpec{Controller: controller},
	}
	if isDefault {
		c.Annotations = map[string]string{"ingressclass.kubernetes.io/is-default-class": "true"}
	}
	return c
}

func minimal(name string, className *string) networkingv1.Ingress {
	return networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: name},
		Spec: networkingv1.IngressSpec{
			IngressClassName: className,
			Rules: []networkingv1.IngressRule{{
				Host: "app.example.com",
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{{
							Path:     "/",
							PathType: ptr.To(networkingv1.PathTypePrefix),
							Backend: networkingv1.IngressBackend{
								Service: &networkingv1.IngressServiceBackend{
									Name: "web",
									Port: networkingv1.ServiceBackendPort{Number: 80},
								},
							},
						}},
					},
				},
			}},
		},
	}
}

func TestSelectsByIngressClassName(t *testing.T) {
	tests := []struct {
		name      string
		className *string
		classes   []networkingv1.IngressClass
		want      bool
	}{
		{
			name:      "our class",
			className: ptr.To(ourClass),
			want:      true,
		},
		{
			name:      "somebody else's class",
			className: ptr.To("other"),
			classes:   classes(ingressClass(ourClass, ingress.ControllerName, false)),
			want:      false,
		},
		{
			name:      "our class without the IngressClass object existing",
			className: ptr.To(ourClass),
			classes:   nil,
			want:      true,
		},
		{
			name:      "no class and no default",
			className: nil,
			classes:   classes(ingressClass(ourClass, ingress.ControllerName, false)),
			want:      false,
		},
		{
			name:      "no class, and ours is the default",
			className: nil,
			classes:   classes(ingressClass(ourClass, ingress.ControllerName, true)),
			want:      true,
		},
		{
			name:      "no class, and somebody else is the default",
			className: nil,
			classes:   classes(ingressClass("other", "example.com/other", true), ingressClass(ourClass, ingress.ControllerName, false)),
			want:      false,
		},
		{
			name:      "no class, and a class with our name belongs to another controller",
			className: nil,
			classes:   classes(ingressClass(ourClass, "example.com/other", true)),
			want:      false,
		},
		{
			name:      "the empty class name is not our class",
			className: ptr.To(""),
			classes:   classes(ingressClass(ourClass, ingress.ControllerName, true)),
			want:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := minimal("app", tc.className)
			if got := ingress.Selected(&in, tc.classes, ourClass); got != tc.want {
				t.Errorf("Selected() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestBuildKeepsOnlyOurIngresses(t *testing.T) {
	ours := minimal("ours", ptr.To(ourClass))
	theirs := minimal("theirs", ptr.To("other"))

	got := ingress.Build([]networkingv1.Ingress{ours, theirs}, nil, ourClass)
	if len(got) != 1 {
		t.Fatalf("Build() returned %d resources, want 1", len(got))
	}
	if got[0].Name != "ours" {
		t.Errorf("Build()[0].Name = %q, want %q", got[0].Name, "ours")
	}
}

func TestConvertCarriesRulesPathsAndTLS(t *testing.T) {
	created := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	in := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "apps",
			Name:              "shop",
			CreationTimestamp: metav1.NewTime(created),
		},
		Spec: networkingv1.IngressSpec{
			DefaultBackend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: "fallback",
					Port: networkingv1.ServiceBackendPort{Name: "http"},
				},
			},
			TLS: []networkingv1.IngressTLS{{
				Hosts:      []string{"app.example.com"},
				SecretName: "app-tls",
			}},
			Rules: []networkingv1.IngressRule{{
				Host: "app.example.com",
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{
								Path:     "/api",
								PathType: ptr.To(networkingv1.PathTypeExact),
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "api",
										Port: networkingv1.ServiceBackendPort{Number: 8080},
									},
								},
							},
							{
								// A missing pathType is what the API server
								// leaves behind for manifests written before
								// the field existed.
								Path: "/legacy",
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "legacy",
										Port: networkingv1.ServiceBackendPort{Name: "web"},
									},
								},
							},
						},
					},
				},
			}},
		},
	}

	want := routing.Ingress{
		Namespace: "apps",
		Name:      "shop",
		CreatedAt: created,
		Rules: []routing.HostRule{{
			Host: "app.example.com",
			Paths: []routing.PathRule{
				{
					Path:     "/api",
					PathType: routing.PathTypeExact,
					Backend:  routing.Backend{Namespace: "apps", Service: "api", PortNumber: 8080},
				},
				{
					Path:     "/legacy",
					PathType: routing.PathTypeImplementationSpecific,
					Backend:  routing.Backend{Namespace: "apps", Service: "legacy", PortName: "web"},
				},
			},
		}},
		DefaultBackend: &routing.Backend{Namespace: "apps", Service: "fallback", PortName: "http"},
		TLS:            []routing.TLSBlock{{Hosts: []string{"app.example.com"}, SecretName: "app-tls"}},
	}

	got := ingress.Convert(&in)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Convert() = %#v\nwant %#v", got, want)
	}
}

func TestConvertDropsBackendsItCannotResolve(t *testing.T) {
	// A resource backend points at something gated has no way to forward to.
	// Dropping the path leaves the rest of the resource working.
	in := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "app"},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{{
				Host: "app.example.com",
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{
								Path:     "/static",
								PathType: ptr.To(networkingv1.PathTypePrefix),
								Backend: networkingv1.IngressBackend{
									Resource: &corev1TypedRef,
								},
							},
							{
								Path:     "/",
								PathType: ptr.To(networkingv1.PathTypePrefix),
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "web",
										Port: networkingv1.ServiceBackendPort{Number: 80},
									},
								},
							},
						},
					},
				},
			}},
			DefaultBackend: &networkingv1.IngressBackend{Resource: &corev1TypedRef},
		},
	}

	got := ingress.Convert(&in)
	if got.DefaultBackend != nil {
		t.Errorf("Convert().DefaultBackend = %+v, want nil", got.DefaultBackend)
	}
	if len(got.Rules) != 1 || len(got.Rules[0].Paths) != 1 {
		t.Fatalf("Convert().Rules = %#v, want one host with one path", got.Rules)
	}
	if got.Rules[0].Paths[0].Backend.Service != "web" {
		t.Errorf("surviving backend = %q, want %q", got.Rules[0].Paths[0].Backend.Service, "web")
	}
}

func TestConvertKeepsHostsThatDeclareNoPaths(t *testing.T) {
	// A rule with no HTTP block still declares the host, which matters for
	// the certificate lookup and for bounding login redirects.
	in := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "app"},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{{Host: "app.example.com"}},
		},
	}

	got := ingress.Convert(&in)
	if len(got.Rules) != 1 || got.Rules[0].Host != "app.example.com" {
		t.Fatalf("Convert().Rules = %#v, want the host preserved", got.Rules)
	}
	if len(got.Rules[0].Paths) != 0 {
		t.Errorf("Convert().Rules[0].Paths = %#v, want none", got.Rules[0].Paths)
	}
}

func TestBuildFeedsTheTable(t *testing.T) {
	// The two packages meet here: whatever Build produces has to be routable
	// without further massaging.
	in := minimal("app", ptr.To(ourClass))
	table := routing.BuildTable(ingress.Build([]networkingv1.Ingress{in}, nil, ourClass))

	got, ok := table.Match("app.example.com", "/anything")
	if !ok {
		t.Fatal("Match() = _, false, want a match")
	}
	want := routing.Backend{Namespace: "apps", Service: "web", PortNumber: 80}
	if got.Backend != want {
		t.Errorf("Match().Backend = %+v, want %+v", got.Backend, want)
	}
}
