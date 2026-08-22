package controller

import (
	"context"
	"fmt"
	"net"
	"slices"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/yuanying/gated/internal/ingress"
)

// IngressStatusReconciler writes the addresses gated is reachable at into the
// status of the Ingresses it is responsible for (ADR 0032).
//
// gated cannot work out those addresses for itself — it does not know which
// Service, if any, publishes it — so they are named at startup. Naming none
// leaves every status alone, and is how a deployment says it does not want
// them written.
type IngressStatusReconciler struct {
	// Client writes status. Required.
	Client client.Client
	// Reader reads Ingresses, IngressClasses and the published Services,
	// from the manager's cache.
	Reader client.Reader
	// IngressClass is the class this process is responsible for. What is
	// written to is exactly what is routed and issued for: writing to
	// anything else is how two controllers end up overwriting each other.
	IngressClass string
	// Services are read for the addresses their own load balancer status
	// carries.
	Services []types.NamespacedName
	// Addresses are written as they stand, and added to whatever the
	// Services resolve to.
	Addresses []string
	// Log records what was written. The zero Logger discards.
	Log logr.Logger
}

// Reconcile brings the status of one Ingress up to date.
func (r *IngressStatusReconciler) Reconcile(ctx context.Context, req reconcile.Request) (ctrl.Result, error) {
	var ing networkingv1.Ingress
	if err := r.Reader.Get(ctx, req.NamespacedName, &ing); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	var classes networkingv1.IngressClassList
	if err := r.Reader.List(ctx, &classes); err != nil {
		return ctrl.Result{}, err
	}
	if !ingress.Selected(&ing, classes.Items, r.IngressClass) {
		// Not ours, so not ours to write — and not ours to clear
		// either. An Ingress that has just left this class is being
		// looked after by somebody else now, and there is no way to
		// remove only what gated put there.
		return ctrl.Result{}, nil
	}

	addresses, err := r.published(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}
	if len(addresses) == 0 {
		// A Service that has not been given an address yet is the
		// ordinary state of the first seconds after a start. Writing
		// an empty list would take away whatever the Ingress carries —
		// including the address of the controller gated took over from
		// — and put it back a moment later.
		return ctrl.Result{}, nil
	}
	if apiequality.Semantic.DeepEqual(ing.Status.LoadBalancer.Ingress, addresses) {
		return ctrl.Result{}, nil
	}

	ing.Status.LoadBalancer.Ingress = addresses
	if err := r.Client.Status().Update(ctx, &ing); err != nil {
		return ctrl.Result{}, fmt.Errorf("writing the status of Ingress %s: %w", req.NamespacedName, err)
	}
	r.Log.V(1).Info("wrote the address of an Ingress", "ingress", req.NamespacedName, "addresses", addresses)
	return ctrl.Result{}, nil
}

// published is every address gated is reachable at, in a stable order.
//
// The order matters because the result is compared against what is already
// written: two orderings of the same set would be an update each time round,
// forever.
func (r *IngressStatusReconciler) published(ctx context.Context) ([]networkingv1.IngressLoadBalancerIngress, error) {
	seen := map[string]bool{}
	var addresses []string

	add := func(address string) {
		if address == "" || seen[address] {
			return
		}
		seen[address] = true
		addresses = append(addresses, address)
	}

	for _, ref := range r.Services {
		var svc corev1.Service
		if err := r.Reader.Get(ctx, ref, &svc); err != nil {
			if apierrors.IsNotFound(err) {
				// Named but not there. Saying so once a
				// reconcile would be a line per Ingress; the
				// Service appearing brings everything back
				// here anyway.
				r.Log.V(1).Info("a published Service does not exist", "service", ref)
				continue
			}
			return nil, fmt.Errorf("reading Service %s: %w", ref, err)
		}
		for _, entry := range svc.Status.LoadBalancer.Ingress {
			// An entry carries an address or a name, and gated
			// passes on whichever it was given.
			if entry.IP != "" {
				add(entry.IP)
				continue
			}
			add(entry.Hostname)
		}
	}
	for _, address := range r.Addresses {
		add(address)
	}

	slices.Sort(addresses)
	out := make([]networkingv1.IngressLoadBalancerIngress, 0, len(addresses))
	for _, address := range addresses {
		// The two fields are validated differently by the API server,
		// so which one an address goes in is not a free choice.
		if net.ParseIP(address) != nil {
			out = append(out, networkingv1.IngressLoadBalancerIngress{IP: address})
			continue
		}
		out = append(out, networkingv1.IngressLoadBalancerIngress{Hostname: address})
	}
	return out, nil
}

// SetupWithManager registers the controller.
//
// It is explicitly leader elected. Every replica would write the same thing,
// so letting them all write it multiplies the updates by the number of
// replicas and tells the reader nothing new (ADR 0006, ADR 0016).
func (r *IngressStatusReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("ingress-status").
		For(&networkingv1.Ingress{}).
		// The address of a load balancer arrives after the Service is
		// created and can change afterwards, so it is watched rather
		// than read once.
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(r.ingressesWhenPublished)).
		// A class becoming, or ceasing to be, the cluster default
		// changes which Ingresses are ours.
		Watches(&networkingv1.IngressClass{}, handler.EnqueueRequestsFromMapFunc(r.everyIngress)).
		WithOptions(controller.Options{NeedLeaderElection: ptr.To(true)}).
		Complete(r)
}

// ingressesWhenPublished enqueues every Ingress when one of the Services gated
// is published through changes, and nothing otherwise.
func (r *IngressStatusReconciler) ingressesWhenPublished(ctx context.Context, obj client.Object) []reconcile.Request {
	changed := types.NamespacedName{Namespace: obj.GetNamespace(), Name: obj.GetName()}
	if !slices.Contains(r.Services, changed) {
		return nil
	}
	return r.everyIngress(ctx, obj)
}

// everyIngress enqueues them all, because the answer is the same for all of
// them and a change to it changes all of them.
func (r *IngressStatusReconciler) everyIngress(ctx context.Context, _ client.Object) []reconcile.Request {
	var list networkingv1.IngressList
	if err := r.Reader.List(ctx, &list); err != nil {
		return nil
	}
	out := make([]reconcile.Request, 0, len(list.Items))
	for i := range list.Items {
		out = append(out, requestFor(&list.Items[i]))
	}
	return out
}
