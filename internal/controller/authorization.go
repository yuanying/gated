package controller

import (
	"context"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	gatev1alpha1 "github.com/yuanying/gated/internal/apis/gate/v1alpha1"
	"github.com/yuanying/gated/internal/authz"
	"github.com/yuanying/gated/internal/policy"
	"github.com/yuanying/gated/internal/proxy"
)

// rebuildPolicies is the single work item the authorisation controller ever
// queues, for the same reason the routing table has one: the permissions are
// derived from every role, every binding and every Ingress at once, so a burst
// of changes coalesces into one rebuild and rebuilds stay serialised without
// any locking here.
var rebuildPolicies = reconcile.Request{NamespacedName: types.NamespacedName{Name: "authorization-policies"}}

// AuthorizationReconciler keeps the permissions in force in step with the
// cluster.
//
// It only ever reads. Writing back what a role resolved to is a separate
// controller (ADR 0006): every replica has to decide, and only one of them
// should be writing status.
type AuthorizationReconciler struct {
	// Reader lists roles, bindings and Ingresses, from the manager's cache.
	Reader client.Reader
	// Policies receives each rebuilt snapshot.
	Policies *proxy.PolicyStore
}

// Reconcile rebuilds the whole permission set and swaps it in.
//
// The set is rebuilt from scratch on every event, like the routing table and
// for the same reason: a set edited in place has to get removal and renaming
// right, and a mistake there is a permission that outlives the role that
// granted it.
func (r *AuthorizationReconciler) Reconcile(ctx context.Context, _ reconcile.Request) (ctrl.Result, error) {
	var roles gatev1alpha1.NetworkRoleList
	if err := r.Reader.List(ctx, &roles); err != nil {
		return ctrl.Result{}, err
	}
	var bindings gatev1alpha1.NetworkRoleBindingList
	if err := r.Reader.List(ctx, &bindings); err != nil {
		return ctrl.Result{}, err
	}
	var ingresses networkingv1.IngressList
	if err := r.Reader.List(ctx, &ingresses); err != nil {
		return ctrl.Result{}, err
	}

	// Every Ingress is offered for resolution, not only the ones gated
	// routes. A role pointing at somebody else's Ingress grants permissions
	// on traffic that never arrives here, which is harmless; treating it as
	// unresolved would instead report a hole that is not one.
	r.Policies.Store(authz.BuildPolicySet(policy.Build(roles.Items, bindings.Items, ingresses.Items)))

	log := ctrl.LoggerFrom(ctx)
	log.V(1).Info("authorisation policies rebuilt",
		"roles", len(roles.Items), "bindings", len(bindings.Items))
	return ctrl.Result{}, nil
}

// SetupWithManager registers the controller. It runs on every replica: each
// one serves traffic, and a replica that cannot tell a protected resource from
// an unprotected one has no business answering a request (ADR 0006).
func (r *AuthorizationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	rebuild := handler.EnqueueRequestsFromMapFunc(
		func(context.Context, client.Object) []reconcile.Request {
			return []reconcile.Request{rebuildPolicies}
		},
	)
	return ctrl.NewControllerManagedBy(mgr).
		Named("authorization").
		Watches(&gatev1alpha1.NetworkRole{}, rebuild).
		Watches(&gatev1alpha1.NetworkRoleBinding{}, rebuild).
		// An Ingress appearing or going away changes which roles resolve,
		// and so which resources are protected at all.
		Watches(&networkingv1.Ingress{}, rebuild).
		WithOptions(controller.Options{NeedLeaderElection: ptr.To(false)}).
		Complete(r)
}
