// Package controller holds the controller-runtime reconcilers that keep the
// data plane in step with the cluster, and the cache-backed lookups the data
// plane needs while serving a request.
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

	"github.com/yuanying/gated/internal/ingress"
	"github.com/yuanying/gated/internal/proxy"
	"github.com/yuanying/gated/internal/routing"
)

// rebuildRequest is the single work item the routing controller ever queues.
//
// The table is derived from every Ingress at once, so there is nothing useful
// to do per object. Collapsing every event onto one key lets the work queue
// coalesce a burst of changes into a single rebuild, and keeps rebuilds
// serialised without any locking of our own.
var rebuildRequest = reconcile.Request{NamespacedName: types.NamespacedName{Name: "routing-table"}}

// RoutingReconciler keeps the routing table in step with the cluster.
type RoutingReconciler struct {
	// Reader lists Ingresses and IngressClasses, from the manager's cache.
	Reader client.Reader
	// IngressClass is the class this process is responsible for.
	IngressClass string
	// Tables receives each rebuilt snapshot.
	Tables *proxy.TableStore
}

// Reconcile rebuilds the whole table and swaps it in.
//
// Rebuilding everything on every event is deliberate. The alternative — a
// table edited in place as objects come and go — has to get removal, renaming
// and partial failure right, and a mistake there is a route that outlives the
// Ingress that created it. A cluster's worth of Ingresses is small enough that
// rebuilding costs nothing next to that risk.
func (r *RoutingReconciler) Reconcile(ctx context.Context, _ reconcile.Request) (ctrl.Result, error) {
	var ingresses networkingv1.IngressList
	if err := r.Reader.List(ctx, &ingresses); err != nil {
		return ctrl.Result{}, err
	}
	var classes networkingv1.IngressClassList
	if err := r.Reader.List(ctx, &classes); err != nil {
		return ctrl.Result{}, err
	}

	selected := ingress.Build(ingresses.Items, classes.Items, r.IngressClass)
	table := routing.BuildTable(selected)
	r.Tables.Store(table)

	log := ctrl.LoggerFrom(ctx)
	log.V(1).Info("routing table rebuilt", "ingresses", len(selected), "hosts", len(table.Hosts()))
	return ctrl.Result{}, nil
}

// SetupWithManager registers the controller. It runs on every replica, not
// only the leader: each one serves traffic and so each one needs the table
// (ADR 0006).
//
// Saying so is not optional. A controller that expresses no opinion is leader
// elected, which is controller-runtime's default, and a replica that never
// wins the lease would then never build a table and answer 404 to everything
// it is handed.
func (r *RoutingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	rebuild := handler.EnqueueRequestsFromMapFunc(
		func(context.Context, client.Object) []reconcile.Request {
			return []reconcile.Request{rebuildRequest}
		},
	)
	return ctrl.NewControllerManagedBy(mgr).
		Named("routing").
		Watches(&networkingv1.Ingress{}, rebuild).
		Watches(&networkingv1.IngressClass{}, rebuild).
		// A cluster with no Ingress in it produces no watch event at
		// all, and a table that was never built is not the same thing
		// as one that is empty.
		WatchesRawSource(startupSource{request: rebuildRequest}).
		WithOptions(controller.Options{NeedLeaderElection: ptr.To(false)}).
		Complete(r)
}
