package controller

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	gatev1alpha1 "github.com/yuanying/gated/internal/apis/gate/v1alpha1"
	"github.com/yuanying/gated/internal/ingress"
	"github.com/yuanying/gated/internal/policy"
)

// reasonRefusedByDefault is the reason of the event recorded on an Ingress that
// is refused only because its namespace fails closed and no role names it.
const reasonRefusedByDefault = "RefusedByDefault"

// FailClosedReconciler tells whoever wrote an Ingress in a namespace that
// fails closed that nothing protects it, and so that nobody can reach it
// (ADR 0041).
//
// The refusal itself is every replica's: it is part of the permission
// snapshot. What is written here is the same on all of them, so it is the
// leader's alone, like the status of the roles (ADR 0006). It writes an event
// rather than a condition because an Ingress has nowhere to hold one, and the
// event is recorded in the Ingress's own namespace, which is where its author
// looks.
type FailClosedReconciler struct {
	// Reader reads Ingresses, IngressClasses, namespaces and roles, from
	// the manager's cache.
	Reader client.Reader
	// IngressClass is the class this process is responsible for. An
	// Ingress of another class is not served here, so it is not refused
	// here either.
	IngressClass string
	// Recorder reports the refusal. Required.
	Recorder record.EventRecorder
	// Log records what was reported. The zero Logger discards.
	Log logr.Logger
}

// Reconcile reports one Ingress, if it is refused by default.
func (r *FailClosedReconciler) Reconcile(ctx context.Context, req reconcile.Request) (ctrl.Result, error) {
	var ing networkingv1.Ingress
	if err := r.Reader.Get(ctx, req.NamespacedName, &ing); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	var ns corev1.Namespace
	if err := r.Reader.Get(ctx, client.ObjectKey{Name: ing.Namespace}, &ns); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if !policy.FailsClosed(&ns) {
		return ctrl.Result{}, nil
	}

	var classes networkingv1.IngressClassList
	if err := r.Reader.List(ctx, &classes); err != nil {
		return ctrl.Result{}, err
	}
	if !ingress.Selected(&ing, classes.Items, r.IngressClass) {
		return ctrl.Result{}, nil
	}

	var roles gatev1alpha1.NetworkRoleList
	if err := r.Reader.List(ctx, &roles); err != nil {
		return ctrl.Result{}, err
	}
	if policy.NamesTarget(roles.Items, req.NamespacedName) {
		return ctrl.Result{}, nil
	}

	// The wording says what happens, not only what is missing, the way
	// an unresolved role is reported (ADR 0017).
	r.Recorder.Event(&ing, corev1.EventTypeWarning, reasonRefusedByDefault, fmt.Sprintf(
		"namespace %s is labelled %s=%s and no NetworkRole names this Ingress, so every request to it is refused",
		ing.Namespace, gatev1alpha1.LabelFailClosed, gatev1alpha1.LabelFailClosedValue))
	r.Log.V(1).Info("an Ingress is refused by default", "ingress", req.NamespacedName)
	return ctrl.Result{}, nil
}

// SetupWithManager registers the controller. It is explicitly leader elected,
// which ADR 0016 asks to be stated rather than inherited.
func (r *FailClosedReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// A namespace gaining the label affects every Ingress in it.
	byNamespace := handler.EnqueueRequestsFromMapFunc(
		func(ctx context.Context, obj client.Object) []reconcile.Request {
			var ingresses networkingv1.IngressList
			if err := r.Reader.List(ctx, &ingresses, client.InNamespace(obj.GetName())); err != nil {
				r.Log.Error(err, "listing the Ingresses of a namespace", "namespace", obj.GetName())
				return nil
			}
			out := make([]reconcile.Request, 0, len(ingresses.Items))
			for i := range ingresses.Items {
				out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&ingresses.Items[i])})
			}
			return out
		},
	)
	// A role going away can leave its target with nothing naming it.
	byRole := handler.EnqueueRequestsFromMapFunc(
		func(_ context.Context, obj client.Object) []reconcile.Request {
			role, ok := obj.(*gatev1alpha1.NetworkRole)
			if !ok {
				return nil
			}
			key, resolvable := policy.TargetKey(role)
			if !resolvable {
				return nil
			}
			return []reconcile.Request{{NamespacedName: key}}
		},
	)
	return ctrl.NewControllerManagedBy(mgr).
		Named("fail-closed").
		For(&networkingv1.Ingress{}).
		Watches(&corev1.Namespace{}, byNamespace).
		Watches(&gatev1alpha1.NetworkRole{}, byRole).
		WithOptions(controller.Options{NeedLeaderElection: ptr.To(true)}).
		Complete(r)
}
