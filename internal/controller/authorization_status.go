package controller

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	gatev1alpha1 "github.com/yuanying/gated/internal/apis/gate/v1alpha1"
	"github.com/yuanying/gated/internal/policy"
)

// Reasons written into the conditions and the events of the two authorisation
// resources.
//
// The failing ones matter more than the succeeding ones. A reference that does
// not resolve leaves the resource it meant to protect served to everybody
// (ADR 0002), and nothing else in the system reports that: the request
// succeeds, the proxy logs an ordinary 200, and the person who wrote the role
// believes it is in force.
const (
	reasonTargetFound     = "TargetFound"
	reasonTargetNotFound  = "TargetNotFound"
	reasonTargetNotUsable = "TargetKindNotSupported"
	reasonRoleFound       = "RoleFound"
	reasonRoleNotFound    = "RoleNotFound"
)

// NetworkRoleReconciler writes back what a role's targetRef resolved to.
//
// It is the leader's job alone. Every replica decides, but the answer written
// here is the same on all of them, so having each replica write it multiplies
// the writes and the events by the number of replicas without adding anything
// (ADR 0006).
type NetworkRoleReconciler struct {
	// Client writes status. Required.
	Client client.Client
	// Reader reads roles and Ingresses, from the manager's cache.
	Reader client.Reader
	// Recorder reports a reference that resolves to nothing. Required.
	Recorder record.EventRecorder
	// Metrics receives whether the target resolved (ADR 0031). A nil
	// Metrics reports nothing.
	Metrics *Metrics
	// Log records the decisions. The zero Logger discards.
	Log logr.Logger
}

// Reconcile resolves one role's target and records the outcome.
func (r *NetworkRoleReconciler) Reconcile(ctx context.Context, req reconcile.Request) (ctrl.Result, error) {
	var role gatev1alpha1.NetworkRole
	if err := r.Reader.Get(ctx, req.NamespacedName, &role); err != nil {
		if apierrors.IsNotFound(err) {
			// A role that no longer exists is not an unresolved one.
			r.Metrics.ForgetNetworkRole(req.Namespace, req.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// The conditions are copied, not aliased: SetStatusCondition edits the
	// slice in place, and editing the one the object already holds would
	// make the comparison below find no change and never write.
	status := gatev1alpha1.NetworkRoleStatus{
		ObservedGeneration: role.Generation,
		Conditions:         append([]metav1.Condition(nil), role.Status.Conditions...),
	}
	condition := metav1.Condition{
		Type:               gatev1alpha1.ConditionTargetResolved,
		ObservedGeneration: role.Generation,
	}

	key, resolvable := policy.TargetKey(&role)
	switch {
	case !resolvable:
		condition.Status = metav1.ConditionFalse
		condition.Reason = reasonTargetNotUsable
		condition.Message = fmt.Sprintf(
			"spec.targetRef names %s/%s, which gated cannot resolve; nothing is protected by this role",
			role.Spec.TargetRef.Group, role.Spec.TargetRef.Kind)
		r.Recorder.Event(&role, corev1.EventTypeWarning, reasonTargetNotUsable, condition.Message)
	default:
		var ing networkingv1.Ingress
		err := r.Reader.Get(ctx, key, &ing)
		switch {
		case apierrors.IsNotFound(err):
			condition.Status = metav1.ConditionFalse
			condition.Reason = reasonTargetNotFound
			// The wording says what the consequence is, not just
			// what was not found: the whole point of the condition
			// is that the consequence is otherwise invisible.
			condition.Message = fmt.Sprintf(
				"Ingress %s does not exist, so this role protects nothing and that Ingress is served without authentication",
				key)
			r.Recorder.Event(&role, corev1.EventTypeWarning, reasonTargetNotFound, condition.Message)
		case err != nil:
			return ctrl.Result{}, err
		default:
			hosts := policy.Hosts(&ing)
			status.ResolvedTargets = []gatev1alpha1.ResolvedTarget{{
				Namespace: ing.Namespace,
				Name:      ing.Name,
				Hosts:     hosts,
			}}
			condition.Status = metav1.ConditionTrue
			condition.Reason = reasonTargetFound
			condition.Message = fmt.Sprintf("Ingress %s serves %s", key, hostList(hosts))
		}
	}

	// Reported before the comparison below, not after it: a restarted
	// process finds the status already correct and writes nothing, and the
	// series has to appear all the same.
	r.Metrics.SetNetworkRoleResolved(role.Namespace, role.Name, condition.Status == metav1.ConditionTrue)

	meta.SetStatusCondition(&status.Conditions, condition)
	if apiequality.Semantic.DeepEqual(role.Status, status) {
		return ctrl.Result{}, nil
	}
	role.Status = status
	if err := r.Client.Status().Update(ctx, &role); err != nil {
		return ctrl.Result{}, fmt.Errorf("writing the status of NetworkRole %s: %w", req.NamespacedName, err)
	}
	r.Log.V(1).Info("resolved a role's target",
		"networkrole", req.NamespacedName, "resolved", condition.Status == metav1.ConditionTrue)
	return ctrl.Result{}, nil
}

// SetupWithManager registers the controller.
//
// It is explicitly leader elected. controller-runtime would do that by default,
// but ADR 0016 asks for the side of the split to be stated rather than
// inherited, so that reading the registration answers the question.
func (r *NetworkRoleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("networkrole-status").
		For(&gatev1alpha1.NetworkRole{}).
		// An Ingress appearing is what fixes a reference that resolved to
		// nothing, and an Ingress going away is what breaks one.
		Watches(&networkingv1.Ingress{}, handler.EnqueueRequestsFromMapFunc(r.rolesTargeting)).
		WithOptions(controller.Options{NeedLeaderElection: ptr.To(true)}).
		Complete(r)
}

// rolesTargeting enqueues the roles whose targetRef names this object.
//
// Roles that already resolve to it are included along with roles that do not
// resolve at all, since both change when the object comes or goes.
func (r *NetworkRoleReconciler) rolesTargeting(ctx context.Context, obj client.Object) []reconcile.Request {
	var roles gatev1alpha1.NetworkRoleList
	if err := r.Reader.List(ctx, &roles); err != nil {
		return nil
	}
	target := types.NamespacedName{Namespace: obj.GetNamespace(), Name: obj.GetName()}
	var out []reconcile.Request
	for i := range roles.Items {
		key, resolvable := policy.TargetKey(&roles.Items[i])
		if !resolvable || key != target {
			continue
		}
		out = append(out, requestFor(&roles.Items[i]))
	}
	return out
}

// NetworkRoleBindingReconciler writes back whether a binding's roleRef names a
// role that exists.
//
// A binding that names nothing grants nothing. That failure is quieter than a
// broken targetRef — it closes rather than opens — but it is just as invisible
// from the binding itself, and it looks exactly like a permission that was
// never granted.
type NetworkRoleBindingReconciler struct {
	// Client writes status. Required.
	Client client.Client
	// Reader reads bindings and roles, from the manager's cache.
	Reader client.Reader
	// Recorder reports a reference that resolves to nothing. Required.
	Recorder record.EventRecorder
	// Log records the decisions. The zero Logger discards.
	Log logr.Logger
}

// Reconcile resolves one binding's role and records the outcome.
func (r *NetworkRoleBindingReconciler) Reconcile(ctx context.Context, req reconcile.Request) (ctrl.Result, error) {
	var binding gatev1alpha1.NetworkRoleBinding
	if err := r.Reader.Get(ctx, req.NamespacedName, &binding); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	status := gatev1alpha1.NetworkRoleBindingStatus{
		ObservedGeneration: binding.Generation,
		Conditions:         append([]metav1.Condition(nil), binding.Status.Conditions...),
	}
	condition := metav1.Condition{
		Type:               gatev1alpha1.ConditionRoleResolved,
		ObservedGeneration: binding.Generation,
	}

	// The reference is namespace-local: a binding can never reach across a
	// namespace boundary to grant something its author does not own.
	key := types.NamespacedName{Namespace: binding.Namespace, Name: binding.Spec.RoleRef.Name}
	var role gatev1alpha1.NetworkRole
	err := r.Reader.Get(ctx, key, &role)
	switch {
	case apierrors.IsNotFound(err):
		condition.Status = metav1.ConditionFalse
		condition.Reason = reasonRoleNotFound
		condition.Message = fmt.Sprintf(
			"NetworkRole %s does not exist, so this binding grants nothing", key)
		r.Recorder.Event(&binding, corev1.EventTypeWarning, reasonRoleNotFound, condition.Message)
	case err != nil:
		return ctrl.Result{}, err
	default:
		condition.Status = metav1.ConditionTrue
		condition.Reason = reasonRoleFound
		condition.Message = fmt.Sprintf("NetworkRole %s is granted to %d subject(s)", key, len(binding.Spec.Subjects))
	}

	meta.SetStatusCondition(&status.Conditions, condition)
	if apiequality.Semantic.DeepEqual(binding.Status, status) {
		return ctrl.Result{}, nil
	}
	binding.Status = status
	if err := r.Client.Status().Update(ctx, &binding); err != nil {
		return ctrl.Result{}, fmt.Errorf("writing the status of NetworkRoleBinding %s: %w", req.NamespacedName, err)
	}
	r.Log.V(1).Info("resolved a binding's role",
		"networkrolebinding", req.NamespacedName, "resolved", condition.Status == metav1.ConditionTrue)
	return ctrl.Result{}, nil
}

// SetupWithManager registers the controller. It is explicitly leader elected,
// for the same reason as the role's own status (ADR 0006, 0016).
func (r *NetworkRoleBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("networkrolebinding-status").
		For(&gatev1alpha1.NetworkRoleBinding{}).
		Watches(&gatev1alpha1.NetworkRole{}, handler.EnqueueRequestsFromMapFunc(r.bindingsOfRole)).
		WithOptions(controller.Options{NeedLeaderElection: ptr.To(true)}).
		Complete(r)
}

// bindingsOfRole enqueues the bindings that name this role.
func (r *NetworkRoleBindingReconciler) bindingsOfRole(ctx context.Context, obj client.Object) []reconcile.Request {
	var bindings gatev1alpha1.NetworkRoleBindingList
	if err := r.Reader.List(ctx, &bindings, client.InNamespace(obj.GetNamespace())); err != nil {
		return nil
	}
	var out []reconcile.Request
	for i := range bindings.Items {
		if bindings.Items[i].Spec.RoleRef.Name != obj.GetName() {
			continue
		}
		out = append(out, requestFor(&bindings.Items[i]))
	}
	return out
}
