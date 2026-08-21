package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
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

	"github.com/yuanying/gated/internal/accesstoken"
	gatedacme "github.com/yuanying/gated/internal/acme"
	gatev1alpha1 "github.com/yuanying/gated/internal/apis/gate/v1alpha1"
)

// Reasons written into the TokenIssued condition and the events beside it.
const (
	reasonTokenIssued      = "TokenIssued"
	reasonTokenRotated     = "TokenRotated"
	reasonSecretNotOurs    = "SecretNotOurs"
	reasonSecretUnwritable = "SecretUnwritable"
)

// defaultTokenResync is how often an AccessToken is looked at again when
// nothing has happened to it.
//
// It exists because the Secret cannot be watched. The informer cache holds
// only TLS Secrets (ADR 0013), so a token Secret that is deleted produces no
// event, and without a periodic look the AccessToken would go on claiming a
// token that nobody can read any more.
const defaultTokenResync = 10 * time.Minute

// AccessTokenReconciler mints the token an AccessToken declares and writes it
// into a Secret.
//
// It is the leader's job. The token is a value invented rather than derived,
// so two replicas deciding would invent two different ones and the second
// would revoke the first (ADR 0006).
type AccessTokenReconciler struct {
	// Client reads and writes AccessTokens and their Secrets. It must not
	// be backed by the TLS-only cache, or the Opaque Secret holding a token
	// reads as absent and every reconcile mints a new one.
	Client client.Client
	// Recorder reports a token being minted and a Secret that is in the
	// way. Required.
	Recorder record.EventRecorder
	// Resync is how often a token is checked when nothing happened to it.
	// Zero means defaultTokenResync.
	Resync time.Duration
	// Log records the decisions. The zero Logger discards.
	Log logr.Logger
}

// Reconcile brings one AccessToken's Secret and status into line with its
// spec.
func (r *AccessTokenReconciler) Reconcile(ctx context.Context, req reconcile.Request) (ctrl.Result, error) {
	var token gatev1alpha1.AccessToken
	if err := r.Client.Get(ctx, req.NamespacedName, &token); err != nil {
		if apierrors.IsNotFound(err) {
			// The Secret is owned by the AccessToken, so removing
			// the declaration removes the credential with it.
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if !token.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	// The conditions are copied rather than aliased: SetStatusCondition
	// edits in place, and editing the slice the object already holds would
	// make the comparison below find no change and never write.
	status := gatev1alpha1.AccessTokenStatus{
		ObservedGeneration: token.Generation,
		// Whoever last used the token is recorded by another controller,
		// on whichever replica served the request. Carry it through or
		// this write would erase it.
		LastUsedTime: token.Status.LastUsedTime,
		Conditions:   append([]metav1.Condition(nil), token.Status.Conditions...),
	}
	condition := metav1.Condition{
		Type:               gatev1alpha1.ConditionTokenIssued,
		ObservedGeneration: token.Generation,
	}

	hash, err := r.ensureSecret(ctx, &token)
	switch {
	case errors.As(err, new(*secretInTheWay)):
		condition.Status = metav1.ConditionFalse
		condition.Reason = reasonSecretNotOurs
		condition.Message = err.Error()
		r.Recorder.Event(&token, corev1.EventTypeWarning, reasonSecretNotOurs, condition.Message)
	case err != nil:
		condition.Status = metav1.ConditionFalse
		condition.Reason = reasonSecretUnwritable
		condition.Message = err.Error()
		// Setting the condition and returning the error both: the
		// condition is what a person reads, the error is what makes the
		// controller try again.
		meta.SetStatusCondition(&status.Conditions, condition)
		token.Status = status
		if updateErr := r.Client.Status().Update(ctx, &token); updateErr != nil {
			r.Log.V(1).Info("could not report why a token was not issued", "reason", updateErr.Error())
		}
		return ctrl.Result{}, err
	default:
		name := secretNameFor(&token)
		status.SecretRef = &corev1.LocalObjectReference{Name: name}
		status.TokenHash = hash
		condition.Status = metav1.ConditionTrue
		condition.Reason = reasonTokenIssued
		condition.Message = fmt.Sprintf("the token is in the %q entry of Secret %s/%s, and acts as %s",
			accesstoken.SecretKey, token.Namespace, name, token.Spec.Subject)
	}

	meta.SetStatusCondition(&status.Conditions, condition)
	if !apiequality.Semantic.DeepEqual(token.Status, status) {
		token.Status = status
		if err := r.Client.Status().Update(ctx, &token); err != nil {
			return ctrl.Result{}, fmt.Errorf("writing the status of AccessToken %s: %w", req.NamespacedName, err)
		}
	}
	// Looked at again on a timer because the Secret cannot be watched; see
	// defaultTokenResync.
	return ctrl.Result{RequeueAfter: r.resync()}, nil
}

// secretInTheWay reports a Secret that exists, holds no gated token and was
// not put there by gated.
type secretInTheWay struct {
	key types.NamespacedName
}

func (e *secretInTheWay) Error() string {
	return fmt.Sprintf(
		"Secret %s already exists and was not created by gated, so no token was written into it; "+
			"choose another spec.secretName, or remove that Secret", e.key)
}

// ensureSecret makes sure the token exists, and returns its digest.
//
// A token already in the Secret is kept: the value is the credential somebody
// is using, and reissuing it would revoke it. A Secret that is gone means a
// new token, which is the one way an operator can rotate one — the value
// cannot be recovered from its digest, so there is nothing else to restore.
func (r *AccessTokenReconciler) ensureSecret(ctx context.Context, token *gatev1alpha1.AccessToken) (string, error) {
	key := types.NamespacedName{Namespace: token.Namespace, Name: secretNameFor(token)}

	var secret corev1.Secret
	err := r.Client.Get(ctx, key, &secret)
	switch {
	case err == nil:
		if existing := string(secret.Data[accesstoken.SecretKey]); existing != "" {
			return accesstoken.Hash(existing), nil
		}
		if !ours(&secret) {
			return "", &secretInTheWay{key: key}
		}
		value, err := accesstoken.New()
		if err != nil {
			return "", err
		}
		if secret.Data == nil {
			secret.Data = map[string][]byte{}
		}
		secret.Data[accesstoken.SecretKey] = []byte(value)
		if err := r.Client.Update(ctx, &secret); err != nil {
			return "", fmt.Errorf("writing the token into Secret %s: %w", key, err)
		}
		r.Recorder.Eventf(token, corev1.EventTypeNormal, reasonTokenRotated,
			"a new token was written into Secret %s", key)
		return accesstoken.Hash(value), nil
	case !apierrors.IsNotFound(err):
		return "", fmt.Errorf("reading Secret %s: %w", key, err)
	}

	value, err := accesstoken.New()
	if err != nil {
		return "", err
	}
	secret = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: key.Namespace,
			Name:      key.Name,
			Labels:    map[string]string{gatedacme.ManagedByLabel: gatedacme.ManagedByValue},
			// The Secret belongs to the AccessToken. Deleting the
			// declaration takes the credential with it, which is
			// what "revoke it by deleting it" has to mean
			// (ADR 0004).
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion:         gatev1alpha1.GroupVersion.String(),
				Kind:               "AccessToken",
				Name:               token.Name,
				UID:                token.UID,
				Controller:         ptr.To(true),
				BlockOwnerDeletion: ptr.To(true),
			}},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{accesstoken.SecretKey: []byte(value)},
	}
	if err := r.Client.Create(ctx, &secret); err != nil {
		return "", fmt.Errorf("creating Secret %s: %w", key, err)
	}
	r.Log.Info("issued an access token", "accesstoken", client.ObjectKeyFromObject(token), "secret", key)
	r.Recorder.Eventf(token, corev1.EventTypeNormal, reasonTokenIssued,
		"a token was written into Secret %s", key)
	return accesstoken.Hash(value), nil
}

func (r *AccessTokenReconciler) resync() time.Duration {
	if r.Resync <= 0 {
		return defaultTokenResync
	}
	return r.Resync
}

// SetupWithManager registers the controller. It is explicitly leader elected
// (ADR 0006, 0016).
func (r *AccessTokenReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("accesstoken").
		For(&gatev1alpha1.AccessToken{}).
		WithOptions(controller.Options{NeedLeaderElection: ptr.To(true)}).
		Complete(r)
}

// secretNameFor is where a token is written. An unset spec.secretName means
// the AccessToken's own name, so that the ordinary case needs no second name.
func secretNameFor(token *gatev1alpha1.AccessToken) string {
	if token.Spec.SecretName != "" {
		return token.Spec.SecretName
	}
	return token.Name
}

// ours reports whether gated created this Secret. An empty Secret counts:
// there is nothing in it to destroy.
func ours(secret *corev1.Secret) bool {
	if secret.Labels[gatedacme.ManagedByLabel] == gatedacme.ManagedByValue {
		return true
	}
	return len(secret.Data) == 0 && len(secret.StringData) == 0
}

// rebuildTokens is the single work item the token set controller queues, for
// the same reason the permissions have one: the set is derived from every
// AccessToken at once, so a burst coalesces into one rebuild.
var rebuildTokens = reconcile.Request{NamespacedName: types.NamespacedName{Name: "access-tokens"}}

// TokenSetReconciler keeps the tokens a replica will accept in step with the
// cluster.
//
// It reads the digests out of the statuses and never the Secrets. That is not
// an optimisation: the informer cache holds TLS Secrets only (ADR 0013), and
// widening it would put every credential in the cluster into this process's
// memory in order to check a handful of tokens.
type TokenSetReconciler struct {
	// Reader lists AccessTokens, from the manager's cache.
	Reader client.Reader
	// Tokens receives each rebuilt snapshot.
	Tokens *accesstoken.Store
	// Log records the size of each snapshot at V(1).
	Log logr.Logger
}

// Reconcile rebuilds the whole set and swaps it in.
func (r *TokenSetReconciler) Reconcile(ctx context.Context, _ reconcile.Request) (ctrl.Result, error) {
	var tokens gatev1alpha1.AccessTokenList
	if err := r.Reader.List(ctx, &tokens); err != nil {
		return ctrl.Result{}, err
	}

	entries := make([]accesstoken.Entry, 0, len(tokens.Items))
	for i := range tokens.Items {
		token := &tokens.Items[i]
		entries = append(entries, accesstoken.Entry{
			Identity: accesstoken.Identity{
				Subject:   token.Spec.Subject,
				Namespace: token.Namespace,
				Name:      token.Name,
			},
			Hash: token.Status.TokenHash,
		})
	}
	snapshot := accesstoken.NewSnapshot(entries)
	r.Tokens.Store(snapshot)

	r.Log.V(1).Info("access tokens rebuilt", "declared", len(tokens.Items), "usable", snapshot.Len())
	return ctrl.Result{}, nil
}

// SetupWithManager registers the controller. It runs on every replica: each
// one serves traffic, and a replica that cannot recognise a token turns it
// into an anonymous request (ADR 0006).
func (r *TokenSetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("accesstoken-set").
		Watches(&gatev1alpha1.AccessToken{}, handler.EnqueueRequestsFromMapFunc(
			func(context.Context, client.Object) []reconcile.Request {
				return []reconcile.Request{rebuildTokens}
			},
		)).
		// A cluster with no AccessToken in it produces no watch event
		// at all, and the snapshot gates readiness.
		WatchesRawSource(startupSource{request: rebuildTokens}).
		WithOptions(controller.Options{NeedLeaderElection: ptr.To(false)}).
		Complete(r)
}

// defaultUsageFlush is how often the buffered uses are written back.
const defaultUsageFlush = time.Minute

// AccessTokenUsageRecorder writes back when a token was last presented.
//
// It runs on every replica, and not under the lease: the replica that saw the
// request is the only one that knows it happened, and a follower that buffered
// a use and never wrote it would make a token in daily use look abandoned
// (ADR 0006).
//
// Nothing here is on the request path. Uses are buffered as they happen and
// written on a timer, so a slow API server costs a stale timestamp and never a
// slow request.
type AccessTokenUsageRecorder struct {
	// Client reads and writes AccessToken status. Required.
	Client client.Client
	// Uses is the buffer the request path writes into. Required.
	Uses *accesstoken.Uses
	// Interval is how often the buffer is drained. Zero means one minute.
	Interval time.Duration
	// Resolution is how close two recorded times may be. Zero means
	// accesstoken.DefaultUsageResolution.
	Resolution time.Duration
	// Log records failures to write, at V(1): a lost timestamp is not
	// worth an error, and the next use writes a fresher one.
	Log logr.Logger
}

// NeedLeaderElection reports that every replica writes what it saw.
func (r *AccessTokenUsageRecorder) NeedLeaderElection() bool { return false }

// Start drains the buffer until the context is cancelled.
func (r *AccessTokenUsageRecorder) Start(ctx context.Context) error {
	ticker := time.NewTicker(r.interval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// One last drain, so that a shutdown does not lose the
			// last minute of use. The parent context is already
			// cancelled, hence a fresh one with a short budget.
			flush, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.interval())
			r.Flush(flush)
			cancel()
			return nil
		case <-ticker.C:
			r.Flush(ctx)
		}
	}
}

// Flush writes back everything buffered so far.
//
// A write that fails is dropped rather than retried. The value being written
// is "somebody used this recently", and the next use produces a fresher one;
// keeping a stale time alive to write it later would be work in aid of a worse
// answer.
func (r *AccessTokenUsageRecorder) Flush(ctx context.Context) {
	for ref, used := range r.Uses.Take() {
		if err := r.record(ctx, ref, used); err != nil {
			r.Log.V(1).Info("could not record that a token was used",
				"accesstoken", ref.Namespace+"/"+ref.Name, "reason", err.Error())
		}
	}
}

func (r *AccessTokenUsageRecorder) record(ctx context.Context, ref accesstoken.Ref, used time.Time) error {
	key := types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}

	var token gatev1alpha1.AccessToken
	if err := r.Client.Get(ctx, key, &token); err != nil {
		return err
	}
	recorded := time.Time{}
	if token.Status.LastUsedTime != nil {
		recorded = token.Status.LastUsedTime.Time
	}
	// Checked against what is stored rather than against what this replica
	// last wrote, so that several replicas serving the same token still
	// write about once per resolution between them.
	if !accesstoken.ShouldRecord(recorded, used, r.resolution()) {
		return nil
	}

	token.Status.LastUsedTime = &metav1.Time{Time: used}
	return r.Client.Status().Update(ctx, &token)
}

func (r *AccessTokenUsageRecorder) interval() time.Duration {
	if r.Interval <= 0 {
		return defaultUsageFlush
	}
	return r.Interval
}

func (r *AccessTokenUsageRecorder) resolution() time.Duration {
	if r.Resolution <= 0 {
		return accesstoken.DefaultUsageResolution
	}
	return r.Resolution
}
