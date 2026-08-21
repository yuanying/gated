package controller

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	gatedacme "github.com/yuanying/gated/internal/acme"
	"github.com/yuanying/gated/internal/certs"
	"github.com/yuanying/gated/internal/ingress"
)

// Issuer obtains a certificate for a set of hosts.
//
// It is an interface so that the reconciler can be exercised without an ACME
// directory, and so that whoever decides an order may be placed — the elected
// leader, and nobody else (ADR 0006) — is separable from the code that decides
// one is needed.
type Issuer interface {
	Obtain(ctx context.Context, hosts []string) (*gatedacme.Keypair, error)
}

// Timings of the retry after a failed order. ACME directories rate limit by
// domain and by failure, so the first retry is a wait rather than a moment
// later, and the cap still leaves dozens of attempts inside the thirty day
// renewal window.
const (
	defaultRetryBaseDelay = 30 * time.Second
	defaultRetryMaxDelay  = 8 * time.Hour
	// maxRequeueInterval bounds how far ahead a look is scheduled, so that
	// a process running for months still re-reads what it believes.
	maxRequeueInterval = 12 * time.Hour
)

// Event reasons recorded against the Ingress. ADR 0005 asks for the count and
// the reason of a failure to be visible somewhere; Ingress has no status field
// to put them in, so they are events.
const (
	reasonIssuing     = "IssuingCertificate"
	reasonIssued      = "IssuedCertificate"
	reasonIssueFailed = "CertificateIssuanceFailed"
	reasonUnusable    = "CertificateSecretUnusable"
)

// CertificateReconciler keeps the Secret an Ingress names in spec.tls holding
// a certificate for the hosts beside it.
//
// spec.tls is the whole trigger (ADR 0005). No annotation is required: writing
// spec.tls is already the statement that this host is served over TLS, and
// asking for a second declaration only creates a way to get it wrong.
type CertificateReconciler struct {
	// Client reads and writes Secrets. It must not be backed by a cache
	// restricted to TLS Secrets, because the account key and the challenge
	// tokens are Opaque.
	Client client.Client
	// Reader lists Ingresses and IngressClasses, from the manager's cache.
	Reader client.Reader
	// IngressClass is the class this process is responsible for.
	IngressClass string
	// Issuer places the orders. Required.
	Issuer Issuer
	// Policy decides when a certificate is due for replacement. The zero
	// value uses certs.DefaultPolicy.
	Policy certs.Policy
	// Recorder reports what happened against the Ingress. Required.
	Recorder record.EventRecorder
	// RetryBaseDelay and RetryMaxDelay bound the backoff between attempts.
	RetryBaseDelay time.Duration
	RetryMaxDelay  time.Duration
	// Now reads the clock, overridable in tests.
	Now func() time.Time
	// Log records the decisions. The zero Logger discards.
	Log logr.Logger

	mu sync.Mutex
	// attempts counts consecutive failures per target Secret, so that an
	// event can say how long this has been going on. The work queue owns
	// the backoff itself.
	attempts map[types.NamespacedName]int
}

// Reconcile brings every tls block of one Ingress up to date.
//
// Each block is dealt with on its own: an order that fails for one Secret does
// not stop the others from being looked at, because the hosts behind them are
// unrelated.
func (r *CertificateReconciler) Reconcile(ctx context.Context, req reconcile.Request) (ctrl.Result, error) {
	var ing networkingv1.Ingress
	if err := r.Reader.Get(ctx, req.NamespacedName, &ing); err != nil {
		if apierrors.IsNotFound(err) {
			r.forgetNamespace(req.Namespace, req.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	var classes networkingv1.IngressClassList
	if err := r.Reader.List(ctx, &classes); err != nil {
		return ctrl.Result{}, err
	}
	if !ingress.Selected(&ing, classes.Items, r.IngressClass) {
		return ctrl.Result{}, nil
	}

	var (
		failures []error
		next     time.Duration
	)
	for _, block := range ing.Spec.TLS {
		if block.SecretName == "" {
			continue
		}
		due, err := r.ensure(ctx, &ing, block.SecretName, block.Hosts)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if due > 0 && (next == 0 || due < next) {
			next = due
		}
	}

	if len(failures) > 0 {
		// Returning the error hands the retry to the work queue, whose
		// rate limiter is the exponential backoff ADR 0005 asks for.
		// A result is not returned alongside it: the queue would
		// ignore it anyway.
		return ctrl.Result{}, errors.Join(failures...)
	}
	return ctrl.Result{RequeueAfter: next}, nil
}

// ensure deals with one tls block, returning how long until the certificate it
// left in place is due for renewal.
func (r *CertificateReconciler) ensure(ctx context.Context, ing *networkingv1.Ingress, secretName string, hosts []string) (time.Duration, error) {
	key := types.NamespacedName{Namespace: ing.Namespace, Name: secretName}

	secret, err := r.readSecret(ctx, key)
	if err != nil {
		return 0, err
	}
	if secret != nil && secret.Type != corev1.SecretTypeTLS {
		// A Secret's type cannot be changed, so this cannot be fixed
		// by writing to it. Say so rather than failing on the update.
		r.Recorder.Eventf(ing, corev1.EventTypeWarning, reasonUnusable,
			"Secret %s is of type %q; a certificate needs %q", key, secret.Type, corev1.SecretTypeTLS)
		return 0, fmt.Errorf("Secret %s is of type %q, want %q", key, secret.Type, corev1.SecretTypeTLS)
	}

	decision := r.policy().Evaluate(materialOf(secret), hosts, r.now())
	log := r.Log.WithValues("ingress", client.ObjectKeyFromObject(ing), "secret", key, "hosts", hosts)

	if !decision.Renew {
		r.forget(key)
		log.V(1).Info("the certificate in place is current", "reason", string(decision.Reason))
		return r.until(decision), nil
	}
	if decision.Reason == certs.ReasonNoHosts {
		return 0, nil
	}

	log.Info("ordering a certificate", "reason", string(decision.Reason), "detail", decision.Detail)
	r.Recorder.Eventf(ing, corev1.EventTypeNormal, reasonIssuing,
		"Ordering a certificate for %s into Secret %s: %s", hostList(hosts), key, decision.Detail)

	keypair, err := r.Issuer.Obtain(ctx, hosts)
	if err != nil {
		attempt := r.failed(key)
		// Nothing is written on this path. That is the whole of how
		// ADR 0005's requirement is met: a renewal that cannot be
		// completed leaves the certificate already in place untouched,
		// and the listener goes on serving it.
		if decision.Usable {
			r.Recorder.Eventf(ing, corev1.EventTypeWarning, reasonIssueFailed,
				"Ordering a certificate for %s failed on attempt %d: %v. Keeping the certificate already in Secret %s, which is valid until %s",
				hostList(hosts), attempt, err, key, decision.NotAfter.UTC().Format(time.RFC3339))
		} else {
			r.Recorder.Eventf(ing, corev1.EventTypeWarning, reasonIssueFailed,
				"Ordering a certificate for %s failed on attempt %d: %v. Secret %s holds nothing usable: %s",
				hostList(hosts), attempt, err, key, decision.Detail)
		}
		return 0, fmt.Errorf("ordering a certificate for %s: %w", hostList(hosts), err)
	}

	if err := r.writeSecret(ctx, key, secret, keypair); err != nil {
		attempt := r.failed(key)
		r.Recorder.Eventf(ing, corev1.EventTypeWarning, reasonIssueFailed,
			"Storing the certificate for %s failed on attempt %d: %v", hostList(hosts), attempt, err)
		return 0, err
	}

	r.forget(key)
	stored := r.policy().Evaluate(&certs.Material{CertPEM: keypair.CertPEM, KeyPEM: keypair.KeyPEM}, hosts, r.now())
	log.Info("stored a certificate", "notAfter", stored.NotAfter)
	r.Recorder.Eventf(ing, corev1.EventTypeNormal, reasonIssued,
		"Issued a certificate for %s into Secret %s, valid until %s",
		hostList(hosts), key, stored.NotAfter.UTC().Format(time.RFC3339))
	return r.until(stored), nil
}

// readSecret returns the Secret, or nil when there is none.
func (r *CertificateReconciler) readSecret(ctx context.Context, key types.NamespacedName) (*corev1.Secret, error) {
	var secret corev1.Secret
	if err := r.Client.Get(ctx, key, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading Secret %s: %w", key, err)
	}
	return &secret, nil
}

// writeSecret stores a keypair, creating the Secret when it is not there.
//
// No owner reference is set. gated adopts a Secret somebody else created (ADR
// 0005), and an owner reference on such a Secret would have the garbage
// collector delete a hand-written certificate when the Ingress goes away.
func (r *CertificateReconciler) writeSecret(ctx context.Context, key types.NamespacedName, existing *corev1.Secret, keypair *gatedacme.Keypair) error {
	if existing == nil {
		created := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: key.Namespace,
				Name:      key.Name,
				Labels:    map[string]string{gatedacme.ManagedByLabel: gatedacme.ManagedByValue},
			},
			Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{
				corev1.TLSCertKey:       keypair.CertPEM,
				corev1.TLSPrivateKeyKey: keypair.KeyPEM,
			},
		}
		if err := r.Client.Create(ctx, created); err != nil {
			return fmt.Errorf("creating Secret %s: %w", key, err)
		}
		return nil
	}

	if existing.Data == nil {
		existing.Data = map[string][]byte{}
	}
	existing.Data[corev1.TLSCertKey] = keypair.CertPEM
	existing.Data[corev1.TLSPrivateKeyKey] = keypair.KeyPEM
	if existing.Labels == nil {
		existing.Labels = map[string]string{}
	}
	existing.Labels[gatedacme.ManagedByLabel] = gatedacme.ManagedByValue
	if err := r.Client.Update(ctx, existing); err != nil {
		return fmt.Errorf("updating Secret %s: %w", key, err)
	}
	return nil
}

// until is how long to wait before looking at this Secret again.
func (r *CertificateReconciler) until(decision certs.Decision) time.Duration {
	if decision.RenewAt.IsZero() {
		return 0
	}
	wait := decision.RenewAt.Sub(r.now())
	if wait <= 0 {
		return time.Minute
	}
	if wait > maxRequeueInterval {
		return maxRequeueInterval
	}
	return wait
}

func (r *CertificateReconciler) policy() certs.Policy {
	if r.Policy.LifetimeDivisor <= 0 && r.Policy.MinRemaining <= 0 {
		return certs.DefaultPolicy()
	}
	return r.Policy
}

func (r *CertificateReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// failed records one more consecutive failure and returns the running count.
func (r *CertificateReconciler) failed(key types.NamespacedName) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.attempts == nil {
		r.attempts = map[types.NamespacedName]int{}
	}
	r.attempts[key]++
	return r.attempts[key]
}

func (r *CertificateReconciler) forget(key types.NamespacedName) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.attempts, key)
}

// forgetNamespace drops the counters of an Ingress that is gone. The Secret
// names are no longer known, so everything in the namespace is cleared; the
// count is a reporting aid, not state anything depends on.
func (r *CertificateReconciler) forgetNamespace(namespace, _ string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key := range r.attempts {
		if key.Namespace == namespace {
			delete(r.attempts, key)
		}
	}
}

// materialOf reads the PEM out of a Secret, in the neutral form the renewal
// decision takes.
func materialOf(secret *corev1.Secret) *certs.Material {
	if secret == nil {
		return nil
	}
	return &certs.Material{
		CertPEM: secret.Data[corev1.TLSCertKey],
		KeyPEM:  secret.Data[corev1.TLSPrivateKeyKey],
	}
}

func hostList(hosts []string) string {
	if len(hosts) == 0 {
		return "no host"
	}
	out := hosts[0]
	for _, h := range hosts[1:] {
		out += ", " + h
	}
	return out
}

// SetupWithManager registers the controller.
//
// It is leader elected, which is controller-runtime's default and what ADR
// 0006 wants: every replica watches and proxies, but only one places orders,
// or the same certificate is ordered as many times as there are replicas and
// the directory's rate limit is spent that much faster.
func (r *CertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	base := r.RetryBaseDelay
	if base <= 0 {
		base = defaultRetryBaseDelay
	}
	max := r.RetryMaxDelay
	if max <= 0 {
		max = defaultRetryMaxDelay
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named("certificates").
		For(&networkingv1.Ingress{}).
		// A class becoming, or ceasing to be, the cluster default
		// changes which Ingresses are ours.
		Watches(&networkingv1.IngressClass{}, handler.EnqueueRequestsFromMapFunc(r.ingressesOfClass)).
		// A certificate Secret being edited or deleted has to bring the
		// Ingress that depends on it back for a look.
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.ingressesUsing)).
		WithOptions(controller.Options{
			RateLimiter: workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](base, max),
		}).
		Complete(r)
}

// ingressesOfClass enqueues every Ingress, because a change to a class can
// change the answer for any of them.
func (r *CertificateReconciler) ingressesOfClass(ctx context.Context, _ client.Object) []reconcile.Request {
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

// ingressesUsing enqueues the Ingresses that name this Secret in spec.tls.
func (r *CertificateReconciler) ingressesUsing(ctx context.Context, obj client.Object) []reconcile.Request {
	var list networkingv1.IngressList
	if err := r.Reader.List(ctx, &list, client.InNamespace(obj.GetNamespace())); err != nil {
		return nil
	}
	var out []reconcile.Request
	for i := range list.Items {
		for _, block := range list.Items[i].Spec.TLS {
			if block.SecretName == obj.GetName() {
				out = append(out, requestFor(&list.Items[i]))
				break
			}
		}
	}
	return out
}

func requestFor(obj client.Object) reconcile.Request {
	return reconcile.Request{NamespacedName: types.NamespacedName{
		Namespace: obj.GetNamespace(), Name: obj.GetName(),
	}}
}
