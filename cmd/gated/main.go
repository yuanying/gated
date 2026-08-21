// Command gated is an Ingress controller that terminates TLS, obtains its own
// certificates over ACME and authorises requests against its own CRDs.
//
// Controller and proxy live in the same process (ADR 0001): the same binary
// watches the API server, answers ACME challenges, runs the login flow and
// forwards traffic to backends.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	gatedacme "github.com/yuanying/gated/internal/acme"
	"github.com/yuanying/gated/internal/acme/http01"
	gatev1alpha1 "github.com/yuanying/gated/internal/apis/gate/v1alpha1"
	"github.com/yuanying/gated/internal/config"
	"github.com/yuanying/gated/internal/controller"
	"github.com/yuanying/gated/internal/proxy"
)

// gracefulShutdownTimeout is how long the manager waits for its runnables to
// return once the process is asked to stop, and proxyDrainTimeout is how long
// the listeners spend draining inside that. The listeners have to finish
// first, or the manager gives up on them mid-drain.
const (
	gracefulShutdownTimeout = 30 * time.Second
	proxyDrainTimeout       = 25 * time.Second
)

// scheme carries every type the process reads or writes. Ingress and Secret
// come from the core API; the gate group carries authorisation and tokens.
var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(networkingv1.AddToScheme(scheme))
	utilruntime.Must(gatev1alpha1.AddToScheme(scheme))
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg := config.Default()

	fs := config.NewFlagSet("gated")
	cfg.AddFlags(fs)

	zapOpts := zap.Options{Development: false}
	zapOpts.BindFlags(fs)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration:\n%w", err)
	}

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zapOpts)))
	log := ctrl.Log.WithName("gated")

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), managerOptions(cfg))
	if err != nil {
		return fmt.Errorf("building the manager: %w", err)
	}

	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return fmt.Errorf("registering the health check: %w", err)
	}
	if err := mgr.AddReadyzCheck("ping", healthz.Ping); err != nil {
		return fmt.Errorf("registering the readiness check: %w", err)
	}

	challenges := &http01.SecretStore{
		Client:    mgr.GetClient(),
		Namespace: cfg.ChallengeSecretNamespace,
	}
	if err := setupDataPlane(mgr, cfg, challenges, log); err != nil {
		return err
	}
	if err := setupCertificates(mgr, cfg, challenges, log); err != nil {
		return err
	}

	// The remaining reconcilers — authorisation, tokens — are registered
	// here as later stages add them, through a setup function of their
	// own rather than inline: which side of ADR 0006's split a runnable
	// falls on is checked per setup function, and one registered here
	// directly is checked by nothing.

	log.Info("starting",
		"ingressClass", cfg.IngressClass,
		"httpAddr", cfg.HTTPAddr,
		"httpsAddr", cfg.HTTPSAddr,
		"authHost", cfg.Auth.Host,
		"leaderElection", cfg.LeaderElection.Enabled,
	)

	// SetupSignalHandler cancels the context on the first SIGINT or SIGTERM
	// and aborts the process on the second, so a stuck shutdown can still be
	// interrupted. Start returns once every runnable has stopped.
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("running the manager: %w", err)
	}

	log.Info("stopped")
	return nil
}

// setupDataPlane wires the routing table, the reverse proxy and the two
// listeners into the manager.
//
// Everything here runs on every replica. Only certificate issuance is the
// leader's job (ADR 0006), so nothing in this path may be gated on the lease:
// a replica that loses it must keep serving traffic.
func setupDataPlane(mgr ctrl.Manager, cfg config.Config, challenges http01.Source, log logr.Logger) error {
	tables := &proxy.TableStore{}

	routes := &controller.RoutingReconciler{
		Reader:       mgr.GetCache(),
		IngressClass: cfg.IngressClass,
		Tables:       tables,
	}
	if err := routes.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("registering the routing controller: %w", err)
	}

	// Services and certificates are read while a request is being served,
	// not from a reconciler, so nothing else would start their informers.
	// Without this the first request of each kind waits for a full list.
	if err := mgr.Add(warmUpCache(mgr, &corev1.Service{}, &corev1.Secret{})); err != nil {
		return fmt.Errorf("registering the data plane caches: %w", err)
	}

	certificates := &proxy.Certificates{
		Tables: tables,
		Store:  &controller.SecretCertificates{Reader: mgr.GetCache()},
		Log:    log.WithName("tls"),
	}

	servers := &proxy.Servers{
		HTTPAddr:  cfg.HTTPAddr,
		HTTPSAddr: cfg.HTTPSAddr,
		Handler: &proxy.Handler{
			Tables:   tables,
			Backends: &controller.ServiceResolver{Reader: mgr.GetCache()},
			Log:      log.WithName("proxy"),
		},
		// Answering challenges is every replica's job, not the
		// leader's: the CA reaches whichever replica the load balancer
		// hands it (ADR 0006).
		InsecureHandler: &proxy.InsecureHandler{
			Solver: &http01.Responder{Source: challenges, Log: log.WithName("acme-http01")},
			Log:    log.WithName("http"),
		},
		TLSConfig:       certificates.TLSConfig(),
		ShutdownTimeout: proxyDrainTimeout,
		Log:             log.WithName("servers"),
	}
	if err := mgr.Add(servers); err != nil {
		return fmt.Errorf("registering the listeners: %w", err)
	}
	return nil
}

// setupCertificates wires the ACME client and the reconciler that drives it.
//
// The reconciler is leader elected, which is controller-runtime's default and
// what ADR 0006 asks for: every replica watches and proxies, but only one
// places orders, or the same certificate is ordered once per replica and the
// directory's rate limit is spent that much faster.
func setupCertificates(mgr ctrl.Manager, cfg config.Config, challenges http01.Store, log logr.Logger) error {
	acmeLog := log.WithName("acme")

	issuer := &gatedacme.Client{
		DirectoryURL: cfg.ACME.DirectoryURL,
		Email:        cfg.ACME.Email,
		Accounts: &gatedacme.SecretAccountStore{
			Client:    mgr.GetClient(),
			Namespace: cfg.ACME.AccountSecret.Namespace,
			Name:      cfg.ACME.AccountSecret.Name,
			Log:       acmeLog,
		},
		Solver: &http01.Solver{
			Store: challenges,
			// The write has to be old enough that a replica
			// serving a snapshot takes a fresh look before it
			// answers the validation request.
			Propagation: http01.DefaultPropagation,
			Log:         acmeLog.WithName("http01"),
		},
		UserAgent: "gated",
		Log:       acmeLog,
	}

	certificates := &controller.CertificateReconciler{
		Client:       mgr.GetClient(),
		Reader:       mgr.GetCache(),
		IngressClass: cfg.IngressClass,
		Issuer:       issuer,
		Recorder:     mgr.GetEventRecorderFor("gated-certificates"),
		Log:          log.WithName("certificates"),
	}
	if err := certificates.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("registering the certificate controller: %w", err)
	}
	return nil
}

// cacheWarmUp starts the informers for a set of kinds before anything asks
// them for an object.
//
// It is not leader elected. The kinds it starts are read while a request is
// being served, so a replica that never wins the lease needs them just as
// much as the one that does (ADR 0006).
type cacheWarmUp struct {
	cache cache.Cache
	objs  []client.Object
}

// warmUpCache returns a runnable that starts the informers for objs.
func warmUpCache(mgr ctrl.Manager, objs ...client.Object) *cacheWarmUp {
	return &cacheWarmUp{cache: mgr.GetCache(), objs: objs}
}

// NeedLeaderElection reports that every replica warms its own cache.
func (w *cacheWarmUp) NeedLeaderElection() bool { return false }

// Start requests each informer and returns; the cache itself keeps them
// running for as long as the manager does.
func (w *cacheWarmUp) Start(ctx context.Context) error {
	for _, obj := range w.objs {
		if _, err := w.cache.GetInformer(ctx, obj); err != nil {
			return err
		}
	}
	return nil
}

// managerOptions translates the startup configuration into the manager's own
// options.
//
// Leader election gates certificate issuance only (ADR 0006). Watching,
// proxying and authorising run on every replica, so losing the lease must not
// take traffic with it: the runnables that serve requests are registered
// outside the leader-elected set.
func managerOptions(cfg config.Config) ctrl.Options {
	opts := ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 metricsserver.Options{BindAddress: cfg.MetricsAddr},
		HealthProbeBindAddress:  cfg.HealthProbeAddr,
		GracefulShutdownTimeout: ptr.To(gracefulShutdownTimeout),
		Cache:                   cacheOptions(),
		Client: client.Options{
			// Reads of Secrets bypass the cache. The cache holds only
			// TLS Secrets, so serving an Opaque Secret from it would
			// answer "not found" for something that exists. Later
			// stages read the ACME account key and the session key
			// through this client and must not fall into that.
			Cache: &client.CacheOptions{DisableFor: []client.Object{&corev1.Secret{}}},
		},
		LeaderElection:          cfg.LeaderElection.Enabled,
		LeaderElectionID:        cfg.LeaderElection.ID,
		LeaderElectionNamespace: cfg.LeaderElection.Namespace,
		// Handing the lease back on shutdown lets the next leader take
		// over at once instead of waiting out the full lease duration.
		LeaderElectionReleaseOnCancel: true,
	}
	if cfg.LeaderElection.Enabled {
		opts.LeaseDuration = &cfg.LeaderElection.LeaseDuration
		opts.RenewDeadline = &cfg.LeaderElection.RenewDeadline
		opts.RetryPeriod = &cfg.LeaderElection.RetryPeriod
	}
	return opts
}

// cacheOptions restricts what the informers hold.
//
// Secrets are the expensive kind: caching all of them means keeping every
// credential in the cluster in memory. gated needs exactly one class of Secret
// while serving a request — the certificates it terminates TLS with — so that
// is the only class it caches.
func cacheOptions() cache.Options {
	return cache.Options{
		ByObject: map[client.Object]cache.ByObject{
			&corev1.Secret{}: {
				Field: fields.OneTermEqualSelector("type", string(corev1.SecretTypeTLS)),
			},
		},
	}
}
