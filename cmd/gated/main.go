// Command gated is an Ingress controller that terminates TLS, obtains its own
// certificates over ACME and authorises requests against its own CRDs.
//
// Controller and proxy live in the same process (ADR 0001): the same binary
// watches the API server, answers ACME challenges, runs the login flow and
// forwards traffic to backends.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	gatev1alpha1 "github.com/yuanying/gated/internal/apis/gate/v1alpha1"
	"github.com/yuanying/gated/internal/config"
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

	// Reconcilers and the proxy are registered here as later stages add
	// them. The manager already knows how to start and stop them.

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
