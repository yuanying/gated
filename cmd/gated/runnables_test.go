package main

import (
	"testing"

	"github.com/go-logr/logr"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/yuanying/gated/internal/acme/http01"
	"github.com/yuanying/gated/internal/config"
)

// The tests in this file are about one line of ADR 0006: every replica
// watches, proxies and authorises, and only the leader orders certificates.
//
// That split is easy to get wrong by omission rather than by decision.
// controller-runtime runs a runnable under the lease unless it says otherwise,
// so a controller registered without an opinion silently becomes the leader's
// alone — and a replica that never builds a routing table answers 404 to
// everything it is handed. Nothing about that failure is visible until leader
// election is switched on with more than one replica.
//
// So the check here is mechanical rather than a list of the runnables that
// exist today: whatever setupDataPlane registers must be exempt from the
// lease, and whatever setupCertificates registers must be under it.

// recordingManager is a manager that remembers what was registered with it.
//
// The controller builder registers the controller it builds through the same
// Add, so a reconciler wired with SetupWithManager is recorded alongside the
// runnables main adds directly.
type recordingManager struct {
	ctrl.Manager
	added []manager.Runnable
}

func (m *recordingManager) Add(r manager.Runnable) error {
	m.added = append(m.added, r)
	return m.Manager.Add(r)
}

// newRecordingManager builds a manager that is never started, so it needs no
// API server to talk to: the wiring under test happens entirely before Start.
func newRecordingManager(t *testing.T) *recordingManager {
	t.Helper()

	mgr, err := ctrl.NewManager(&rest.Config{Host: "http://127.0.0.1:1"}, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		// Controller names are registered process-wide. Each test wires
		// its own manager, so the same names come round again.
		Controller: ctrlconfig.Controller{SkipNameValidation: ptr.To(true)},
	})
	if err != nil {
		t.Fatalf("building the manager: %v", err)
	}
	return &recordingManager{Manager: mgr}
}

// underTheLease reports whether the manager would hold this runnable back
// until the replica is the leader. It mirrors what the manager itself does:
// anything that does not declare otherwise is leader elected.
func underTheLease(r manager.Runnable) bool {
	le, ok := r.(manager.LeaderElectionRunnable)
	if !ok {
		return true
	}
	return le.NeedLeaderElection()
}

// testConfig is a configuration that names nothing outside gated itself.
func testConfig() config.Config {
	cfg := config.Default()
	cfg.HTTPAddr = "127.0.0.1:0"
	cfg.HTTPSAddr = "127.0.0.1:0"
	cfg.MetricsAddr = "0"
	cfg.HealthProbeAddr = "0"
	cfg.ChallengeSecretNamespace = "gated-system"
	cfg.ACME.DirectoryURL = "https://acme.example.com/directory"
	cfg.ACME.Email = "gated@example.com"
	cfg.ACME.AccountSecret = config.SecretRef{Namespace: "gated-system", Name: "gated-acme-account"}
	cfg.Auth.Host = "auth.example.com"
	return cfg
}

func TestTheDataPlaneRunsOnEveryReplica(t *testing.T) {
	mgr := newRecordingManager(t)
	challenges := &http01.SecretStore{
		Client:    mgr.GetClient(),
		Namespace: testConfig().ChallengeSecretNamespace,
	}

	if err := setupDataPlane(mgr, testConfig(), challenges, logr.Discard()); err != nil {
		t.Fatalf("setupDataPlane() = %v", err)
	}

	if len(mgr.added) == 0 {
		t.Fatal("setupDataPlane registered no runnables at all")
	}
	for i, r := range mgr.added {
		if underTheLease(r) {
			t.Errorf("data plane runnable %d (%T) waits for the lease; "+
				"every replica watches, proxies and authorises (ADR 0006), so it must "+
				"implement NeedLeaderElection returning false", i, r)
		}
	}
}

func TestOnlyCertificateIssuanceWaitsForTheLease(t *testing.T) {
	mgr := newRecordingManager(t)
	challenges := &http01.SecretStore{
		Client:    mgr.GetClient(),
		Namespace: testConfig().ChallengeSecretNamespace,
	}

	if err := setupCertificates(mgr, testConfig(), challenges, logr.Discard()); err != nil {
		t.Fatalf("setupCertificates() = %v", err)
	}

	if len(mgr.added) == 0 {
		t.Fatal("setupCertificates registered no runnables at all")
	}
	for i, r := range mgr.added {
		if !underTheLease(r) {
			t.Errorf("certificate runnable %d (%T) runs on every replica; "+
				"ordering is the leader's alone (ADR 0006), or the same certificate "+
				"is ordered once per replica", i, r)
		}
	}
}
