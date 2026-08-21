//go:build envtest

package envtest_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	gatedacme "github.com/yuanying/gated/internal/acme"
	"github.com/yuanying/gated/internal/acme/http01"
	"github.com/yuanying/gated/internal/controller"
	"github.com/yuanying/gated/internal/proxy"
)

// These tests run two gated processes against one API server and one Lease,
// which is the shape ADR 0006 describes: every replica watches, proxies and
// terminates TLS, and only the leader orders certificates.
//
// What they are looking for is the failure that shape invites. Leader election
// is off in a single-replica test and in every unit test, so a runnable that
// waits for a lease it will never hold looks perfectly healthy until a second
// replica exists. Here one of the two replicas is always the follower, and it
// is the follower the assertions are about.

// Lease timings. Short enough that a handover happens inside a test, still far
// enough apart to satisfy the ordering client-go insists on.
const (
	testLeaseDuration = 3 * time.Second
	testRenewDeadline = 2 * time.Second
	testRetryPeriod   = 300 * time.Millisecond
)

// countingIssuer records what it was asked to obtain and returns a
// certificate. Reaching a real directory is the integration suite's job (ADR
// 0007); what matters here is only which replica asked.
type countingIssuer struct {
	mu    sync.Mutex
	hosts [][]string
}

func (c *countingIssuer) Obtain(_ context.Context, hosts []string) (*gatedacme.Keypair, error) {
	c.mu.Lock()
	c.hosts = append(c.hosts, append([]string(nil), hosts...))
	c.mu.Unlock()

	certPEM, keyPEM := mintCert(nil, time.Now().Add(90*24*time.Hour), hosts...)
	return &gatedacme.Keypair{CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

func (c *countingIssuer) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.hosts)
}

func (c *countingIssuer) ordered(host string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, hosts := range c.hosts {
		for _, h := range hosts {
			if h == host {
				return true
			}
		}
	}
	return false
}

// replica is one gated process: its own manager, its own cache, its own
// routing table, competing for the same Lease as its peer.
type replica struct {
	name         string
	mgr          ctrl.Manager
	tables       *proxy.TableStore
	resolver     *controller.ServiceResolver
	certificates *proxy.Certificates
	issuer       *countingIssuer

	stopOnce sync.Once
	cancel   context.CancelFunc
	done     chan error
}

// elected reports whether this replica currently holds the Lease.
func (r *replica) elected() bool {
	select {
	case <-r.mgr.Elected():
		return true
	default:
		return false
	}
}

// stop takes the replica down and waits for it, the way a rolling update or an
// evicted pod would.
func (r *replica) stop(t *testing.T) {
	t.Helper()
	r.stopOnce.Do(func() {
		r.cancel()
		select {
		case <-r.done:
		case <-time.After(30 * time.Second):
			t.Errorf("replica %s did not stop", r.name)
		}
	})
}

// startReplica wires the runnables main wires and starts them with leader
// election on, against a Lease in ns.
//
// Registration goes through the same SetupWithManager calls the binary uses,
// so a controller that forgets to opt out of the lease fails here exactly as
// it would in a cluster.
func startReplica(t *testing.T, name, ns string) *replica {
	t.Helper()

	mgr, err := ctrl.NewManager(restCfg, ctrl.Options{
		Scheme:                 testScheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		// The Lease lives in the test's own namespace, so two tests
		// never compete for the same one.
		LeaderElection:          true,
		LeaderElectionID:        "gated-leader-election",
		LeaderElectionNamespace: ns,
		// The lease is not handed back when a replica goes away. A pod
		// that is evicted, OOM killed or partitioned does not hand
		// anything back either, and it is that case — a stretch with no
		// leader at all — the handover test is about.
		LeaderElectionReleaseOnCancel: false,
		LeaseDuration:                 ptr.To(testLeaseDuration),
		RenewDeadline:                 ptr.To(testRenewDeadline),
		RetryPeriod:                   ptr.To(testRetryPeriod),
		Controller:                    ctrlconfig.Controller{SkipNameValidation: ptr.To(true)},
	})
	if err != nil {
		t.Fatalf("building the manager for replica %s: %v", name, err)
	}

	tables := &proxy.TableStore{}
	routes := &controller.RoutingReconciler{
		Reader:       mgr.GetCache(),
		IngressClass: ingressClass,
		Tables:       tables,
	}
	if err := routes.SetupWithManager(mgr); err != nil {
		t.Fatalf("registering the routing controller: %v", err)
	}

	issuer := &countingIssuer{}
	certs := &controller.CertificateReconciler{
		Client:       mgr.GetClient(),
		Reader:       mgr.GetCache(),
		IngressClass: ingressClass,
		Issuer:       issuer,
		Recorder:     mgr.GetEventRecorderFor("gated-certificates-" + name),
	}
	if err := certs.SetupWithManager(mgr); err != nil {
		t.Fatalf("registering the certificate controller: %v", err)
	}

	r := &replica{
		name:     name,
		mgr:      mgr,
		tables:   tables,
		resolver: &controller.ServiceResolver{Reader: mgr.GetCache()},
		certificates: &proxy.Certificates{
			Tables: tables,
			Store:  &controller.SecretCertificates{Reader: mgr.GetCache()},
		},
		issuer: issuer,
		done:   make(chan error, 1),
	}

	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go func() { r.done <- mgr.Start(ctx) }()
	t.Cleanup(func() { r.stop(t) })

	if !mgr.GetCache().WaitForCacheSync(ctx) {
		t.Fatalf("the cache of replica %s never synced", name)
	}
	return r
}

// frontend serves this replica's routing table over plain HTTP, with the last
// hop redirected at a test backend.
func (r *replica) frontend(t *testing.T, backendAddr string) *httptest.Server {
	t.Helper()

	dialer := &dialRecorder{to: backendAddr}
	front := httptest.NewServer(&proxy.Handler{
		Tables:    r.tables,
		Backends:  r.resolver,
		Transport: &http.Transport{DialContext: dialer.DialContext},
	})
	t.Cleanup(front.Close)
	return front
}

// get asks a frontend for one path on one host.
func get(t *testing.T, front *httptest.Server, host, path string) int {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, front.URL+path, nil)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	req.Host = host
	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatalf("Do() = %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// awaitLeader waits until exactly one of the replicas holds the Lease, and
// returns it together with the one that does not.
func awaitLeader(t *testing.T, a, b *replica) (leader, follower *replica) {
	t.Helper()

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		switch {
		case a.elected() && b.elected():
			t.Fatal("both replicas hold the lease at once")
		case a.elected():
			return a, b
		case b.elected():
			return b, a
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("neither replica took the lease")
	return nil, nil
}

// tlsIngressFor builds an Ingress that routes a host and terminates TLS for it
// out of secretName.
func tlsIngressFor(t *testing.T, ns, name, host, secretName string) *networkingv1.Ingress {
	t.Helper()

	ing := newIngress(ns, name, ingressClass, host, "/", "web", 80)
	ing.Spec.TLS = []networkingv1.IngressTLS{{Hosts: []string{host}, SecretName: secretName}}
	if err := k8sClient.Create(context.Background(), ing); err != nil {
		t.Fatalf("creating the Ingress: %v", err)
	}
	// Namespaces are not collected in envtest, so an Ingress left behind
	// goes on being listed by every suite that builds a routing table.
	t.Cleanup(func() {
		if err := k8sClient.Delete(context.Background(), ing); err != nil {
			t.Logf("deleting the Ingress: %v", err)
		}
	})
	return ing
}

// TestEveryReplicaRoutesWhileOnlyOneOrders is the table in ADR 0006 as a test:
// the follower builds the same routing table as the leader and serves the same
// traffic, and it places no ACME orders at all.
func TestEveryReplicaRoutesWhileOnlyOneOrders(t *testing.T) {
	ns := newNamespace(t)
	backendAddr := newBackend(t, "from the backend")
	newService(t, ns, "web", 80, "http")

	a := startReplica(t, "a", ns)
	b := startReplica(t, "b", ns)
	leader, follower := awaitLeader(t, a, b)

	const host = "ordered.example.com"
	tlsIngressFor(t, ns, "ordered", host, "ordered-tls")

	// Both replicas route it, the follower included. This is the assertion
	// a leader-elected routing controller fails: the follower's table stays
	// empty and every request it is handed is a 404.
	for _, r := range []*replica{leader, follower} {
		front := r.frontend(t, backendAddr)
		waitFor(t, "replica "+r.name+" to route "+host, func() bool {
			return get(t, front, host, "/") == http.StatusOK
		})
	}

	// The certificate is ordered, once, by the replica holding the lease.
	waitFor(t, "the leader to order the certificate", func() bool {
		return leader.issuer.ordered(host)
	})
	if n := follower.issuer.calls(); n != 0 {
		t.Errorf("the follower placed %d ACME order(s); ordering is the leader's alone (ADR 0006)", n)
	}

	// And what the leader obtained reaches the follower through the Secret,
	// which is the only channel between them (ADR 0006).
	waitFor(t, "the follower to serve the certificate the leader obtained", func() bool {
		_, err := follower.certificates.GetCertificate(clientHello(host))
		return err == nil
	})
}

// TestTrafficSurvivesTheLeaderGoingAway covers what ADR 0006 promises about a
// handover: the surviving replica keeps serving throughout, with the
// certificate that is already in its Secret, and only then takes the lease.
func TestTrafficSurvivesTheLeaderGoingAway(t *testing.T) {
	ns := newNamespace(t)
	backendAddr := newBackend(t, "still serving")
	newService(t, ns, "web", 80, "http")

	// A certificate obtained before any of this, as after a restart.
	const host = "steady.example.com"
	cert, pemCert, pemKey := issueSelfSigned(t, host)
	secret := putTLSSecret(t, ns, "steady-tls", pemCert, pemKey)
	tlsIngressFor(t, ns, "steady", host, secret.Name)

	a := startReplica(t, "a", ns)
	b := startReplica(t, "b", ns)
	leader, follower := awaitLeader(t, a, b)

	front := follower.frontend(t, backendAddr)
	waitFor(t, "the follower to route "+host, func() bool {
		return get(t, front, host, "/") == http.StatusOK
	})
	waitFor(t, "the follower to serve the certificate", func() bool {
		_, err := follower.certificates.GetCertificate(clientHello(host))
		return err == nil
	})

	// Keep asking the follower for the whole handover, so that the stretch
	// between the leader going away and the lease expiring — during which
	// the cluster has no leader at all — is a failed request rather than
	// something nobody was looking at.
	var requests, failures atomic.Int64
	stop := make(chan struct{})
	traffic := make(chan struct{})
	go func() {
		defer close(traffic)
		client := front.Client()
		for {
			select {
			case <-stop:
				return
			default:
			}
			req, err := http.NewRequest(http.MethodGet, front.URL+"/", nil)
			if err != nil {
				failures.Add(1)
				return
			}
			req.Host = host
			requests.Add(1)
			resp, err := client.Do(req)
			if err != nil {
				failures.Add(1)
				continue
			}
			if resp.StatusCode != http.StatusOK {
				failures.Add(1)
			}
			resp.Body.Close()

			// TLS is terminated out of the Secret on every
			// handshake, so the certificate is part of what has to
			// keep working while there is no leader.
			if _, err := follower.certificates.GetCertificate(clientHello(host)); err != nil {
				failures.Add(1)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	leader.stop(t)

	waitFor(t, "the follower to take the lease", func() bool { return follower.elected() })

	close(stop)
	<-traffic

	if got := requests.Load(); got < 10 {
		t.Fatalf("only %d requests were made across the handover; the test proves nothing", got)
	}
	if got := failures.Load(); got != 0 {
		t.Errorf("%d of %d requests failed across the handover; a leader change must not disturb traffic (ADR 0006)",
			got, requests.Load())
	}

	// The certificate served afterwards is still the one in the Secret: a
	// handover is not a reissue.
	after, err := follower.certificates.GetCertificate(clientHello(host))
	if err != nil {
		t.Fatalf("GetCertificate() after the handover = _, %v", err)
	}
	if after.Leaf == nil || !after.Leaf.Equal(cert.Leaf) {
		t.Error("the certificate changed across the handover, want the one already in the Secret")
	}
	if n := follower.issuer.calls(); n != 0 {
		t.Errorf("the new leader ordered %d certificate(s); the one in the Secret is still valid (ADR 0005)", n)
	}
}

// TestAChallengePublishedByOneReplicaIsAnsweredByAnother is the wait ADR 0006
// requires, end to end: publishing returns only once another replica — one
// that took its snapshot before the write — answers for the token.
//
// The replica reading here is deliberately primed first. A responder built
// after the write would read the token on its first look and prove nothing
// about propagation.
func TestAChallengePublishedByOneReplicaIsAnsweredByAnother(t *testing.T) {
	ns := newNamespace(t)

	writer := &http01.Solver{
		Store:       &http01.SecretStore{Client: k8sClient, Namespace: ns},
		Propagation: http01.DefaultPropagation,
	}
	// The reader is a separate process's view: its own store, its own
	// snapshot, and the lifetimes the binary runs with.
	reader := &http01.Responder{Source: &http01.SecretStore{Client: k8sClient, Namespace: ns}}

	const token = "primed-snapshot-token"
	if _, ok := reader.KeyAuthorization(context.Background(), "challenge.example.com", token); ok {
		t.Fatalf("the store already holds %q", token)
	}

	ch := gatedacme.Challenge{
		Type:       gatedacme.ChallengeHTTP01,
		Identifier: "challenge.example.com",
		Token:      token,
		Response:   token + ".key-authorization",
	}
	if err := writer.Present(context.Background(), ch); err != nil {
		t.Fatalf("Present() = %v", err)
	}

	// Present has returned, so the ACME client would have accepted the
	// challenge and the CA could arrive now.
	got, ok := reader.KeyAuthorization(context.Background(), ch.Identifier, token)
	if !ok {
		t.Fatal("the replica that did not publish the challenge answers 404 for it; " +
			"the publisher must wait until every replica can read it (ADR 0006)")
	}
	if got != ch.Response {
		t.Errorf("KeyAuthorization() = %q, want %q", got, ch.Response)
	}

	if err := writer.CleanUp(context.Background(), ch); err != nil {
		t.Fatalf("CleanUp() = %v", err)
	}
	t.Cleanup(func() {
		var secret corev1.Secret
		secret.Namespace, secret.Name = ns, http01.DefaultSecretName
		if err := k8sClient.Delete(context.Background(), &secret); err != nil {
			t.Logf("deleting the challenge Secret: %v", err)
		}
	})
}
