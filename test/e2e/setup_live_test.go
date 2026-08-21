//go:build live

package e2e

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

// What this layer puts in the cluster, and where it reaches for the rest.
//
// The end-to-end suite runs a certificate authority of its own and answers
// every name from a DNS server it controls (ADR 0024). This one has neither:
// the authority is on the internet, the name is in somebody's real zone, and
// the address the validation arrives at is the node's own (ADR 0025).
const (
	clusterName = "gated-live"
	kindConfig  = "hack/live/kind.yaml"

	// recordPrefix begins every name this layer creates. It is the only
	// thing that tells a leftover from a real record, so it is fixed and
	// it is never used for anything else.
	recordPrefix = "gated-live-"

	// stagingDirectory is where a run goes unless it is told otherwise,
	// twice. Its rate limits are generous and its certificates are trusted
	// by nobody, which is what makes it the right place to find out
	// whether an order completes.
	stagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory"

	// The stand-in identity provider, reused from the end-to-end suite.
	// gated refuses to start without a provider (ADR 0009) and no scenario
	// here logs in, so this one is present and never visited.
	idpBase       = "http://mock-idp.gated-e2e.svc.cluster.local:8080"
	oauthClientID = "gated-e2e"

	// ingressName and secretName are what the scenario applies and reads.
	ingressName = "live"
	secretName  = "live-tls"
)

// The surroundings this layer needs, all of them named and none of them with
// a default. Everything here describes one person's zone and one person's
// network; a default would be a guess about somebody else's (ADR 0025).
const (
	envZone        = "GATED_LIVE_ZONE"
	envToken       = "CLOUDFLARE_API_TOKEN"
	envNetwork     = "GATED_LIVE_IPV6_NETWORK"
	envEmail       = "GATED_LIVE_ACME_EMAIL"
	envDirectory   = "GATED_LIVE_ACME_DIRECTORY"
	envNonStaging  = "GATED_LIVE_ACME_ALLOW_NONSTAGING"
	envKeepRecords = "GATED_LIVE_KEEP_RECORDS"
)

// live is what preflight worked out and deploy then arranged.
var live struct {
	zone      string
	token     string
	network   string
	email     string
	directory string

	// host is the name a certificate is ordered for, different on every
	// run so that one run's order cannot be answered by another's leftover.
	host string
	// authHost is the central authentication host gated requires. Nothing
	// resolves it and nothing visits it: no scenario here logs in.
	authHost string
	// address is the node's globally routable address, where the
	// certificate authority arrives.
	address string
}

// preflight reports why this layer has nothing to do, if it has nothing to do.
//
// Missing surroundings are a skip and not a failure. Somebody without a zone
// to edit and an address the internet can reach cannot run this, and that says
// nothing about gated.
func preflight() (string, error) {
	live.zone = os.Getenv(envZone)
	live.token = os.Getenv(envToken)
	live.network = os.Getenv(envNetwork)
	live.email = os.Getenv(envEmail)

	var missing []string
	for _, needed := range []struct{ name, value string }{
		{envZone, live.zone},
		{envToken, live.token},
		{envNetwork, live.network},
		{envEmail, live.email},
	} {
		if strings.TrimSpace(needed.value) == "" {
			missing = append(missing, needed.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Sprintf(
			"the live verification needs %s: a DNS zone it may add a name to, a token that "+
				"may edit it, a container network carrying globally routable addresses, and "+
				"a contact address for the ACME account. None of them have defaults (ADR 0025).",
			strings.Join(missing, ", ")), nil
	}

	live.directory = os.Getenv(envDirectory)
	switch {
	case live.directory == "":
		live.directory = stagingDirectory
	case live.directory != stagingDirectory && os.Getenv(envNonStaging) == "":
		// Two separate statements of intent. A production directory
		// rate-limits by the week, so a run started by accident is not
		// undone by starting the right one.
		return "", fmt.Errorf("%s names a directory other than staging; set %s as well to confirm that "+
			"spending its rate limit is meant (ADR 0025)", envDirectory, envNonStaging)
	}

	suffix, err := uniqueSuffix()
	if err != nil {
		return "", err
	}
	live.host = recordPrefix + suffix + "." + live.zone
	live.authHost = "auth." + live.host
	return "", nil
}

// uniqueSuffix is what makes one run's name its own.
func uniqueSuffix() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("choosing a name for this run: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// dialCluster sends a connection to the node, keeping the name in the request.
//
// The name resolves for real here — that is the point of the layer — but it
// resolves to an address this process may have no route to, and asking the
// certificate authority's path to also be the test's would confuse a failure
// of one with a failure of the other. So the name travels and the address
// does not, as in the end-to-end suite.
func dialCluster(ctx context.Context, network, addr string) (net.Conn, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if port != "80" && port != "443" {
		return nil, fmt.Errorf("nothing in the live cluster answers port %s", port)
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return dialer.DialContext(ctx, network, net.JoinHostPort(clusterHost, port))
}

// deploy puts gated in the cluster, gives the node a name on the internet and
// waits until that name resolves.
//
// The name is made first so that it has the whole of the image build to spread
// before anything asks a certificate authority to resolve it.
func deploy(ctx context.Context) error {
	if err := attachNode(ctx); err != nil {
		return err
	}
	if err := publishName(ctx); err != nil {
		return err
	}

	if err := buildImages(ctx, []imageBuild{
		{gatedImage, "Dockerfile"},
		{testsrvImage, "hack/e2e/testsrv/Dockerfile"},
	}); err != nil {
		return err
	}

	if err := applyFile(ctx, "config/manager/namespace.yaml"); err != nil {
		return err
	}
	if err := applyDir(ctx, "config/crd"); err != nil {
		return err
	}
	if err := waitForCRDs(ctx); err != nil {
		return err
	}
	if err := applyDir(ctx, "config/rbac"); err != nil {
		return err
	}
	if err := applyFile(ctx, "config/manager/ingressclass.yaml"); err != nil {
		return err
	}
	// The application behind the Ingress, the stand-in identity provider
	// and its client secret, exactly as the end-to-end suite has them.
	// None of it is what this layer is about, and none of it is worth a
	// second copy.
	if err := applyFile(ctx, "hack/e2e/manifests/00-namespace.yaml"); err != nil {
		return err
	}
	if err := applyFile(ctx, "hack/e2e/manifests/30-testsrv.yaml"); err != nil {
		return err
	}
	if err := applyGated(ctx); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "waiting for the deployments")
	for _, d := range []types.NamespacedName{
		{Namespace: appNamespace, Name: "backend"},
		{Namespace: appNamespace, Name: "mock-idp"},
		{Namespace: gatedNamespace, Name: "gated"},
	} {
		if err := waitForDeployment(ctx, d); err != nil {
			return err
		}
	}

	return awaitResolution(ctx)
}

// attachNode puts the node on the network that carries globally routable
// addresses and works out where it now answers.
//
// When these tests run in a container of their own the cluster is already on
// the network they share with it, which may well be this one; joining a
// network twice is an error rather than a no-op, so it is only done when the
// node is not there yet.
func attachNode(ctx context.Context) error {
	node := clusterName + "-control-plane"

	attached, err := onNetwork(ctx, node, live.network)
	if err != nil {
		return err
	}
	if !attached {
		fmt.Fprintf(os.Stderr, "attaching the node to the %s network\n", live.network)
		if out, err := exec.CommandContext(ctx, "docker", "network", "connect",
			live.network, node).CombinedOutput(); err != nil {
			return fmt.Errorf("attaching the node to %s: %w\n%s", live.network, err, out)
		}
	}

	v6, err := nodeField(ctx, node, live.network, "GlobalIPv6Address")
	if err != nil {
		return err
	}
	if v6 == "" {
		return fmt.Errorf("the node has no address on %s that a certificate authority could reach; "+
			"the network has to carry globally routable IPv6", live.network)
	}
	ip := net.ParseIP(v6)
	if ip == nil || !ip.IsGlobalUnicast() || ip[0]&0xfe == 0xfc {
		return fmt.Errorf("the node's address on %s is not globally routable", live.network)
	}
	live.address = v6

	// Where this process reaches gated. Not the same address: the node's
	// public one may have no route from here, and the point of dialling it
	// from the test is to read gated's answer, not to prove reachability.
	v4, err := nodeField(ctx, node, live.network, "IPAddress")
	if err != nil {
		return err
	}
	switch {
	case v4 != "":
		clusterHost = v4
	default:
		clusterHost = v6
	}
	return nil
}

// onNetwork reports whether a container is already on a network.
func onNetwork(ctx context.Context, container, network string) (bool, error) {
	out, err := exec.CommandContext(ctx, "docker", "inspect", container,
		"--format", "{{range $name, $_ := .NetworkSettings.Networks}}{{$name}} {{end}}").Output()
	if err != nil {
		return false, fmt.Errorf("reading the node's networks: %w", err)
	}
	for _, name := range strings.Fields(string(out)) {
		if name == network {
			return true, nil
		}
	}
	return false, nil
}

// nodeField reads one of the node's settings on one network.
func nodeField(ctx context.Context, container, network, field string) (string, error) {
	out, err := exec.CommandContext(ctx, "docker", "inspect", container,
		"--format", fmt.Sprintf("{{(index .NetworkSettings.Networks %q).%s}}", network, field)).Output()
	if err != nil {
		return "", fmt.Errorf("reading the node's %s on %s: %w", field, network, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// publishName gives the node's address a name in the zone, having first swept
// away anything an earlier run left behind.
//
// The sweep is what makes a run that was killed outright recoverable. Nothing
// else removes those records, and the prefix is what identifies them.
func publishName(ctx context.Context) error {
	zone, err := openZone(ctx, live.token, live.zone)
	if err != nil {
		return err
	}
	stale, err := zone.records(ctx, recordPrefix)
	if err != nil {
		return err
	}
	for _, r := range stale {
		fmt.Fprintf(os.Stderr, "removing a %s record an earlier run left behind\n", r.Type)
		if err := zone.remove(ctx, r.ID); err != nil {
			return err
		}
	}

	id, err := zone.add(ctx, live.host, live.address)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "published %s\n", live.host)

	withdraw := func() {
		if os.Getenv(envKeepRecords) != "" {
			fmt.Fprintf(os.Stderr, "%s is set; leaving %s in the zone\n", envKeepRecords, live.host)
			return
		}
		// Its own context: the run's may already have been cancelled,
		// and a record has to go whichever way the run ended.
		remove, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := zone.remove(remove, id); err != nil {
			fmt.Fprintf(os.Stderr, "the name %s is still in the zone: %v\n", live.host, err)
			return
		}
		fmt.Fprintf(os.Stderr, "withdrew %s\n", live.host)
	}
	cleanups = append(cleanups, withdraw)

	// A signal does not run a deferred function, and the whole point of
	// the prefix is that this one sometimes fails to run. Catching the two
	// ordinary ones means the ordinary interruption still cleans up.
	interrupted := make(chan os.Signal, 1)
	signal.Notify(interrupted, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-interrupted
		fmt.Fprintln(os.Stderr, "interrupted")
		runCleanups()
		if !keepCluster() {
			deleteCluster()
		}
		os.Exit(1)
	}()
	return nil
}

// awaitResolution waits until the name answers with the address, because an
// order placed before it does spends a failure and a backoff to learn nothing.
func awaitResolution(ctx context.Context) error {
	fmt.Fprintf(os.Stderr, "waiting for %s to resolve\n", live.host)
	resolver := &net.Resolver{}
	return poll(ctx, settleTimeout, func(ctx context.Context) (bool, error) {
		addrs, err := resolver.LookupIP(ctx, "ip6", live.host)
		if err != nil {
			return false, nil
		}
		for _, a := range addrs {
			if a.String() == live.address {
				return true, nil
			}
		}
		return false, nil
	})
}

// applyGated deploys gated from the manifest an installation would use, with
// the settings that name this particular run.
//
// Two things differ from the end-to-end suite's overlay beyond the directory
// it talks to. gated is on the node's own network namespace and holds the
// node's ports 80 and 443, because a certificate authority on the internet
// arrives at the node's address and asks for port 80 by name — there is no
// port to choose. And there is one replica rather than two, because two of
// them on one node cannot both hold that port. What several replicas do
// between them is the end-to-end suite's subject (ADR 0024), not this one's.
func applyGated(ctx context.Context) error {
	var deployment appsv1.Deployment
	if err := decodeFile(filepath.Join(repoRoot, "config/manager/deployment.yaml"), &deployment); err != nil {
		return err
	}
	if len(deployment.Spec.Template.Spec.Containers) != 1 {
		return fmt.Errorf("config/manager/deployment.yaml no longer has exactly one container")
	}

	one := int32(1)
	deployment.Spec.Replicas = &one
	pod := &deployment.Spec.Template.Spec
	pod.HostNetwork = true
	// Cluster DNS is still what resolves the API server and the identity
	// provider; without this a host-networked pod uses the node's resolver
	// and finds neither.
	pod.DNSPolicy = corev1.DNSClusterFirstWithHostNet
	// Ports below 1024 need the capability to bind them, and a capability
	// survives exec for root and not for anybody else. This is the one
	// place gated runs as root, and it is a cluster that exists for the
	// length of one test.
	root := int64(0)
	pod.SecurityContext.RunAsNonRoot = nil
	pod.SecurityContext.RunAsUser = &root
	pod.SecurityContext.RunAsGroup = &root

	c := &deployment.Spec.Template.Spec.Containers[0]
	c.Image = gatedImage
	c.ImagePullPolicy = corev1.PullIfNotPresent
	c.SecurityContext.Capabilities.Add = []corev1.Capability{"NET_BIND_SERVICE"}
	for i := range c.Ports {
		switch c.Ports[i].Name {
		case "http":
			c.Ports[i].ContainerPort = 80
		case "https":
			c.Ports[i].ContainerPort = 443
		}
	}
	c.Args = append(c.Args,
		"--http-addr=:80",
		"--https-addr=:443",
		"--acme-directory-url="+live.directory,
		"--acme-email="+live.email,
		"--auth-host="+live.authHost,
		"--github-client-id="+oauthClientID,
		"--github-client-secret-ref="+gatedNamespace+"/github-oauth/clientSecret",
		"--github-base-url="+idpBase,
		"--github-api-url="+idpBase,
		"--zap-log-level=debug",
	)

	return createOrUpdate(ctx, &deployment)
}
