//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// What this layer puts in the cluster, and what it calls the things it makes.
//
// Everything here is the end-to-end suite's own arrangement: a certificate
// authority in the cluster, a DNS server that sends every name to gated, and
// hostnames under example.com that resolve nowhere else (ADR 0024). The live
// layer answers the same names with a real authority instead (ADR 0025).
const (
	clusterName = "gated-e2e"
	kindConfig  = "hack/e2e/kind.yaml"

	// The ACME test server and its DNS server. They are built rather than
	// pulled: see hack/e2e/pebble/Dockerfile for why.
	pebbleImage       = "gated-pebble:e2e"
	challtestsrvImage = "gated-challtestsrv:e2e"
)

// The ports hack/e2e/kind.yaml publishes on the loopback address.
const (
	httpPort  = 31080
	httpsPort = 31443
	idpPort   = 31081
)

// The names the scenarios use. They are example.com subdomains: they resolve
// inside the test cluster, through a DNS server that answers every query with
// gated's address, and nowhere else.
const (
	authHost  = "auth.example.com"
	openHost  = "open.example.com"
	appHost   = "app.example.com"
	tokenHost = "token.example.com"

	// idpBase is where gated reaches the stand-in identity provider, and
	// where it sends a browser to log in. One address for both, because
	// that is how an OAuth application is registered.
	idpBase = "http://mock-idp.gated-e2e.svc.cluster.local:8080"
	idpHost = "mock-idp.gated-e2e.svc.cluster.local:8080"

	oauthClientID = "gated-e2e"
)

// preflight has nothing to ask: this layer contacts nothing outside the
// cluster it makes, so a machine with a container runtime is the whole of what
// it needs, and that is checked separately.
func preflight() (string, error) { return "", nil }

// dialCluster sends every connection to the port kind published for it.
//
// The tests are the browser and the API client at once, and neither of them
// has a resolver that knows about example.com. Rewriting the address here is
// the whole of the arrangement: the name in the request, and therefore the
// name TLS is verified against and the one gated routes on, is the real one.
func dialCluster(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	var target int
	switch {
	case addr == idpHost:
		target = idpPort
	case port == "443":
		target = httpsPort
	case port == "80":
		target = httpPort
	default:
		return nil, fmt.Errorf("nothing in the test cluster answers %s (host %s)", addr, host)
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return dialer.DialContext(ctx, network, net.JoinHostPort(clusterHost, strconv.Itoa(target)))
}

// deploy builds the images, loads them and applies everything.
func deploy(ctx context.Context) error {
	if err := buildImages(ctx, []imageBuild{
		{gatedImage, "Dockerfile"},
		{testsrvImage, "hack/e2e/testsrv/Dockerfile"},
		{pebbleImage, "hack/e2e/pebble/Dockerfile"},
		{challtestsrvImage, "hack/e2e/challtestsrv/Dockerfile"},
	}); err != nil {
		return err
	}

	// The namespace first: everything else is in it or refers to it.
	if err := applyFile(ctx, "config/manager/namespace.yaml"); err != nil {
		return err
	}
	// gated verifies the ACME directory it talks to like any other TLS
	// server, so it has to be told about the test server's certificate
	// authority. Nothing else changes about how it talks to a directory.
	if err := applyPebbleCA(ctx); err != nil {
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
	if err := applyDir(ctx, "hack/e2e/manifests"); err != nil {
		return err
	}
	if err := applyGated(ctx); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "waiting for the deployments")
	for _, d := range []types.NamespacedName{
		{Namespace: gatedNamespace, Name: "challtestsrv"},
		{Namespace: gatedNamespace, Name: "pebble"},
		{Namespace: appNamespace, Name: "backend"},
		{Namespace: appNamespace, Name: "mock-idp"},
		{Namespace: gatedNamespace, Name: "gated"},
	} {
		if err := waitForDeployment(ctx, d); err != nil {
			return err
		}
	}
	return nil
}

// applyPebbleCA copies the test authority's root out of the image and puts it
// where gated's container can read it.
func applyPebbleCA(ctx context.Context) error {
	pem, err := copyFromImage(ctx, pebbleImage, "/test/certs/pebble.minica.pem")
	if err != nil {
		return fmt.Errorf("reading the ACME test server's certificate authority: %w", err)
	}
	if len(bytes.TrimSpace(pem)) == 0 {
		return errors.New("the ACME test server's image holds no certificate authority")
	}

	cm := &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{Namespace: gatedNamespace, Name: "pebble-ca"},
		Data:       map[string]string{"ca.crt": string(pem)},
	}
	return createOrUpdate(ctx, cm)
}

// copyFromImage reads one file out of an image without running it.
func copyFromImage(ctx context.Context, image, path string) ([]byte, error) {
	created, err := exec.CommandContext(ctx, "docker", "create", image).Output()
	if err != nil {
		return nil, err
	}
	id := strings.TrimSpace(string(created))
	defer exec.Command("docker", "rm", "-f", id).Run() //nolint:errcheck // best effort cleanup

	dir, err := os.MkdirTemp("", "gated-e2e")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	local := filepath.Join(dir, filepath.Base(path))
	if out, err := exec.CommandContext(ctx, "docker", "cp", id+":"+path, local).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("%w\n%s", err, out)
	}
	return os.ReadFile(local)
}

// applyGated deploys gated from the manifest an installation would use,
// adding the settings that name this particular deployment.
//
// The base manifest carries no ACME directory, no contact address, no central
// authentication host and no identity provider, because none of those mean
// anything outside one installation (ADR 0009). Supplying them is what an
// overlay is for, and this is the overlay.
func applyGated(ctx context.Context) error {
	var deployment appsv1.Deployment
	if err := decodeFile(filepath.Join(repoRoot, "config/manager/deployment.yaml"), &deployment); err != nil {
		return err
	}
	if len(deployment.Spec.Template.Spec.Containers) != 1 {
		return fmt.Errorf("config/manager/deployment.yaml no longer has exactly one container")
	}
	c := &deployment.Spec.Template.Spec.Containers[0]

	c.Image = gatedImage
	// The image is loaded into the cluster, never pulled.
	c.ImagePullPolicy = corev1.PullIfNotPresent
	c.Args = append(c.Args,
		"--acme-directory-url=https://pebble:14000/dir",
		"--acme-email=gated@example.com",
		"--auth-host="+authHost,
		"--github-client-id="+oauthClientID,
		"--github-client-secret-ref="+gatedNamespace+"/github-oauth/clientSecret",
		"--github-base-url="+idpBase,
		"--github-api-url="+idpBase,
		// Short enough that a test does not spend a minute waiting for
		// a replica to notice it lost the lease.
		"--leader-election-lease-duration=5s",
		"--leader-election-renew-deadline=3s",
		"--leader-election-retry-period=1s",
		"--zap-log-level=debug",
	)
	c.Env = append(c.Env, corev1.EnvVar{
		Name:  "SSL_CERT_FILE",
		Value: "/etc/gated/acme-ca/ca.crt",
	})
	c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{
		Name:      "acme-ca",
		MountPath: "/etc/gated/acme-ca",
		ReadOnly:  true,
	})
	deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes, corev1.Volume{
		Name: "acme-ca",
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: "pebble-ca"},
			},
		},
	})

	return createOrUpdate(ctx, &deployment)
}
