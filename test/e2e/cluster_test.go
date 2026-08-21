//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gatev1alpha1 "github.com/yuanying/gated/internal/apis/gate/v1alpha1"
)

// What the cluster is called and what is in it.
const (
	clusterName = "gated-e2e"

	// gatedNamespace is where gated and the test certificate authority
	// run. It is the namespace config/manager names.
	gatedNamespace = "gated-system"
	// appNamespace holds the Ingresses and the workloads behind them, so
	// that the tests exercise routing to somewhere other than where gated
	// itself lives.
	appNamespace = "gated-e2e"

	gatedImage   = "gated:e2e"
	testsrvImage = "gated-testsrv:e2e"
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

// How long the slowest thing here is given.
const (
	clusterTimeout = 10 * time.Minute
	rolloutTimeout = 5 * time.Minute
	settleTimeout  = 3 * time.Minute
	pollInterval   = 2 * time.Second
)

// The cluster the tests share, built once by TestMain.
var (
	restConfig *rest.Config
	k8s        client.Client
	// repoRoot is where the manifests are read from.
	repoRoot string
	// clusterHost is where the node's published ports answer. It is the
	// loopback address when the tests run beside the container runtime,
	// and the node's own address when they run in a container of their
	// own.
	clusterHost = "127.0.0.1"
)

var scheme = runtime.NewScheme()

func init() {
	must(clientgoscheme.AddToScheme(scheme))
	must(apiextensionsv1.AddToScheme(scheme))
	must(gatev1alpha1.AddToScheme(scheme))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	root, err := filepath.Abs("../..")
	if err != nil {
		fmt.Fprintf(os.Stderr, "finding the repository root: %v\n", err)
		return 1
	}
	repoRoot = root

	if err := usable(); err != nil {
		// These tests are opt-in (`make test-e2e`) and take minutes.
		// Somebody who asked for them wants to know why they cannot
		// run, not to be told everything passed.
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), clusterTimeout)
	defer cancel()

	// A cluster left behind by an interrupted run holds the ports and may
	// hold stale objects.
	deleteCluster()
	if err := createCluster(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		deleteCluster()
		return 1
	}
	if !keepCluster() {
		defer deleteCluster()
	} else {
		defer fmt.Fprintf(os.Stderr,
			"GATED_E2E_KEEP_CLUSTER is set; leaving the %q cluster running\n", clusterName)
	}

	if err := deploy(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		describeFailure(ctx)
		return 1
	}
	return m.Run()
}

// usable reports why the tests cannot run, if they cannot.
func usable() error {
	if _, err := exec.LookPath("docker"); err != nil {
		return errors.New("docker is not on PATH; these tests build images and run a kind cluster")
	}
	if out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		return fmt.Errorf("docker is not usable: %w\n%s", err, out)
	}
	return nil
}

func keepCluster() bool { return os.Getenv("GATED_E2E_KEEP_CLUSTER") != "" }

// kind runs the cluster manager. It is pinned by the tool directive in go.mod
// like every other tool this repository uses (ADR 0011), so there is nothing
// to install first.
func kind(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "go", append([]string{"tool", "kind"}, args...)...)
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("kind %s: %w\n%s", strings.Join(args, " "), err, out)
	}
	return out, nil
}

func createCluster(ctx context.Context) error {
	network, err := sharedNetwork()
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "creating the %q cluster\n", clusterName)
	args := []string{"create", "cluster",
		"--name", clusterName,
		"--config", filepath.Join(repoRoot, "hack", "e2e", "kind.yaml"),
		"--wait", "120s",
	}
	if _, err := kind(ctx, args...); err != nil {
		return err
	}

	// Where the cluster answers depends on where the tests are. Beside the
	// container runtime, the node publishes its ports on the loopback
	// address. Inside a container, that loopback belongs to somebody else,
	// and the node is a neighbour on the same network instead.
	kubeconfigArgs := []string{"get", "kubeconfig", "--name", clusterName}
	if network != "" {
		kubeconfigArgs = append(kubeconfigArgs, "--internal")
		addr, err := nodeAddress(ctx, network)
		if err != nil {
			return err
		}
		clusterHost = addr
	}
	raw, err := kind(ctx, kubeconfigArgs...)
	if err != nil {
		return err
	}

	cfg, err := clientcmd.RESTConfigFromKubeConfig(raw)
	if err != nil {
		return fmt.Errorf("reading the cluster's kubeconfig: %w", err)
	}
	// One process talking to one small cluster; the client-go defaults
	// throttle it hard enough to matter while waiting for rollouts.
	cfg.QPS, cfg.Burst = 50, 100
	restConfig = cfg

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("building a client for the cluster: %w", err)
	}
	k8s = c
	return nil
}

// sharedNetwork is the container network the cluster has to join, or the empty
// string when the tests are not in a container.
//
// A cluster on a network of its own is unreachable from a process that is
// itself in a container: the ports it publishes belong to the host's loopback,
// which is not this one. Putting the node on the network these tests are
// already attached to is what makes it a neighbour instead.
func sharedNetwork() (string, error) {
	if _, err := os.Stat("/.dockerenv"); err != nil {
		return "", nil
	}

	self, err := routedAddress()
	if err != nil {
		return "", err
	}
	network, err := networkContaining(self)
	if err != nil {
		return "", err
	}
	// kind reads this rather than a flag.
	if err := os.Setenv("KIND_EXPERIMENTAL_DOCKER_NETWORK", network); err != nil {
		return "", err
	}
	return network, nil
}

// routedAddress is the address this process would leave by, which is the one a
// container on the same network reaches it at. Dialling a UDP address chooses
// a route without sending anything.
func routedAddress() (string, error) {
	conn, err := net.Dial("udp", "192.0.2.1:9")
	if err != nil {
		return "", fmt.Errorf("finding this process's address: %w", err)
	}
	defer conn.Close()
	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return "", err
	}
	return host, nil
}

// networkContaining finds the container network whose subnet holds an address.
func networkContaining(addr string) (string, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return "", fmt.Errorf("%q is not an address", addr)
	}

	out, err := exec.Command("docker", "network", "ls", "--format", "{{.Name}}").Output()
	if err != nil {
		return "", fmt.Errorf("listing container networks: %w", err)
	}
	for _, name := range strings.Fields(string(out)) {
		if name == "host" || name == "none" {
			continue
		}
		raw, err := exec.Command("docker", "network", "inspect", name, "--format", "{{json .IPAM.Config}}").Output()
		if err != nil {
			continue
		}
		var configs []struct {
			Subnet string `json:"subnet"`
		}
		if err := json.Unmarshal(raw, &configs); err != nil {
			continue
		}
		for _, c := range configs {
			_, subnet, err := net.ParseCIDR(c.Subnet)
			if err != nil || subnet == nil {
				continue
			}
			if subnet.Contains(ip) {
				return name, nil
			}
		}
	}
	return "", fmt.Errorf("no container network holds %s; the tests cannot reach a cluster from here", addr)
}

// nodeAddress is where the node answers on a network these tests share.
func nodeAddress(ctx context.Context, network string) (string, error) {
	out, err := exec.CommandContext(ctx, "docker", "inspect", clusterName+"-control-plane",
		"--format", fmt.Sprintf("{{(index .NetworkSettings.Networks %q).IPAddress}}", network)).Output()
	if err != nil {
		return "", fmt.Errorf("reading the node's address on %s: %w", network, err)
	}
	addr := strings.TrimSpace(string(out))
	if addr == "" {
		return "", fmt.Errorf("the node has no address on %s", network)
	}
	return addr, nil
}

func deleteCluster() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	_, _ = kind(ctx, "delete", "cluster", "--name", clusterName)
}

// deploy builds the images, loads them and applies everything.
func deploy(ctx context.Context) error {
	if err := images(ctx); err != nil {
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

// images builds what the tests run and loads it into the cluster, so that no
// node ever has to reach a registry for it.
func images(ctx context.Context) error {
	fmt.Fprintln(os.Stderr, "building images")
	builds := []struct{ tag, dockerfile string }{
		{gatedImage, "Dockerfile"},
		{testsrvImage, "hack/e2e/testsrv/Dockerfile"},
		{pebbleImage, "hack/e2e/pebble/Dockerfile"},
		{challtestsrvImage, "hack/e2e/challtestsrv/Dockerfile"},
	}
	for _, b := range builds {
		cmd := exec.CommandContext(ctx, "docker", "build",
			// Without this the builder attaches a provenance
			// attestation, which turns the result into a manifest
			// list that the cluster's image loader will not take.
			"--provenance=false",
			// And without this an image that is published for
			// several platforms stays a manifest list, which the
			// loader will not take either.
			"--platform", "linux/"+goruntime.GOARCH,
			"--tag", b.tag, "--file", filepath.Join(repoRoot, b.dockerfile), repoRoot)
		cmd.Dir = repoRoot
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("building %s: %w\n%s", b.tag, err, out)
		}
	}

	fmt.Fprintln(os.Stderr, "loading images into the cluster")
	for _, image := range []string{gatedImage, testsrvImage, pebbleImage, challtestsrvImage} {
		if _, err := kind(ctx, "load", "docker-image", "--name", clusterName, image); err != nil {
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

// applyDir applies every manifest in a directory, in name order.
func applyDir(ctx context.Context, dir string) error {
	entries, err := os.ReadDir(filepath.Join(repoRoot, dir))
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		// kustomization.yaml is an index, not an object.
		if e.Name() == "kustomization.yaml" {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		if err := applyFile(ctx, filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}

// applyFile applies every document of one manifest.
func applyFile(ctx context.Context, path string) error {
	raw, err := os.ReadFile(filepath.Join(repoRoot, path))
	if err != nil {
		return err
	}
	decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096)
	for {
		obj := &unstructured.Unstructured{}
		if err := decoder.Decode(obj); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("reading %s: %w", path, err)
		}
		if len(obj.Object) == 0 {
			continue
		}
		if err := createOrUpdate(ctx, obj); err != nil {
			return fmt.Errorf("applying %s: %w", path, err)
		}
	}
}

// createOrUpdate puts an object into the cluster whether or not it is already
// there. A fresh cluster only ever takes the first branch; the second is for
// a run against a cluster somebody kept.
func createOrUpdate(ctx context.Context, obj client.Object) error {
	err := k8s.Create(ctx, obj)
	if err == nil || !apierrors.IsAlreadyExists(err) {
		return err
	}

	existing := obj.DeepCopyObject().(client.Object)
	key := client.ObjectKeyFromObject(obj)
	if err := k8s.Get(ctx, key, existing); err != nil {
		return err
	}
	obj.SetResourceVersion(existing.GetResourceVersion())
	// A Service's cluster IP is assigned once and cannot be sent back
	// empty.
	if svc, ok := obj.(*corev1.Service); ok {
		if current, ok := existing.(*corev1.Service); ok && svc.Spec.ClusterIP == "" {
			svc.Spec.ClusterIP = current.Spec.ClusterIP
		}
	}
	return k8s.Update(ctx, obj)
}

// decodeFile reads a single-document manifest into a typed object.
func decodeFile(path string, into any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096).Decode(into); err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	return nil
}

// waitForCRDs blocks until the API server serves gated's own kinds. Creating
// one before it does is a "no matches for kind" that reads like a typo.
func waitForCRDs(ctx context.Context) error {
	names := []string{
		"networkroles.gate.unstable.cloud",
		"networkrolebindings.gate.unstable.cloud",
		"accesstokens.gate.unstable.cloud",
	}
	for _, name := range names {
		err := poll(ctx, settleTimeout, func(ctx context.Context) (bool, error) {
			var crd apiextensionsv1.CustomResourceDefinition
			if err := k8s.Get(ctx, types.NamespacedName{Name: name}, &crd); err != nil {
				return false, nil
			}
			for _, c := range crd.Status.Conditions {
				if c.Type == apiextensionsv1.Established && c.Status == apiextensionsv1.ConditionTrue {
					return true, nil
				}
			}
			return false, nil
		})
		if err != nil {
			return fmt.Errorf("the %s CRD was never established: %w", name, err)
		}
	}
	return nil
}

// waitForDeployment blocks until every replica of a deployment is available.
func waitForDeployment(ctx context.Context, key types.NamespacedName) error {
	err := poll(ctx, rolloutTimeout, func(ctx context.Context) (bool, error) {
		var d appsv1.Deployment
		if err := k8s.Get(ctx, key, &d); err != nil {
			return false, nil
		}
		want := int32(1)
		if d.Spec.Replicas != nil {
			want = *d.Spec.Replicas
		}
		return d.Status.AvailableReplicas >= want && d.Status.UpdatedReplicas >= want, nil
	})
	if err != nil {
		return fmt.Errorf("%s never became available: %w", key, err)
	}
	return nil
}

// poll runs a condition until it holds, the deadline passes or it fails.
func poll(ctx context.Context, timeout time.Duration, condition func(context.Context) (bool, error)) error {
	deadline, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		ok, err := condition(deadline)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		select {
		case <-deadline.Done():
			return deadline.Err()
		case <-time.After(pollInterval):
		}
	}
}

// describeFailure prints what a deployment that never came up was doing, so
// that a failure in the harness says something without a second run.
func describeFailure(ctx context.Context) {
	var pods corev1.PodList
	if err := k8s.List(ctx, &pods, client.InNamespace(gatedNamespace)); err == nil {
		for i := range pods.Items {
			p := &pods.Items[i]
			fmt.Fprintf(os.Stderr, "pod %s: %s\n", p.Name, p.Status.Phase)
			for _, s := range p.Status.ContainerStatuses {
				fmt.Fprintf(os.Stderr, "  %s ready=%t restarts=%d state=%+v\n",
					s.Name, s.Ready, s.RestartCount, s.State)
			}
			if logs, err := podLogs(ctx, p.Namespace, p.Name); err == nil {
				fmt.Fprintf(os.Stderr, "  logs:\n%s\n", tail(logs, 40))
			}
		}
	}
	var events corev1.EventList
	if err := k8s.List(ctx, &events, client.InNamespace(gatedNamespace)); err == nil {
		for i := range events.Items {
			e := &events.Items[i]
			fmt.Fprintf(os.Stderr, "event %s %s: %s\n", e.Type, e.InvolvedObject.Name, e.Message)
		}
	}
}

// tail returns the last n lines of a log.
func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
