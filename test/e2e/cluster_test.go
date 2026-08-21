//go:build e2e || live

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

// Where things live in the cluster, whichever authority a run is against.
const (
	// gatedNamespace is where gated runs, and where a test certificate
	// authority runs alongside it when there is one. It is the namespace
	// config/manager names.
	gatedNamespace = "gated-system"
	// appNamespace holds the Ingresses and the workloads behind them, so
	// that the tests exercise routing to somewhere other than where gated
	// itself lives.
	appNamespace = "gated-e2e"

	gatedImage   = "gated:e2e"
	testsrvImage = "gated-testsrv:e2e"
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
	// skipReason is why this run has nothing to do, set by a preflight
	// that found the surroundings the layer needs to be missing. The
	// scenarios read it and skip; a run that cannot happen is not a run
	// that passed.
	skipReason string
	// cleanups undo whatever a layer made outside the cluster. A cluster
	// goes away whole, but a name in somebody's zone does not (ADR 0025),
	// so the layer that makes one appends the removal here.
	cleanups []func()
)

// runCleanups undoes what a layer registered, in reverse, once the run is over.
func runCleanups() {
	for i := len(cleanups) - 1; i >= 0; i-- {
		cleanups[i]()
	}
	cleanups = nil
}

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

	// Asked before anything is created, because a layer that cannot run
	// here must not leave a cluster behind saying so.
	if reason, err := preflight(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	} else if reason != "" {
		fmt.Fprintf(os.Stderr, "%s\n", reason)
		skipReason = reason
		return m.Run()
	}

	if err := usable(); err != nil {
		// These tests are opt-in (`make test-e2e`) and take minutes.
		// Somebody who asked for them wants to know why they cannot
		// run, not to be told everything passed.
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), clusterTimeout)
	defer cancel()

	defer runCleanups()

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
		"--config", filepath.Join(repoRoot, kindConfig),
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

// imageBuild is one image the cluster needs and the file that describes it.
type imageBuild struct{ tag, dockerfile string }

// buildImages builds what a run needs and loads it into the cluster, so that
// no node ever has to reach a registry for it.
func buildImages(ctx context.Context, builds []imageBuild) error {
	fmt.Fprintln(os.Stderr, "building images")
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
	for _, b := range builds {
		if _, err := kind(ctx, "load", "docker-image", "--name", clusterName, b.tag); err != nil {
			return err
		}
	}
	return nil
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
