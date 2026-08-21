//go:build envtest

// Package envtest_test exercises the generated CRDs against a real API server
// and etcd.
//
// The point is the schema, not the Go types: a fake client accepts anything
// the Go structs can hold, so a marker that is missing or wrong stays
// invisible until a real API server rejects — or fails to reject — a manifest
// (ADR 0007). These tests therefore write the manifests a person would write,
// as YAML, and assert on what the API server does with them.
package envtest_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/yaml"

	gatev1alpha1 "github.com/yuanying/gated/internal/apis/gate/v1alpha1"
)

// crdDir is the directory `make generate` writes the CRDs to. Pointing the
// suite at the committed output means a stale commit fails the suite.
const crdDir = "../../config/crd"

var k8sClient client.Client

func TestMain(m *testing.M) {
	os.Exit(runSuite(m))
}

func runSuite(m *testing.M) int {
	logf.SetLogger(zap.New(zap.WriteTo(io.Discard)))

	testEnv := &envtest.Environment{
		CRDDirectoryPaths:     []string{crdDir},
		ErrorIfCRDPathMissing: true,
	}

	cfg, err := testEnv.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "starting the test environment: %v\n"+
			"Run `make test-envtest`, which fetches the control plane binaries first.\n", err)
		return 1
	}
	defer func() {
		if err := testEnv.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "stopping the test environment: %v\n", err)
		}
	}()

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(gatev1alpha1.AddToScheme(scheme))

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		fmt.Fprintf(os.Stderr, "building the client: %v\n", err)
		return 1
	}

	return m.Run()
}

// newNamespace creates a namespace that lives as long as the test.
func newNamespace(t *testing.T) string {
	t.Helper()

	ns := &corev1.Namespace{}
	ns.SetGenerateName("gated-test-")
	if err := k8sClient.Create(context.Background(), ns); err != nil {
		t.Fatalf("creating a namespace: %v", err)
	}
	t.Cleanup(func() {
		if err := k8sClient.Delete(context.Background(), ns); err != nil {
			t.Logf("deleting namespace %s: %v", ns.GetName(), err)
		}
	})
	return ns.GetName()
}

// object parses a manifest the way kubectl would and places it in ns.
func object(t *testing.T, ns, manifest string) *unstructured.Unstructured {
	t.Helper()

	var content map[string]any
	if err := yaml.Unmarshal([]byte(manifest), &content); err != nil {
		t.Fatalf("parsing the manifest: %v\n%s", err, manifest)
	}
	obj := &unstructured.Unstructured{Object: content}
	obj.SetNamespace(ns)
	return obj
}

// create applies a manifest and returns whatever the API server made of it.
func create(t *testing.T, ns, manifest string) (*unstructured.Unstructured, error) {
	t.Helper()

	obj := object(t, ns, manifest)
	err := k8sClient.Create(context.Background(), obj)
	return obj, err
}

// mustCreate applies a manifest that is expected to be accepted.
func mustCreate(t *testing.T, ns, manifest string) *unstructured.Unstructured {
	t.Helper()

	obj, err := create(t, ns, manifest)
	if err != nil {
		t.Fatalf("Create() = %v, want nil\n%s", err, manifest)
	}
	return obj
}

// field reads a nested string, failing the test when the path is absent.
func field(t *testing.T, obj *unstructured.Unstructured, path ...string) string {
	t.Helper()

	v, found, err := unstructured.NestedString(obj.Object, path...)
	if err != nil {
		t.Fatalf("reading %v: %v", path, err)
	}
	if !found {
		t.Fatalf("%v is absent", path)
	}
	return v
}

// nestedSlice reads a nested list.
func nestedSlice(obj *unstructured.Unstructured, path ...string) ([]any, bool, error) {
	return unstructured.NestedSlice(obj.Object, path...)
}
