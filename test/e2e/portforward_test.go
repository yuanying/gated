//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

// forward opens a tunnel to one replica and returns the local address that
// reaches it.
//
// Addressing a single replica is the only way to ask "can this one answer?".
// Through the Service the answer would come from whichever replica the
// cluster picked, which is exactly the thing that must not be left to chance
// (ADR 0015).
func forward(t *testing.T, ctx context.Context, pod corev1.Pod, port int) string {
	t.Helper()

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		t.Fatalf("building a clientset: %v", err)
	}
	transport, upgrader, err := spdy.RoundTripperFor(restConfig)
	if err != nil {
		t.Fatalf("building a port forward transport: %v", err)
	}

	url := clientset.CoreV1().RESTClient().Post().
		Resource("pods").Namespace(pod.Namespace).Name(pod.Name).
		SubResource("portforward").URL()
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, url)

	stop := make(chan struct{})
	ready := make(chan struct{})
	forwarder, err := portforward.New(dialer,
		[]string{fmt.Sprintf("0:%d", port)}, stop, ready, io.Discard, os.Stderr)
	if err != nil {
		t.Fatalf("preparing a port forward to %s: %v", pod.Name, err)
	}

	failed := make(chan error, 1)
	go func() { failed <- forwarder.ForwardPorts() }()
	t.Cleanup(func() { close(stop) })

	select {
	case <-ready:
	case err := <-failed:
		t.Fatalf("forwarding to %s: %v", pod.Name, err)
	case <-ctx.Done():
		t.Fatalf("forwarding to %s: %v", pod.Name, ctx.Err())
	case <-time.After(30 * time.Second):
		t.Fatalf("the port forward to %s never became ready", pod.Name)
	}

	ports, err := forwarder.GetPorts()
	if err != nil || len(ports) == 0 {
		t.Fatalf("reading the forwarded port for %s: %v", pod.Name, err)
	}
	return fmt.Sprintf("127.0.0.1:%d", ports[0].Local)
}
