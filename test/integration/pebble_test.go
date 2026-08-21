//go:build integration

package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The images the ACME test server runs from, and the ports they use.
//
// Pebble validates HTTP-01 against port 5002 rather than 80, and resolves the
// names in an order through whatever DNS server it is pointed at. The
// challenge test server is what makes both work without touching any real
// resolver: it answers every A query with one address, so a validation for a
// name nobody owns arrives at the listener these tests start.
const (
	pebbleImage       = "ghcr.io/letsencrypt/pebble:latest"
	challtestsrvImage = "ghcr.io/letsencrypt/pebble-challtestsrv:latest"

	pebbleContainer       = "gated-pebble"
	challtestsrvContainer = "gated-pebble-challtestsrv"

	pebblePort = 14000
	dnsPort    = 8053
	// challengePort is where Pebble comes looking for an HTTP-01 answer.
	challengePort = 5002

	// pebbleDirectoryURL names Pebble the way its certificate does. Where
	// it actually answers is a matter for the dialler.
	pebbleDirectoryURL = "https://localhost:14000/dir"
)

// The directory, once. Starting Pebble costs a couple of seconds and there is
// nothing in these tests that one directory cannot serve.
var (
	pebbleHTTPClient *http.Client
	// pebbleSkip, when set, is why there is no directory to talk to.
	pebbleSkip string
)

func TestMain(m *testing.M) {
	os.Exit(runSuite(m))
}

func runSuite(m *testing.M) int {
	if reason := dockerUnusable(); reason != "" {
		// The layer is opt-in (`make test-integration`), so a machine
		// without a container runtime should say so plainly rather
		// than report failures nobody can act on.
		pebbleSkip = reason
		return m.Run()
	}

	plan, err := plan()
	if err != nil {
		pebbleSkip = err.Error()
		return m.Run()
	}

	defer stopContainers()
	if err := startContainers(plan); err != nil {
		fmt.Fprintf(os.Stderr, "starting the ACME test server: %v\n", err)
		containerLogs()
		return 1
	}

	roots, err := pebbleRoots()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	pebbleHTTPClient = newPebbleClient(roots, plan.pebbleAddr)
	if err := waitForDirectory(pebbleHTTPClient); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		containerLogs()
		return 1
	}
	return m.Run()
}

// pebble hands a test the directory to order from.
//
// Everything about it is local: no test in this repository ever contacts a
// real CA, both because it would make the suite depend on the network and
// because failures against Let's Encrypt cost a rate limit that takes a week
// to come back (ADR 0007).
func pebble(t *testing.T) (string, *http.Client) {
	t.Helper()
	if pebbleSkip != "" {
		t.Skip(pebbleSkip)
	}
	return pebbleDirectoryURL, pebbleHTTPClient
}

// layout says how the containers and this process reach each other.
//
// Validation has to travel in both directions: the test process orders from
// Pebble, and Pebble comes back to the listener the test process opened. Which
// addresses those are depends on whether the tests run beside the container
// runtime or inside a container of their own.
type layout struct {
	// network is the value passed to `docker run --network`.
	network string
	// selfAddr is how a container reaches this process.
	selfAddr string
	// pebbleAddr is how this process reaches Pebble.
	pebbleAddr string
	// dnsAddr is how Pebble reaches the challenge DNS server.
	dnsAddr string
}

func plan() (*layout, error) {
	if !inContainer() {
		// Everything shares the host's loopback.
		return &layout{
			network:    "host",
			selfAddr:   "127.0.0.1",
			pebbleAddr: net.JoinHostPort("127.0.0.1", fmt.Sprint(pebblePort)),
			dnsAddr:    net.JoinHostPort("127.0.0.1", fmt.Sprint(dnsPort)),
		}, nil
	}

	// The tests are themselves in a container, so the host's loopback is
	// somebody else's. Put the containers on the network this one is
	// already attached to and address everything by container address.
	self, err := routedAddress()
	if err != nil {
		return nil, err
	}
	network, err := networkContaining(self)
	if err != nil {
		return nil, err
	}
	return &layout{network: network, selfAddr: self}, nil
}

func inContainer() bool {
	_, err := os.Stat("/.dockerenv")
	return err == nil
}

// routedAddress is the address of the interface this process would leave by,
// which is the one a container on the same network reaches it at. Dialling a
// UDP address chooses a route without sending anything.
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

// networkContaining finds the docker network whose subnet holds an address.
func networkContaining(addr string) (string, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return "", fmt.Errorf("%q is not an address", addr)
	}

	out, err := exec.Command("docker", "network", "ls", "--format", "{{.Name}}").Output()
	if err != nil {
		return "", fmt.Errorf("listing docker networks: %w", err)
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
			Subnet string `json:"Subnet"`
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
	return "", fmt.Errorf("no docker network holds %s; the tests cannot arrange for Pebble to reach them", addr)
}

func dockerUnusable() string {
	if _, err := exec.LookPath("docker"); err != nil {
		return "docker is not on PATH; these tests need it to run Pebble"
	}
	if out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		return fmt.Sprintf("docker is not usable: %v\n%s", err, out)
	}
	return ""
}

// startContainers brings up the challenge DNS server and Pebble.
func startContainers(plan *layout) error {
	// The challenge server first: Pebble refuses to start if the DNS
	// server it was given is not answering.
	if err := run(plan, challtestsrvContainer, challtestsrvImage, nil, []string{
		// Its own challenge responders are turned off. Answering
		// HTTP-01 is what gated is here to do.
		"-http01=", "-https01=", "-tlsalpn01=", "-doh=",
		// Every name in an order resolves to this process.
		"-defaultIPv4=" + plan.selfAddr,
		// IPv4 only, so a validation cannot arrive over an address the
		// test listener is not bound to.
		"-defaultIPv6=",
	}); err != nil {
		return err
	}
	if plan.dnsAddr == "" {
		addr, err := containerAddress(challtestsrvContainer)
		if err != nil {
			return err
		}
		plan.dnsAddr = net.JoinHostPort(addr, fmt.Sprint(dnsPort))
	}

	if err := run(plan, pebbleContainer, pebbleImage, []string{
		// Without this Pebble sleeps a random moment before each
		// validation, which turns a two second test into a twenty
		// second one.
		"PEBBLE_VA_NOSLEEP=1",
		// And without this it rejects one nonce in twenty on purpose.
		// The client retries, but the retries make a real failure
		// harder to read for no gain here.
		"PEBBLE_WFE_NONCEREJECT=0",
	}, []string{
		"-config", "/test/config/pebble-config.json",
		"-dnsserver", plan.dnsAddr,
	}); err != nil {
		return err
	}
	if plan.pebbleAddr == "" {
		addr, err := containerAddress(pebbleContainer)
		if err != nil {
			return err
		}
		plan.pebbleAddr = net.JoinHostPort(addr, fmt.Sprint(pebblePort))
	}
	return nil
}

func run(plan *layout, name, image string, env, args []string) error {
	// A container left behind by an interrupted run would hold the name
	// and, on the host network, the ports.
	_ = exec.Command("docker", "rm", "-f", name).Run()

	argv := []string{"run", "--detach", "--name", name, "--network", plan.network}
	for _, e := range env {
		argv = append(argv, "--env", e)
	}
	argv = append(argv, image)
	argv = append(argv, args...)

	if out, err := exec.Command("docker", argv...).CombinedOutput(); err != nil {
		return fmt.Errorf("starting %s: %w\n%s", name, err, out)
	}
	return nil
}

func containerAddress(name string) (string, error) {
	out, err := exec.Command("docker", "inspect", name,
		"--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}").Output()
	if err != nil {
		return "", fmt.Errorf("reading the address of %s: %w", name, err)
	}
	for _, addr := range strings.Fields(string(out)) {
		if addr != "" {
			return addr, nil
		}
	}
	return "", fmt.Errorf("%s has no address", name)
}

func stopContainers() {
	for _, name := range []string{pebbleContainer, challtestsrvContainer} {
		_ = exec.Command("docker", "rm", "-f", name).Run()
	}
}

func containerLogs() {
	for _, name := range []string{pebbleContainer, challtestsrvContainer} {
		if out, err := exec.Command("docker", "logs", "--tail", "40", name).CombinedOutput(); err == nil {
			fmt.Fprintf(os.Stderr, "%s logs:\n%s\n", name, out)
		}
	}
}

// newPebbleClient trusts Pebble's CA and sends every request to wherever
// Pebble actually is, while still verifying the name its certificate carries.
//
// Trusting the CA explicitly rather than skipping verification keeps the test
// honest about what the client does: gated verifies the directory it talks to,
// and a test that turned that off would not notice if it stopped.
func newPebbleClient(roots *x509.CertPool, addr string) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			},
		},
	}
}

// pebbleRoots reads the CA Pebble signs with out of the container.
func pebbleRoots() (*x509.CertPool, error) {
	dir, err := os.MkdirTemp("", "gated-pebble")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, "pebble.minica.pem")
	out, err := exec.Command("docker", "cp", pebbleContainer+":/test/certs/pebble.minica.pem", path).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("reading Pebble's CA certificate: %w\n%s", err, out)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("%s holds no certificate", path)
	}
	return pool, nil
}

// waitForDirectory blocks until the directory answers, so that a failure is
// about the exchange rather than about a container that had not finished
// starting.
func waitForDirectory(client *http.Client) error {
	deadline := time.Now().Add(60 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		resp, err := client.Get(pebbleDirectoryURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			last = fmt.Errorf("the directory answered %s", resp.Status)
		} else {
			last = err
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("Pebble never became ready: %w", last)
}

// listen opens the plain listener the challenge is answered on, failing with
// something readable when the port is already taken.
func listen(t *testing.T, handler http.Handler) {
	t.Helper()

	addr := fmt.Sprintf(":%d", challengePort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("binding the challenge listener on %s: %v\n"+
			"Something else is using the port Pebble validates against.", addr, err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { server.Close() })
}
