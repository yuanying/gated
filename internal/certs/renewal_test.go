package certs_test

import (
	"testing"
	"time"

	"github.com/yuanying/gated/internal/certs"
)

// day and the reference instant keep the table readable. Nothing here reads
// the wall clock: "now" is an input (ADR 0007).
const day = 24 * time.Hour

var now = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

// leCert is the shape the certificates gated deals with have: a ninety day
// lifetime, which puts the renewal threshold at thirty days.
func leCert(t *testing.T, remaining time.Duration, hosts ...string) certs.Material {
	t.Helper()
	notAfter := now.Add(remaining)
	return issue(t, notAfter.Add(-90*day), notAfter, hosts...)
}

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name       string
		material   func(t *testing.T) *certs.Material
		hosts      []string
		wantRenew  bool
		wantUsable bool
		wantReason certs.Reason
	}{
		{
			name:       "no certificate at all",
			material:   func(*testing.T) *certs.Material { return nil },
			hosts:      []string{"app.example.com"},
			wantRenew:  true,
			wantUsable: false,
			wantReason: certs.ReasonMissing,
		},
		{
			name:       "the Secret exists but holds nothing",
			material:   func(*testing.T) *certs.Material { return &certs.Material{} },
			hosts:      []string{"app.example.com"},
			wantRenew:  true,
			wantUsable: false,
			wantReason: certs.ReasonMissing,
		},
		{
			name: "the certificate is there but the key is not",
			material: func(t *testing.T) *certs.Material {
				m := leCert(t, 60*day, "app.example.com")
				m.KeyPEM = nil
				return &m
			},
			hosts:      []string{"app.example.com"},
			wantRenew:  true,
			wantUsable: false,
			wantReason: certs.ReasonMissing,
		},
		{
			name: "the certificate does not parse",
			material: func(*testing.T) *certs.Material {
				return &certs.Material{CertPEM: []byte("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n"), KeyPEM: []byte("x")}
			},
			hosts:      []string{"app.example.com"},
			wantRenew:  true,
			wantUsable: false,
			wantReason: certs.ReasonMalformed,
		},
		{
			name: "the certificate is not PEM at all",
			material: func(*testing.T) *certs.Material {
				return &certs.Material{CertPEM: []byte("just some bytes"), KeyPEM: []byte("and some more")}
			},
			hosts:      []string{"app.example.com"},
			wantRenew:  true,
			wantUsable: false,
			wantReason: certs.ReasonMalformed,
		},
		{
			name: "the key belongs to a different certificate",
			material: func(t *testing.T) *certs.Material {
				m := leCert(t, 60*day, "app.example.com")
				m.KeyPEM = otherKey(t)
				return &m
			},
			hosts:      []string{"app.example.com"},
			wantRenew:  true,
			wantUsable: false,
			wantReason: certs.ReasonMalformed,
		},
		{
			name: "a fresh certificate covering the host",
			material: func(t *testing.T) *certs.Material {
				m := leCert(t, 89*day, "app.example.com")
				return &m
			},
			hosts:      []string{"app.example.com"},
			wantRenew:  false,
			wantUsable: true,
			wantReason: certs.ReasonUpToDate,
		},
		{
			name: "exactly at the threshold, with the threshold still to spend",
			material: func(t *testing.T) *certs.Material {
				m := leCert(t, 30*day, "app.example.com")
				return &m
			},
			hosts:      []string{"app.example.com"},
			wantRenew:  false,
			wantUsable: true,
			wantReason: certs.ReasonUpToDate,
		},
		{
			name: "one instant past the threshold",
			material: func(t *testing.T) *certs.Material {
				m := leCert(t, 30*day-time.Nanosecond, "app.example.com")
				return &m
			},
			hosts:      []string{"app.example.com"},
			wantRenew:  true,
			wantUsable: true,
			wantReason: certs.ReasonExpiringSoon,
		},
		{
			name: "expiring in an hour is still usable",
			material: func(t *testing.T) *certs.Material {
				m := leCert(t, time.Hour, "app.example.com")
				return &m
			},
			hosts:      []string{"app.example.com"},
			wantRenew:  true,
			wantUsable: true,
			wantReason: certs.ReasonExpiringSoon,
		},
		{
			name: "expiring exactly now",
			material: func(t *testing.T) *certs.Material {
				m := leCert(t, 0, "app.example.com")
				return &m
			},
			hosts:      []string{"app.example.com"},
			wantRenew:  true,
			wantUsable: false,
			wantReason: certs.ReasonExpired,
		},
		{
			name: "expired a day ago",
			material: func(t *testing.T) *certs.Material {
				m := leCert(t, -day, "app.example.com")
				return &m
			},
			hosts:      []string{"app.example.com"},
			wantRenew:  true,
			wantUsable: false,
			wantReason: certs.ReasonExpired,
		},
		{
			name: "not valid yet",
			material: func(t *testing.T) *certs.Material {
				m := issue(t, now.Add(time.Hour), now.Add(90*day), "app.example.com")
				return &m
			},
			hosts:      []string{"app.example.com"},
			wantRenew:  true,
			wantUsable: false,
			wantReason: certs.ReasonNotYetValid,
		},
		{
			name: "one of the required hosts is missing from the SAN",
			material: func(t *testing.T) *certs.Material {
				m := leCert(t, 80*day, "app.example.com")
				return &m
			},
			hosts:      []string{"app.example.com", "api.example.com"},
			wantRenew:  true,
			wantUsable: false,
			wantReason: certs.ReasonHostsNotCovered,
		},
		{
			name: "the SAN carries more hosts than are required",
			material: func(t *testing.T) *certs.Material {
				m := leCert(t, 80*day, "app.example.com", "api.example.com", "old.example.com")
				return &m
			},
			hosts:      []string{"app.example.com", "api.example.com"},
			wantRenew:  false,
			wantUsable: true,
			wantReason: certs.ReasonUpToDate,
		},
		{
			name: "a wildcard in the SAN covers the required host",
			material: func(t *testing.T) *certs.Material {
				m := leCert(t, 80*day, "*.example.com")
				return &m
			},
			hosts:      []string{"app.example.com"},
			wantRenew:  false,
			wantUsable: true,
			wantReason: certs.ReasonUpToDate,
		},
		{
			name: "a wildcard does not cover a deeper label",
			material: func(t *testing.T) *certs.Material {
				m := leCert(t, 80*day, "*.example.com")
				return &m
			},
			hosts:      []string{"a.b.example.com"},
			wantRenew:  true,
			wantUsable: false,
			wantReason: certs.ReasonHostsNotCovered,
		},
		{
			name: "a required wildcard is covered by the same wildcard",
			material: func(t *testing.T) *certs.Material {
				m := leCert(t, 80*day, "*.example.com")
				return &m
			},
			hosts:      []string{"*.example.com"},
			wantRenew:  false,
			wantUsable: true,
			wantReason: certs.ReasonUpToDate,
		},
		{
			name: "a required wildcard is not covered by the bare name",
			material: func(t *testing.T) *certs.Material {
				m := leCert(t, 80*day, "example.com")
				return &m
			},
			hosts:      []string{"*.example.com"},
			wantRenew:  true,
			wantUsable: false,
			wantReason: certs.ReasonHostsNotCovered,
		},
		{
			name: "hosts differing only in case and trailing dot are the same host",
			material: func(t *testing.T) *certs.Material {
				m := leCert(t, 80*day, "app.example.com")
				return &m
			},
			hosts:      []string{"APP.Example.com."},
			wantRenew:  false,
			wantUsable: true,
			wantReason: certs.ReasonUpToDate,
		},
		{
			name: "an expired certificate that also lost a host reports the expiry",
			material: func(t *testing.T) *certs.Material {
				m := leCert(t, -day, "app.example.com")
				return &m
			},
			hosts:      []string{"app.example.com", "api.example.com"},
			wantRenew:  true,
			wantUsable: false,
			wantReason: certs.ReasonExpired,
		},
		{
			name: "nothing is asked for",
			material: func(t *testing.T) *certs.Material {
				m := leCert(t, 80*day, "app.example.com")
				return &m
			},
			hosts:      nil,
			wantRenew:  false,
			wantUsable: false,
			wantReason: certs.ReasonNoHosts,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := certs.Evaluate(tc.material(t), tc.hosts, now)
			if got.Renew != tc.wantRenew {
				t.Errorf("Renew = %v, want %v (reason %q: %s)", got.Renew, tc.wantRenew, got.Reason, got.Detail)
			}
			if got.Usable != tc.wantUsable {
				t.Errorf("Usable = %v, want %v (reason %q: %s)", got.Usable, tc.wantUsable, got.Reason, got.Detail)
			}
			if got.Reason != tc.wantReason {
				t.Errorf("Reason = %q, want %q (%s)", got.Reason, tc.wantReason, got.Detail)
			}
			if got.Detail == "" {
				t.Error("Detail is empty; the reason has to be reportable to a human")
			}
		})
	}
}

// TestEvaluateRenewAt pins the instant renewal becomes due, which is what the
// controller schedules its next look at.
func TestEvaluateRenewAt(t *testing.T) {
	m := leCert(t, 80*day, "app.example.com")
	got := certs.Evaluate(&m, []string{"app.example.com"}, now)

	wantRenewAt := now.Add(50 * day) // ninety day lifetime, renewed with thirty left
	if !got.RenewAt.Equal(wantRenewAt) {
		t.Errorf("RenewAt = %v, want %v", got.RenewAt, wantRenewAt)
	}
	if !got.NotAfter.Equal(now.Add(80 * day)) {
		t.Errorf("NotAfter = %v, want %v", got.NotAfter, now.Add(80*day))
	}
}

// TestPolicyThreshold covers the rule itself: a third of the lifetime, never
// less than thirty days, and never more than half the lifetime.
func TestPolicyThreshold(t *testing.T) {
	p := certs.DefaultPolicy()
	tests := []struct {
		name     string
		lifetime time.Duration
		want     time.Duration
	}{
		{name: "ninety days is a third and the floor at once", lifetime: 90 * day, want: 30 * day},
		{name: "a year is bounded by the third", lifetime: 366 * day, want: 122 * day},
		{name: "sixty days is where the floor takes over", lifetime: 60 * day, want: 30 * day},
		{name: "ten days is bounded by half the lifetime", lifetime: 10 * day, want: 5 * day},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.Threshold(tc.lifetime); got != tc.want {
				t.Errorf("Threshold(%v) = %v, want %v", tc.lifetime, got, tc.want)
			}
		})
	}
}

// TestEvaluateDoesNotMutate guards the caller's slice, which the controller
// hands straight from the Ingress it is reconciling.
func TestEvaluateDoesNotMutate(t *testing.T) {
	m := leCert(t, 80*day, "app.example.com")
	hosts := []string{"B.example.com.", "a.example.com"}
	certs.Evaluate(&m, hosts, now)

	if hosts[0] != "B.example.com." || hosts[1] != "a.example.com" {
		t.Errorf("the host slice was rewritten: %v", hosts)
	}
}
