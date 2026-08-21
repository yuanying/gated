//go:build e2e

package e2e

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	gatev1alpha1 "github.com/yuanying/gated/internal/apis/gate/v1alpha1"
)

// visitor is a browser: it keeps cookies, follows redirects and trusts the
// certificate authority the test cluster runs.
//
// login is who the stand-in identity provider says the visitor is. A real
// provider asks; this one is told, because the test is the one logging in.
func visitor(t *testing.T, roots *x509.CertPool, login string) *http.Client {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("building a cookie jar: %v", err)
	}

	transport := &http.Transport{
		DialContext:     dialCluster,
		TLSClientConfig: tlsConfig(roots),
	}
	return &http.Client{
		Jar:       jar,
		Timeout:   60 * time.Second,
		Transport: identifying{next: transport, login: login},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 12 {
				return fmt.Errorf("the login bounced more than 12 times, ending at %s", req.URL)
			}
			return nil
		},
	}
}

// identifying tells the stand-in identity provider who is logging in, and
// leaves every other request alone.
type identifying struct {
	next  http.RoundTripper
	login string
}

func (i identifying) RoundTrip(r *http.Request) (*http.Response, error) {
	if i.login != "" && r.URL.Host == idpHost {
		r = r.Clone(r.Context())
		r.Header.Set("X-Mock-Login", i.login)
	}
	return i.next.RoundTrip(r)
}

// browserHeader is what a browser sends, and what makes gated offer a login
// rather than a challenge (ADR 0018).
func browserHeader() http.Header {
	return http.Header{"Accept": {"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}}
}

// role protects an Ingress and allows a set of paths and methods on it.
func role(name, ingress string, rules ...gatev1alpha1.NetworkRoleRule) *gatev1alpha1.NetworkRole {
	return &gatev1alpha1.NetworkRole{
		ObjectMeta: metav1.ObjectMeta{Namespace: appNamespace, Name: name},
		Spec: gatev1alpha1.NetworkRoleSpec{
			TargetRef: gatev1alpha1.TargetReference{Name: ingress},
			Rules:     rules,
		},
	}
}

// binding grants a role to subjects.
func binding(name, roleName string, subjects ...string) *gatev1alpha1.NetworkRoleBinding {
	b := &gatev1alpha1.NetworkRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: appNamespace, Name: name},
		Spec: gatev1alpha1.NetworkRoleBindingSpec{
			RoleRef: gatev1alpha1.RoleReference{Name: roleName},
		},
	}
	for _, s := range subjects {
		b.Spec.Subjects = append(b.Spec.Subjects, gatev1alpha1.Subject{Name: s})
	}
	return b
}

// anyMethod is the rule that allows everything on every path, which is what a
// scenario about who may get in rather than about what they may do wants.
func anyMethod() gatev1alpha1.NetworkRoleRule {
	return gatev1alpha1.NetworkRoleRule{
		Paths:   []string{"*"},
		Methods: []gatev1alpha1.HTTPMethod{gatev1alpha1.MethodAll},
	}
}

// waitFor retries an assertion until it holds. The permissions reach a replica
// through an informer, so a role that was just created is in force a moment
// later rather than at once.
func waitFor(t *testing.T, ctx context.Context, what string, condition func() bool) {
	t.Helper()
	err := poll(ctx, settleTimeout, func(context.Context) (bool, error) {
		return condition(), nil
	})
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}
