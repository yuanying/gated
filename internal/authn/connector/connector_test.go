package connector

import (
	"context"
	"reflect"
	"testing"
)

type stub string

func (s stub) Name() string                                         { return string(s) }
func (s stub) AuthCodeURL(context.Context, Request) (string, error) { return "", nil }
func (s stub) Identify(context.Context, string, Request) (Identity, error) {
	return Identity{}, nil
}

func TestSetIsTheProvidersInAStableOrder(t *testing.T) {
	tests := map[string]struct {
		connectors []Connector
		wantNames  []string
		wantOnly   string
	}{
		"nothing configured": {},
		"one provider": {
			connectors: []Connector{stub("github")},
			wantNames:  []string{"github"},
			wantOnly:   "github",
		},
		"both, listed the other way round": {
			connectors: []Connector{stub("google"), stub("github")},
			wantNames:  []string{"github", "google"},
		},
		"a nil among them": {
			connectors: []Connector{nil, stub("google")},
			wantNames:  []string{"google"},
			wantOnly:   "google",
		},
		"the same name twice": {
			connectors: []Connector{stub("github"), stub("github")},
			wantNames:  []string{"github"},
			wantOnly:   "github",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			set := NewSet(tc.connectors...)
			if got := set.Names(); !reflect.DeepEqual(got, tc.wantNames) && !(len(got) == 0 && len(tc.wantNames) == 0) {
				t.Errorf("Names() = %v, want %v", got, tc.wantNames)
			}
			if got := set.Len(); got != len(tc.wantNames) {
				t.Errorf("Len() = %d, want %d", got, len(tc.wantNames))
			}
			only, ok := set.Only()
			if tc.wantOnly == "" {
				if ok {
					t.Errorf("Only() = %q; want no single provider", only.Name())
				}
			} else if !ok || only.Name() != tc.wantOnly {
				t.Errorf("Only() = %v, %v; want %q", only, ok, tc.wantOnly)
			}
			for _, want := range tc.wantNames {
				if _, ok := set.Lookup(want); !ok {
					t.Errorf("Lookup(%q) found nothing", want)
				}
			}
			if _, ok := set.Lookup("nobody"); ok {
				t.Error("Lookup found a provider that was never configured")
			}
		})
	}
}

// TestANilSetAnswersLikeAnEmptyOne keeps a process configured with no provider
// from panicking instead of refusing.
func TestANilSetAnswersLikeAnEmptyOne(t *testing.T) {
	var set *Set
	if set.Len() != 0 || set.Names() != nil {
		t.Error("a nil set is not empty")
	}
	if _, ok := set.Lookup("github"); ok {
		t.Error("a nil set found a provider")
	}
	if _, ok := set.Only(); ok {
		t.Error("a nil set has a single provider")
	}
}
