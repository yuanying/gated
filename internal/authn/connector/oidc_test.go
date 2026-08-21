package connector

import "testing"

// TestTheIssuerIsComparedLeniently covers the one place the comparison is not
// a plain string equality: a provider may publish its issuer as a URL and
// stamp its tokens with the bare hostname, which is what Google itself has
// historically done. Everything else is still a refusal.
func TestTheIssuerIsComparedLeniently(t *testing.T) {
	client := newOIDCClient("https://accounts.example.com", nil, nil)

	tests := map[string]bool{
		"https://accounts.example.com":  true,
		"https://accounts.example.com/": true,
		"accounts.example.com":          true,
		"http://accounts.example.com":   false,
		"https://accounts.example.net":  false,
		"accounts.example.net":          false,
		"":                              false,
		"example.com":                   false,
	}

	for iss, want := range tests {
		if got := client.issuedByUs(iss); got != want {
			t.Errorf("issuedByUs(%q) = %v, want %v", iss, got, want)
		}
	}
}

// TestTheAudienceClaimIsReadInBothShapes covers the aud claim, which the
// specification allows to be one string or a list of them.
func TestTheAudienceClaimIsReadInBothShapes(t *testing.T) {
	tests := map[string]struct {
		json    string
		want    []string
		invalid bool
	}{
		"one string":    {json: `"client-id"`, want: []string{"client-id"}},
		"a list":        {json: `["client-id","another"]`, want: []string{"client-id", "another"}},
		"an empty list": {json: `[]`, want: []string{}},
		"a number":      {json: `1`, invalid: true},
		"an object":     {json: `{"aud":"client-id"}`, invalid: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var got audience
			err := got.UnmarshalJSON([]byte(tc.json))
			if tc.invalid {
				if err == nil {
					t.Fatalf("UnmarshalJSON(%s) = %v, nil; want an error", tc.json, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalJSON(%s) = %v", tc.json, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("UnmarshalJSON(%s) = %v, want %v", tc.json, got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("aud[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
			if got.contains("nobody") {
				t.Error("contains matched something that is not in the list")
			}
		})
	}
}
