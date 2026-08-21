package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// fixedSubject is a resolver that always answers the same thing.
type fixedSubject string

func (s fixedSubject) Subject(*http.Request) string { return string(s) }

// There are two ways to establish who is asking — a token and a session
// cookie — and one decision that follows (ADR 0004). The chain is where that
// meets: the resolvers are asked in order and the decision never learns which
// one answered.
func TestSubjectResolversTakeTheFirstAnswer(t *testing.T) {
	tests := []struct {
		name      string
		resolvers SubjectResolvers
		want      string
	}{
		{name: "nobody to ask", resolvers: nil, want: ""},
		{name: "one answer", resolvers: SubjectResolvers{fixedSubject("github:octocat")}, want: "github:octocat"},
		{
			// A token is presented deliberately; a cookie is sent by
			// the browser whether or not it is wanted. When both
			// arrive, the deliberate one is the answer.
			name:      "the first of two",
			resolvers: SubjectResolvers{fixedSubject("github:octocat"), fixedSubject("github:hubot")},
			want:      "github:octocat",
		},
		{
			name:      "the first has nothing to say",
			resolvers: SubjectResolvers{fixedSubject(""), fixedSubject("github:hubot")},
			want:      "github:hubot",
		},
		{
			name:      "nobody has anything to say",
			resolvers: SubjectResolvers{fixedSubject(""), fixedSubject("")},
			want:      "",
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.resolvers.Subject(req); got != tt.want {
				t.Errorf("Subject() = %q, want %q", got, tt.want)
			}
		})
	}
}
