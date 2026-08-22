package routing

import (
	"errors"
	"strings"
)

// ErrPathNotCanonical is returned for a request path gated will not route.
//
// The three refusals below all come down to one thing: gated matches the path
// as it received it and forwards it unchanged (ADR 0012), while authorisation
// compares it as a string prefix (ADR 0017). A path that means one place here
// and another place at the backend would let a rule grant what it does not
// name, so it is refused rather than resolved.
var ErrPathNotCanonical = errors.New("the request path is not in canonical form")

// CheckPath reports whether a request path may be routed.
//
// It takes the pair a parsed request URL carries: path is the decoded form,
// and escaped is the form it was received in, which net/url leaves empty when
// it is just the default encoding of the decoded one.
//
// What is refused, and what deliberately is not, is enumerated in ADR 0012 and
// in the table beside this file. Nothing here rewrites: the answer is only
// whether the path is one gated is willing to carry.
func CheckPath(path, escaped string) error {
	for segment := range strings.SplitSeq(path, "/") {
		// A path parameter is separated from the segment by a
		// semicolon, and implementations that read them drop everything
		// from the semicolon on. "..;" is therefore the same segment as
		// ".." to the backend, whatever it looks like here.
		name, _, _ := strings.Cut(segment, ";")
		if name == "." || name == ".." {
			return ErrPathNotCanonical
		}
	}

	// A slash or a dot that arrived percent-encoded is a character gated
	// sees inside a segment and the backend may see as a separator. The
	// decoded form above cannot tell the two apart, so the escaped form
	// answers for them. It is empty unless it differs from the default
	// encoding of the decoded path, which is why an ordinary %20 never
	// reaches this loop.
	for i := 0; i+2 < len(escaped); i++ {
		if escaped[i] != '%' || escaped[i+1] != '2' {
			continue
		}
		switch escaped[i+2] {
		case 'f', 'F', 'e', 'E':
			return ErrPathNotCanonical
		}
	}
	return nil
}
