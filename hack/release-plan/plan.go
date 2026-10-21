package main

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// RenovateAuthor is the author name git records for Renovate's commits.
const RenovateAuthor = "renovate[bot]"

// Version is a release version, vMAJOR.MINOR.PATCH.
type Version struct {
	Major, Minor, Patch int
}

func (v Version) String() string {
	return fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
}

func (v Version) less(o Version) bool {
	if v.Major != o.Major {
		return v.Major < o.Major
	}
	if v.Minor != o.Minor {
		return v.Minor < o.Minor
	}
	return v.Patch < o.Patch
}

var versionTag = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// LatestVersion picks the highest vX.Y.Z among tags, compared as numbers.
// Anything else — a fourth part, a pre-release, a missing v — is not a
// version this repository releases and is skipped.
func LatestVersion(tags []string) (Version, bool) {
	var latest Version
	found := false
	for _, tag := range tags {
		m := versionTag.FindStringSubmatch(tag)
		if m == nil {
			continue
		}
		var v Version
		var err error
		if v.Major, err = strconv.Atoi(m[1]); err != nil {
			continue
		}
		if v.Minor, err = strconv.Atoi(m[2]); err != nil {
			continue
		}
		if v.Patch, err = strconv.Atoi(m[3]); err != nil {
			continue
		}
		if !found || latest.less(v) {
			latest, found = v, true
		}
	}
	return latest, found
}

// imageContent is what the Dockerfile builds the image from: the Dockerfile
// itself and every path it copies in.
var imageContent = []string{"Dockerfile", "go.mod", "go.sum", "cmd/", "internal/"}

// IsImageContent reports whether a change to path can change the image.
func IsImageContent(path string) bool {
	for _, p := range imageContent {
		if strings.HasSuffix(p, "/") {
			if strings.HasPrefix(path, p) {
				return true
			}
		} else if path == p {
			return true
		}
	}
	return false
}

// Commit is one non-merge commit between the latest version and HEAD.
type Commit struct {
	Author  string
	Subject string
}

// Plan is what the weekly run does. Without a release, Version and Message
// are empty and Reason says why nothing is released.
type Plan struct {
	Release bool
	Version string
	// Message is the annotated tag's message.
	Message string
	Reason  string
}

// Decide whether the commits since latest are released as the next patch
// version (ADR 0036). It is released only when every commit is Renovate's and
// at least one changed path is part of the image. Anything a person wrote is
// released by that person, who chooses the version and writes the message.
func Decide(latest Version, commits []Commit, changed []string) Plan {
	if len(commits) == 0 {
		return Plan{Reason: fmt.Sprintf("no commits since %s", latest)}
	}
	for _, c := range commits {
		if c.Author != RenovateAuthor {
			return Plan{Reason: fmt.Sprintf("%q by %s is not by %s; releasing it is left to a person", c.Subject, c.Author, RenovateAuthor)}
		}
	}
	if !slices.ContainsFunc(changed, IsImageContent) {
		return Plan{Reason: fmt.Sprintf("Renovate's commits since %s change nothing the image is built from (%s)", latest, strings.Join(imageContent, ", "))}
	}

	next := Version{Major: latest.Major, Minor: latest.Minor, Patch: latest.Patch + 1}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: dependency updates\n\n", next)
	fmt.Fprintf(&b, "Only Renovate's dependency updates since %s, released by the\nweekly workflow (ADR 0036):\n\n", latest)
	for _, c := range commits {
		fmt.Fprintf(&b, "- %s\n", c.Subject)
	}
	return Plan{
		Release: true,
		Version: next.String(),
		Message: b.String(),
		Reason:  fmt.Sprintf("%d commits since %s, all by %s, and the image's content changed", len(commits), latest, RenovateAuthor),
	}
}
