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

// VulnResponderAuthor is the author name git records for the commits of
// fraction-vuln-responder, the agent that opens pull requests fixing a
// vulnerability (ADR 0038). Its email is
// 348762456+fraction-vuln-responder[bot]@users.noreply.github.com.
const VulnResponderAuthor = "fraction-vuln-responder[bot]"

// botAuthors are the authors whose commits the workflow may release on its
// own. Everything else is a person's.
var botAuthors = []string{RenovateAuthor, VulnResponderAuthor}

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
	Hash    string
	Author  string
	Subject string
}

// Plan is what a run of release.yml does. Without a release, Version and
// Message are empty and Reason says why nothing is released.
type Plan struct {
	Release bool
	Version string
	// Message is the annotated tag's message.
	Message string
	Reason  string
	// Next is the next patch version, set whenever there are commits since
	// the latest one, released or not. A person releasing by hand starts
	// from it.
	Next string
	// Blocking are the commits by people that stopped the release.
	Blocking []Commit
}

// Decide whether the commits since latest are released as the next patch
// version (ADR 0036, ADR 0038). It is released only when every commit is by
// Renovate or the vulnerability responder and at least one changed path is
// part of the image. Anything a person wrote is released by that person, who
// chooses the version and writes the message.
func Decide(latest Version, commits []Commit, changed []string) Plan {
	if len(commits) == 0 {
		return Plan{Reason: fmt.Sprintf("no commits since %s", latest)}
	}
	next := Version{Major: latest.Major, Minor: latest.Minor, Patch: latest.Patch + 1}
	bots := strings.Join(botAuthors, " or ")

	var blocking []Commit
	fixes := false
	for _, c := range commits {
		switch {
		case c.Author == VulnResponderAuthor:
			fixes = true
		case !slices.Contains(botAuthors, c.Author):
			blocking = append(blocking, c)
		}
	}
	if len(blocking) == 1 {
		c := blocking[0]
		return Plan{Next: next.String(), Blocking: blocking, Reason: fmt.Sprintf("%q by %s is not by %s; releasing it is left to a person", c.Subject, c.Author, bots)}
	}
	if len(blocking) > 1 {
		return Plan{Next: next.String(), Blocking: blocking, Reason: fmt.Sprintf("%d commits are not by %s; releasing them is left to a person", len(blocking), bots)}
	}
	if !slices.ContainsFunc(changed, IsImageContent) {
		return Plan{Next: next.String(), Reason: fmt.Sprintf("the commits since %s change nothing the image is built from (%s)", latest, strings.Join(imageContent, ", "))}
	}

	var b strings.Builder
	if fixes {
		fmt.Fprintf(&b, "%s: vulnerability fixes\n\n", next)
		fmt.Fprintf(&b, "Only fixes by %s and updates by %s since %s,\nreleased by release.yml (ADR 0038):\n\n", VulnResponderAuthor, RenovateAuthor, latest)
	} else {
		fmt.Fprintf(&b, "%s: dependency updates\n\n", next)
		fmt.Fprintf(&b, "Only Renovate's dependency updates since %s, released by the\nweekly workflow (ADR 0036):\n\n", latest)
	}
	for _, c := range commits {
		fmt.Fprintf(&b, "- %s\n", c.Subject)
	}
	return Plan{
		Release: true,
		Version: next.String(),
		Next:    next.String(),
		Message: b.String(),
		Reason:  fmt.Sprintf("%d commits since %s, all by %s, and the image's content changed", len(commits), latest, bots),
	}
}

// Summary renders the plan as Markdown for the run's job summary. When people
// stopped the release it lists their commits and the commands that release
// sha by hand, so that whoever reads the run does not have to work them out.
func Summary(plan Plan, sha string) string {
	var b strings.Builder
	if plan.Release {
		fmt.Fprintf(&b, "### Releasing %s\n\n%s\n", plan.Version, plan.Reason)
		return b.String()
	}
	fmt.Fprintf(&b, "### No release\n\n%s\n", plan.Reason)
	if len(plan.Blocking) == 0 {
		return b.String()
	}
	b.WriteString("\nThese commits are not by a bot, so the release is left to a person:\n\n")
	b.WriteString("| commit | author | subject |\n|---|---|---|\n")
	for _, c := range plan.Blocking {
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", short(c.Hash), cell(c.Author), cell(c.Subject))
	}
	fmt.Fprintf(&b, "\nTo release them by hand, check that %s is what should go out, then:\n\n", short(sha))
	fmt.Fprintf(&b, "```sh\ngit fetch origin --tags\ngit tag -a %s %s\ngit push origin %s\n```\n", plan.Next, sha, plan.Next)
	b.WriteString("\nPushing the tag publishes the image through publish.yml (ADR 0029).\n")
	return b.String()
}

func short(hash string) string {
	if len(hash) > 7 {
		return hash[:7]
	}
	return hash
}

// cell keeps a value inside one cell of a Markdown table.
func cell(s string) string {
	return strings.ReplaceAll(s, "|", `\|`)
}
