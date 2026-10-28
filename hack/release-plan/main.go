// release-plan decides whether release.yml releases the next patch version
// (ADR 0036, ADR 0038), reading the history of the checkout it runs in, up to
// its HEAD. The decision itself is Decide; this file only asks git and writes
// the result.
//
// It always prints the decision and its reason. With -github-output it also
// appends version, message and sha to that file in the format of
// $GITHUB_OUTPUT, version and message empty when nothing is released. With
// -step-summary it appends the decision as Markdown, which lists the commits
// that stopped a release and the commands to release by hand.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func main() {
	output := flag.String("github-output", "", "append version, message and sha to this file, in the format of $GITHUB_OUTPUT")
	summary := flag.String("step-summary", "", "append the decision as Markdown to this file, such as $GITHUB_STEP_SUMMARY")
	flag.Parse()

	ctx := context.Background()
	plan, err := planFromGit(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "release-plan:", err)
		os.Exit(1)
	}
	head, err := git(ctx, "rev-parse", "HEAD")
	if err != nil {
		fmt.Fprintln(os.Stderr, "release-plan:", err)
		os.Exit(1)
	}
	sha := strings.TrimSpace(head)

	if plan.Release {
		fmt.Printf("release %s: %s\n\n%s", plan.Version, plan.Reason, plan.Message)
	} else {
		fmt.Printf("no release: %s\n", plan.Reason)
	}

	if *output != "" {
		if err := writeOutput(*output, plan, sha); err != nil {
			fmt.Fprintln(os.Stderr, "release-plan:", err)
			os.Exit(1)
		}
	}
	if *summary != "" {
		if err := appendFile(*summary, Summary(plan, sha)); err != nil {
			fmt.Fprintln(os.Stderr, "release-plan:", err)
			os.Exit(1)
		}
	}
}

func planFromGit(ctx context.Context) (Plan, error) {
	tags, err := git(ctx, "tag", "--list")
	if err != nil {
		return Plan{}, err
	}
	latest, ok := LatestVersion(lines(tags))
	if !ok {
		return Plan{Reason: "no vX.Y.Z tag; the first version is a person's to choose"}, nil
	}

	rng := latest.String() + "..HEAD"
	log, err := git(ctx, "log", "--no-merges", "--reverse", "--format=%H%x1f%an%x1f%s", rng)
	if err != nil {
		return Plan{}, err
	}
	var commits []Commit
	for _, l := range lines(log) {
		hash, rest, _ := strings.Cut(l, "\x1f")
		author, subject, _ := strings.Cut(rest, "\x1f")
		commits = append(commits, Commit{Hash: hash, Author: author, Subject: subject})
	}

	changed, err := git(ctx, "diff", "--name-only", rng)
	if err != nil {
		return Plan{}, err
	}
	return Decide(latest, commits, lines(changed)), nil
}

func git(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "git", args...).Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

func lines(s string) []string {
	var ls []string
	for l := range strings.SplitSeq(s, "\n") {
		if l != "" {
			ls = append(ls, l)
		}
	}
	return ls
}

// writeOutput appends the plan as step outputs. The message spans lines, so
// it goes in the heredoc form with a delimiter it cannot contain. sha is the
// commit the plan was made for, which the image is built from and the tag
// points at.
func writeOutput(path string, plan Plan, sha string) error {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return err
	}
	delim := "EOF_" + hex.EncodeToString(buf)
	return appendFile(path, fmt.Sprintf("version=%s\nsha=%s\nmessage<<%s\n%s\n%s\n", plan.Version, sha, delim, plan.Message, delim))
}

func appendFile(path, content string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(content)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
