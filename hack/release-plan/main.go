// release-plan decides whether the weekly run releases the next patch version
// (ADR 0036), reading the history of the checkout it runs in. The decision
// itself is Decide; this file only asks git and writes the result.
//
// It always prints the decision and its reason. With -github-output it also
// appends version and message to that file in the format of $GITHUB_OUTPUT,
// both empty when nothing is released.
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
	output := flag.String("github-output", "", "append version and message to this file, in the format of $GITHUB_OUTPUT")
	flag.Parse()

	plan, err := planFromGit(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, "release-plan:", err)
		os.Exit(1)
	}

	if plan.Release {
		fmt.Printf("release %s: %s\n\n%s", plan.Version, plan.Reason, plan.Message)
	} else {
		fmt.Printf("no release: %s\n", plan.Reason)
	}

	if *output != "" {
		if err := writeOutput(*output, plan); err != nil {
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
	log, err := git(ctx, "log", "--no-merges", "--reverse", "--format=%an%x1f%s", rng)
	if err != nil {
		return Plan{}, err
	}
	var commits []Commit
	for _, l := range lines(log) {
		author, subject, _ := strings.Cut(l, "\x1f")
		commits = append(commits, Commit{Author: author, Subject: subject})
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
// it goes in the heredoc form with a delimiter it cannot contain.
func writeOutput(path string, plan Plan) error {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return err
	}
	delim := "EOF_" + hex.EncodeToString(buf)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(f, "version=%s\nmessage<<%s\n%s\n%s\n", plan.Version, delim, plan.Message, delim)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
