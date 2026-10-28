package main

import (
	"slices"
	"strings"
	"testing"
)

func TestLatestVersion(t *testing.T) {
	tests := []struct {
		name   string
		tags   []string
		want   string
		wantOK bool
	}{
		{
			name: "no tags",
		},
		{
			name: "only tags that are not vX.Y.Z",
			tags: []string{"v0.17.0.1", "release-1", "v1.2", "1.2.3", "v1.2.3-rc.1"},
		},
		{
			name:   "versions compare by number, not by string",
			tags:   []string{"v0.9.0", "v0.10.0", "v0.2.11"},
			want:   "v0.10.0",
			wantOK: true,
		},
		{
			name:   "a four-part tag above the latest version is ignored",
			tags:   []string{"v0.17.0", "v0.17.0.1", "v0.16.3"},
			want:   "v0.17.0",
			wantOK: true,
		},
		{
			name:   "gated's tags",
			tags:   []string{"v0.1.0", "v0.2.0", "v0.3.0", "v0.4.0", "v0.4.1"},
			want:   "v0.4.1",
			wantOK: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := LatestVersion(tt.tags)
			if ok != tt.wantOK {
				t.Fatalf("LatestVersion(%q) ok = %v, want %v", tt.tags, ok, tt.wantOK)
			}
			if ok && got.String() != tt.want {
				t.Errorf("LatestVersion(%q) = %s, want %s", tt.tags, got, tt.want)
			}
		})
	}
}

func TestDecide(t *testing.T) {
	latest := Version{Major: 0, Minor: 4, Patch: 1}
	renovate := func(subject string) Commit { return Commit{Author: RenovateAuthor, Subject: subject} }
	responder := func(subject string) Commit { return Commit{Author: VulnResponderAuthor, Subject: subject} }
	person := func(subject string) Commit {
		return Commit{Hash: "0123456789abcdef", Author: "OTSUKA, Yuanying", Subject: subject}
	}

	tests := []struct {
		name        string
		commits     []Commit
		changed     []string
		wantRelease bool
		wantReason  string
		// wantTitle is the first line of the tag's message, after the version.
		wantTitle string
		// wantBlocking are the subjects of the commits that stopped the release.
		wantBlocking []string
	}{
		{
			name: "only Renovate, and the image's content changed",
			commits: []Commit{
				renovate("chore(deps): update module golang.org/x/crypto to v0.45.1"),
				renovate("chore(deps): update golang docker tag to v1.27.1"),
			},
			changed:     []string{"go.mod", "go.sum", "Dockerfile"},
			wantRelease: true,
			wantTitle:   "dependency updates",
		},
		{
			name: "a change to the source counts as the image's content",
			commits: []Commit{
				renovate("chore(deps): update module golang.org/x/net to v0.47.1"),
			},
			changed:     []string{"internal/proxy/server.go"},
			wantRelease: true,
			wantTitle:   "dependency updates",
		},
		{
			name: "only the vulnerability responder's fix",
			commits: []Commit{
				responder("Update golang.org/x/net to v0.47.2 for CVE-2026-41234"),
			},
			changed:     []string{"go.mod", "go.sum"},
			wantRelease: true,
			wantTitle:   "vulnerability fixes",
		},
		{
			name: "the responder's fix on top of Renovate's updates",
			commits: []Commit{
				renovate("chore(deps): update module golang.org/x/crypto to v0.45.1"),
				responder("Update the golang base image to 1.27.2 for CVE-2026-40001"),
			},
			changed:     []string{"go.mod", "go.sum", "Dockerfile"},
			wantRelease: true,
			wantTitle:   "vulnerability fixes",
		},
		{
			name: "a commit by someone else leaves the release to a human",
			commits: []Commit{
				renovate("chore(deps): update kubernetes monorepo"),
				person("Regenerate CRDs with controller-gen v0.23.0"),
			},
			changed:      []string{"go.mod", "go.sum", "config/crd/gate.unstable.cloud_networkroles.yaml"},
			wantReason:   "not by renovate[bot] or fraction-vuln-responder[bot]",
			wantBlocking: []string{"Regenerate CRDs with controller-gen v0.23.0"},
		},
		{
			name: "a person's commit next to the responder's fix leaves the release to a human",
			commits: []Commit{
				responder("Update golang.org/x/net to v0.47.2 for CVE-2026-41234"),
				person("Add a header to the refusal page"),
				renovate("chore(deps): update module golang.org/x/crypto to v0.45.1"),
				person("Log the subject on a refusal"),
			},
			changed:      []string{"go.mod", "go.sum", "internal/proxy/refusal.go"},
			wantReason:   "2 commits are not by renovate[bot] or fraction-vuln-responder[bot]",
			wantBlocking: []string{"Add a header to the refusal page", "Log the subject on a refusal"},
		},
		{
			name: "a person who signs as the bot's name without its brackets is a person",
			commits: []Commit{
				{Author: "fraction-vuln-responder", Subject: "Bump golang.org/x/net"},
			},
			changed:      []string{"go.mod"},
			wantReason:   "not by renovate[bot] or fraction-vuln-responder[bot]",
			wantBlocking: []string{"Bump golang.org/x/net"},
		},
		{
			name: "only Renovate, but only the workflows and renovate.json changed",
			commits: []Commit{
				renovate("chore(deps): update github-actions"),
				renovate("chore(config): migrate renovate config"),
			},
			changed:    []string{".github/workflows/ci.yml", ".github/workflows/publish.yml", "renovate.json"},
			wantReason: "nothing the image is built from",
		},
		{
			name: "only Renovate, but only the test scaffolding changed",
			commits: []Commit{
				renovate("chore(deps): update ghcr.io/letsencrypt/pebble docker digest to 0123abc"),
			},
			changed:    []string{"hack/e2e/pebble/Dockerfile"},
			wantReason: "nothing the image is built from",
		},
		{
			name:       "no commits since the tag",
			wantReason: "no commits since v0.4.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Decide(latest, tt.commits, tt.changed)
			if got.Release != tt.wantRelease {
				t.Fatalf("Decide().Release = %v, want %v (reason: %s)", got.Release, tt.wantRelease, got.Reason)
			}
			if got.Reason == "" {
				t.Error("Decide().Reason is empty; every outcome says why")
			}
			if !strings.Contains(got.Reason, tt.wantReason) {
				t.Errorf("Decide().Reason = %q, want it to contain %q", got.Reason, tt.wantReason)
			}
			var blocking []string
			for _, c := range got.Blocking {
				blocking = append(blocking, c.Subject)
			}
			if !slices.Equal(blocking, tt.wantBlocking) {
				t.Errorf("Decide().Blocking = %q, want %q", blocking, tt.wantBlocking)
			}
			if got.Next != "v0.4.2" && tt.commits != nil {
				t.Errorf("Decide().Next = %q, want v0.4.2 whenever there is something to release", got.Next)
			}
			if !got.Release {
				if got.Version != "" || got.Message != "" {
					t.Errorf("Decide() without a release has Version %q and Message %q, want both empty", got.Version, got.Message)
				}
				return
			}
			if got.Version != "v0.4.2" {
				t.Errorf("Decide().Version = %q, want v0.4.2", got.Version)
			}
			if want := "v0.4.2: " + tt.wantTitle + "\n\n"; !strings.HasPrefix(got.Message, want) {
				t.Errorf("Decide().Message = %q, want it to open with %q", got.Message, want)
			}
			for _, c := range tt.commits {
				if !strings.Contains(got.Message, "- "+c.Subject+"\n") {
					t.Errorf("Decide().Message = %q, want it to list %q", got.Message, c.Subject)
				}
			}
		})
	}
}

func TestIsImageContent(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"Dockerfile", true},
		{"go.mod", true},
		{"go.sum", true},
		{"cmd/gated/main.go", true},
		{"internal/authz/evaluate.go", true},
		{".github/workflows/ci.yml", false},
		{"renovate.json", false},
		{"hack/e2e/pebble/Dockerfile", false},
		{"config/manager/deployment.yaml", false},
		{"docs/adr/0036-weekly-dependency-release.md", false},
		{"README.md", false},
		{"Makefile", false},
		{"internalx/file.go", false},
	}
	for _, tt := range tests {
		if got := IsImageContent(tt.path); got != tt.want {
			t.Errorf("IsImageContent(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestSummary(t *testing.T) {
	const sha = "c30bed4e5f0a1b2c3d4e5f60718293a4b5c6d7e8"

	t.Run("a release says what is being released", func(t *testing.T) {
		got := Summary(Plan{Release: true, Version: "v0.4.2", Next: "v0.4.2", Reason: "1 commits since v0.4.1"}, sha)
		for _, want := range []string{"v0.4.2", "1 commits since v0.4.1"} {
			if !strings.Contains(got, want) {
				t.Errorf("Summary() = %q, want it to contain %q", got, want)
			}
		}
		if strings.Contains(got, "git tag") {
			t.Errorf("Summary() = %q, want no command to release by hand when the run releases", got)
		}
	})

	t.Run("a release stopped by people lists their commits and the command to release by hand", func(t *testing.T) {
		plan := Plan{
			Next:   "v0.4.2",
			Reason: "2 commits are not by renovate[bot] or fraction-vuln-responder[bot]",
			Blocking: []Commit{
				{Hash: "1111111111111111111111111111111111111111", Author: "OTSUKA, Yuanying", Subject: "Add a header to the refusal page"},
				{Hash: "2222222222222222222222222222222222222222", Author: "someone | else", Subject: "Log the `subject` | on a refusal"},
			},
		}
		got := Summary(plan, sha)
		for _, want := range []string{
			plan.Reason,
			"1111111", "Add a header to the refusal page", "OTSUKA, Yuanying",
			"2222222",
			"git tag -a v0.4.2 " + sha,
			"git push origin v0.4.2",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("Summary() = %q, want it to contain %q", got, want)
			}
		}
		// A pipe in an author or a subject would split the table's row.
		for _, l := range strings.Split(got, "\n") {
			if strings.Contains(l, "2222222") && strings.Count(l, "|")-strings.Count(l, `\|`) != 4 {
				t.Errorf("Summary() row %q does not have exactly three cells", l)
			}
		}
	})

	t.Run("nothing to release says why and offers no command", func(t *testing.T) {
		got := Summary(Plan{Reason: "no commits since v0.4.1"}, sha)
		if !strings.Contains(got, "no commits since v0.4.1") {
			t.Errorf("Summary() = %q, want it to say why", got)
		}
		if strings.Contains(got, "git tag") {
			t.Errorf("Summary() = %q, want no command when there is nothing a person was stopped on", got)
		}
	})
}
