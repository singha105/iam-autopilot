// Package githubpr opens, comments on, closes and inspects the pull requests
// that carry autopilot proposals and reverts.

package githubpr

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/go-github/v90/github"

	"github.com/singha105/iam-autopilot/internal/config"
)

// Label marks every PR the autopilot opens.
const Label = "autopilot"

// Client opens and inspects autopilot PRs in one repository.
type Client struct {
	gh    *github.Client
	Owner string
	Repo  string
	Base  string // branch PRs target, normally main
}

// New returns a client authenticated with token. baseURL is empty for
// github.com; tests pass an httptest server URL.
func New(token string, repo config.GitHub, baseURL string) (*Client, error) {
	opts := []github.ClientOptionsFunc{github.WithAuthToken(token), github.WithUserAgent("iam-autopilot")}
	if baseURL != "" {
		opts = append(opts, github.WithURLs(&baseURL, &baseURL))
	}
	gh, err := github.NewClient(opts...)
	if err != nil {
		return nil, err
	}
	return &Client{gh: gh, Owner: repo.Owner, Repo: repo.Repo, Base: repo.Branch}, nil
}

// Result identifies an opened PR.
type Result struct {
	Number int
	URL    string
	Branch string
}

// FetchFile returns a file's content at ref. It implements config.FileFetcher.
func (c *Client) FetchFile(ctx context.Context, path, ref string) ([]byte, error) {
	b, _, err := c.file(ctx, path, ref)
	return b, err
}

// file returns content and blob SHA; a missing file returns (nil, "", nil).
func (c *Client) file(ctx context.Context, path, ref string) ([]byte, string, error) {
	fc, _, resp, err := c.gh.Repositories.GetContents(ctx, c.Owner, c.Repo, path, &github.RepositoryContentGetOptions{Ref: ref})
	if resp != nil && resp.StatusCode == http.StatusNotFound {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("get %s@%s: %w", path, ref, err)
	}
	if fc == nil {
		return nil, "", fmt.Errorf("%s is a directory", path)
	}
	s, err := fc.GetContent()
	if err != nil {
		return nil, "", fmt.Errorf("decode %s: %w", path, err)
	}
	return []byte(s), fc.GetSHA(), nil
}

// branchFromBase creates refs/heads/<branch> at the base branch's head.
func (c *Client) branchFromBase(ctx context.Context, branch string) error {
	base, _, err := c.gh.Git.GetRef(ctx, c.Owner, c.Repo, "heads/"+c.Base)
	if err != nil {
		return fmt.Errorf("get %s: %w", c.Base, err)
	}
	_, _, err = c.gh.Git.CreateRef(ctx, c.Owner, c.Repo, github.CreateRef{Ref: "refs/heads/" + branch, SHA: base.GetObject().GetSHA()})
	if err != nil {
		return fmt.Errorf("create branch %s: %w", branch, err)
	}
	return nil
}

// commitFile writes content to path on branch, as one commit. An unchanged
// file is not committed again.
func (c *Client) commitFile(ctx context.Context, branch, path string, content []byte, message string) error {
	old, sha, err := c.file(ctx, path, branch)
	if err != nil {
		return err
	}
	if sha != "" && bytes.Equal(old, content) {
		return nil
	}
	opts := &github.RepositoryContentFileOptions{Message: github.Ptr(message), Content: content, Branch: github.Ptr(branch)}
	if sha == "" {
		_, _, err = c.gh.Repositories.CreateFile(ctx, c.Owner, c.Repo, path, opts)
	} else {
		opts.SHA = github.Ptr(sha)
		_, _, err = c.gh.Repositories.UpdateFile(ctx, c.Owner, c.Repo, path, opts)
	}
	if err != nil {
		return fmt.Errorf("commit %s on %s: %w", path, branch, err)
	}
	return nil
}

// openPR creates the PR and adds the autopilot label (creating the label if
// the repository does not have it yet).
func (c *Client) openPR(ctx context.Context, branch, title, body string) (Result, error) {
	pr, _, err := c.gh.PullRequests.Create(ctx, c.Owner, c.Repo, github.CreatePullRequest{
		Title: github.Ptr(title), Head: branch, Base: c.Base, Body: github.Ptr(body),
	})
	if err != nil {
		return Result{}, fmt.Errorf("open PR from %s: %w", branch, err)
	}
	res := Result{Number: pr.GetNumber(), URL: pr.GetHTMLURL(), Branch: branch}
	if err := c.ensureLabel(ctx); err != nil {
		return res, err
	}
	if _, _, err := c.gh.Issues.AddLabelsToIssue(ctx, c.Owner, c.Repo, res.Number, []string{Label}); err != nil {
		return res, fmt.Errorf("label PR #%d: %w", res.Number, err)
	}
	return res, nil
}

func (c *Client) ensureLabel(ctx context.Context) error {
	_, resp, err := c.gh.Issues.GetLabel(ctx, c.Owner, c.Repo, Label)
	if err == nil {
		return nil
	}
	if resp == nil || resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("get label %s: %w", Label, err)
	}
	_, _, err = c.gh.Issues.CreateLabel(ctx, c.Owner, c.Repo, github.CreateIssueLabelRequest{
		Name: Label, Color: github.Ptr("5319e7"), Description: github.Ptr("Opened by the IAM least-privilege autopilot"),
	})
	if err != nil {
		return fmt.Errorf("create label %s: %w", Label, err)
	}
	return nil
}

// PolicyPR is everything OpenPolicyPR needs.
type PolicyPR struct {
	RolloutID     string
	PolicyFile    string // repo path, from autopilot.yaml policyFile
	PolicyJSON    []byte // the proposed policy, exactly as generated
	Title         string
	CommitMessage string
	Body          string // RenderPRBody
}

// OpenPolicyPR creates branch autopilot/<rolloutId> from the base branch,
// commits the proposed policy to its file, and opens a labelled PR.
func (c *Client) OpenPolicyPR(ctx context.Context, in PolicyPR) (Result, error) {
	branch := "autopilot/" + in.RolloutID
	if err := c.branchFromBase(ctx, branch); err != nil {
		return Result{}, err
	}
	if err := c.commitFile(ctx, branch, in.PolicyFile, in.PolicyJSON, in.CommitMessage); err != nil {
		return Result{Branch: branch}, err
	}
	return c.openPR(ctx, branch, in.Title, in.Body)
}

// RevertPR is everything OpenRevertPR needs.
type RevertPR struct {
	RolloutID     string
	RoleName      string
	PolicyFile    string
	OldPolicyJSON []byte   // the policy before the rollout
	KeepActions   []string // actions that were denied, added to the role's keepActions
	ConfigPath    string   // autopilot.yaml
	Body          string
}

// OpenRevertPR creates branch autopilot-revert/<rolloutId>, restores the old
// policy file, adds KeepActions to the role in autopilot.yaml (one-line
// edit), and opens a labelled PR, so main matches what the rollback applied
// and the next proposal keeps the action that was needed.
func (c *Client) OpenRevertPR(ctx context.Context, in RevertPR) (Result, error) {
	branch := "autopilot-revert/" + in.RolloutID
	if err := c.branchFromBase(ctx, branch); err != nil {
		return Result{}, err
	}
	msg := fmt.Sprintf("autopilot: restore %s policy after rollback of %s", in.RoleName, in.RolloutID)
	if err := c.commitFile(ctx, branch, in.PolicyFile, in.OldPolicyJSON, msg); err != nil {
		return Result{Branch: branch}, err
	}
	if len(in.KeepActions) > 0 {
		cfg, _, err := c.file(ctx, in.ConfigPath, branch)
		if err != nil {
			return Result{Branch: branch}, err
		}
		if cfg == nil {
			return Result{Branch: branch}, fmt.Errorf("%s not found on %s", in.ConfigPath, branch)
		}
		edited, err := config.AddKeepActions(cfg, in.RoleName, in.KeepActions)
		if err != nil {
			return Result{Branch: branch}, err
		}
		msg := fmt.Sprintf("autopilot: keep %v for %s (denied after %s)", in.KeepActions, in.RoleName, in.RolloutID)
		if err := c.commitFile(ctx, branch, in.ConfigPath, edited, msg); err != nil {
			return Result{Branch: branch}, err
		}
	}
	title := fmt.Sprintf("autopilot: revert %s and keep %v", in.RoleName, in.KeepActions)
	return c.openPR(ctx, branch, title, in.Body)
}

// CommentOnPR adds a markdown comment to a PR.
func (c *Client) CommentOnPR(ctx context.Context, number int, markdown string) error {
	if _, _, err := c.gh.Issues.CreateComment(ctx, c.Owner, c.Repo, number, &github.IssueComment{Body: github.Ptr(markdown)}); err != nil {
		return fmt.Errorf("comment on PR #%d: %w", number, err)
	}
	return nil
}

// ClosePR comments, closes the PR without merging, and deletes its branch.
func (c *Client) ClosePR(ctx context.Context, number int, branch, comment string) error {
	if comment != "" {
		if err := c.CommentOnPR(ctx, number, comment); err != nil {
			return err
		}
	}
	if _, _, err := c.gh.PullRequests.Edit(ctx, c.Owner, c.Repo, number, &github.PullRequest{State: github.Ptr("closed")}); err != nil {
		return fmt.Errorf("close PR #%d: %w", number, err)
	}
	if branch != "" {
		resp, err := c.gh.Git.DeleteRef(ctx, c.Owner, c.Repo, "heads/"+branch)
		if err != nil && (resp == nil || resp.StatusCode != http.StatusUnprocessableEntity) {
			return fmt.Errorf("delete branch %s: %w", branch, err)
		}
	}
	return nil
}

// MergeInfo says whether and by whom a PR was merged.
type MergeInfo struct {
	Merged   bool
	MergedBy string
	MergedAt time.Time
	State    string
}

// IsMerged reports whether a PR was merged, by whom and when.
func (c *Client) IsMerged(ctx context.Context, number int) (MergeInfo, error) {
	pr, _, err := c.gh.PullRequests.Get(ctx, c.Owner, c.Repo, number)
	if err != nil {
		return MergeInfo{}, fmt.Errorf("get PR #%d: %w", number, err)
	}
	return MergeInfo{Merged: pr.GetMerged(), MergedBy: pr.GetMergedBy().GetLogin(), MergedAt: pr.GetMergedAt().Time, State: pr.GetState()}, nil
}

// ErrNoToken is returned when no GitHub token is available.
var ErrNoToken = errors.New("no GitHub token: set GITHUB_TOKEN or store it in SSM /iamap/github/token")
