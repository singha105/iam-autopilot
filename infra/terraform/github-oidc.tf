# GitHub Actions approves a rollout through OIDC: no AWS keys in GitHub.
# Day 1 found no token.actions.githubusercontent.com provider in the account,
# so it is created here (free).

locals {
  github_owner    = "singha105"
  github_owner_id = 173531525
  github_repo     = "iam-autopilot"
  github_repo_id  = 1396239326
}

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_policy_document" "github_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Only pull_request workflow runs of this repository (ADR-007). This repo
    # uses GitHub's immutable subject format, which pins the owner and
    # repository IDs (public, not secret): a deleted-and-recreated repo or a
    # re-registered account name can never match. Check the format with
    #   gh api repos/singha105/iam-autopilot/actions/oidc/customization/sub
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${local.github_owner}@${local.github_owner_id}/${local.github_repo}@${local.github_repo_id}:pull_request"]
    }
  }
}

data "aws_iam_policy_document" "github_approver" {
  statement {
    sid       = "InvokeApproverOnly"
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = [aws_lambda_function.approver.arn]
  }
}

resource "aws_iam_role" "github_approver" {
  name                 = "iamap-github-approver"
  description          = "Assumed by the approve-rollout GitHub workflow; can only invoke iamap-approver."
  assume_role_policy   = data.aws_iam_policy_document.github_trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "github_approver" {
  name   = "iamap-invoke-approver"
  role   = aws_iam_role.github_approver.id
  policy = data.aws_iam_policy_document.github_approver.json
}
