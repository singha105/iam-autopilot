# Progress

Read this and CLAUDE.md at the start of every session.

## Day 1: Foundation, guardrails and demo apps (2026-09-29)

- [x] Step 0 safety checks (identity, event history, OIDC provider, existing budgets)
- [x] CLAUDE.md with zero-cost, safety and working rules
- [x] Repo scaffold, go.mod, Makefile, README, DECISIONS, LICENSE
- [x] Three over-permissioned demo Lambdas (inventory, config-reader, quarterly), unit tested with fakes
- [x] Terraform: budget, permissions boundary, demo roles/policies/functions, DynamoDB, SSM
- [x] autopilot.yaml
- [x] scripts/traffic.sh and scripts/cost-audit.sh
- [x] CI workflow (lint, test, build, terraform fmt/validate; no AWS credentials)
- [x] `make check` passes locally
- [x] CI green on GitHub (run 36611828078, both jobs passed)
- [x] Deployed with `make apply` (24 resources); budget `iamap-zero-spend` exists
- [x] `make traffic` prints OK for all 15 calls: runs at 18:12Z, 18:15Z and 18:18Z, 15/15 each
  (one extra back-to-back run at 18:15Z, output not kept)
- [x] `lookup-events` shows API calls made by a demo function (DescribeInstances, DescribeRegions,
  ListBuckets, ListFunctions20150331 by iamap-demo-inventory, about 3 minutes after invoke)
- [x] `make cost-audit` passes
- [x] terraform.tfstate, terraform.tfvars and build/ not in git (`git ls-files`)

## Day 2: Observation engine (2026-09-30 / 10-01)

- [x] Run `make traffic` first (15/15 OK at 2026-10-01T00:36Z)
- [x] internal/observe: CloudTrailAPI / IAMAPI interfaces, ResolveRole (refuses untagged roles;
      verified live against AWSServiceRoleForResourceExplorer)
- [x] CloudTrail event history collector: rate limit 1.5 req/s, throttling retry (5 tries, backoff
      0.5s doubling), 90-day clamp, session-issuer filter, event -> IAM action mapping, resource ARNs,
      denied calls
- [x] Access Advisor collector (ACTION_LEVEL, 2s poll up to 60s, Marker pagination)
- [x] BuildProfile with deterministic JSON (shuffled-input test, byte-identical)
- [x] `autopilot observe` CLI; ADR-001 (standard library flag) and ADR-002 (platform calls)
- [x] Redacted fixtures under testdata/observe/<role>/ (recorded with `--record`) and golden-file
      test (`go test ./internal/observe -update` regenerates expected-profile.json)
- [x] `autopilot observe` matches the expected actions for all three demo roles (live, 2026-10-01)
- [x] Tests pass with AWS credentials unset; real account ID absent from the repo (0 matches)
- [x] `make check` passes; pushed
- [x] CI green on GitHub for the Day 2 head (run 36797344547, both jobs passed)

## Day 3: Policy generator and shadow mode (2026-10-01 / 10-02)

- [x] Run `make traffic` first (15/15 OK at 2026-10-02T03:29Z)
- [x] Service Authorization Reference endpoint confirmed (index: JSON array of 455 {service, url, modified})
- [x] `make catalog` writes internal/catalog/data/actions.json (12 services, 1994 actions,
      resource types with ARN formats); deterministic on re-run; embedded with go:embed
- [x] internal/catalog API: Expand, Matches, SupportsResources, Exists, CountGranted (NotAction -> error),
      plus ARNFitsAction (an ARN must match one of the action's resource-type formats)
- [x] CurrentPolicy: the one /iamap/managed/ policy, default version, URL-decoded
- [x] internal/generate: rules R1-R7, statement grouping, 6,144-char limit, Summary (JSON + Markdown)
- [x] Validate with Access Analyzer ValidatePolicy (ERROR / SECURITY_WARNING fail the run)
- [x] internal/shadow: SimulateCustomPolicy replay at 5 req/s, grouped by resource, Marker paging,
      self-test of the current policy
- [x] CLI: `autopilot generate` (proposed-policy.json, summary.json, summary.md) and `autopilot shadow`
- [x] Tests: R1-R7 table tests, golden proposals per demo role, determinism, shadow denial exits 1,
      SECURITY_WARNING fails generate; `go test ./...` passes offline
- [x] Real run (observe -> generate -> shadow, 1-day window, 2026-10-02): 0 would-be denials and
      0 validation findings for all three roles
      - inventory 1273 -> 5 (99.6%): the 5 observed actions; sns, sqs removed
      - config-reader 305 -> 4 (98.7%): ssm:GetParameter and dynamodb:DescribeTable scoped; GetItem/PutItem
        kept-unobservable on the table; kms, sns, sqs removed
      - quarterly 532 -> 1 (99.8%): ssm:GetParameter only (GetParametersByPath removed: the Day 6 risk)
- [x] ADR-003 (evidence-based R4) and ADR-004 (simulator, not paid custom checks). The prompt
      called them ADR-002/003, but ADR-002 was already used on Day 2 for platform calls.
- [x] `make check` passes; pushed
- [x] CI green on GitHub for the Day 3 head (run 36960690282, both jobs passed)

## Day 4: Rollout records and the pull request (2026-10-02)

- [x] Run `make traffic` first (15/15 OK at 2026-10-02T04:34Z, and again after the apply)
- [x] GitHub token stored by hand as SSM SecureString /iamap/github/token (Standard, aws/ssm key,
      now version 2). Fine-grained, singha105/iam-autopilot only, Contents + Pull requests + Issues
      read/write
- [x] Terraform: iamap-rollouts table (PROVISIONED 1/1, hash key rolloutId); plan reviewed, applied;
      `make cost-audit` passes; follow-up plan shows no changes
- [x] Reproducible Lambda builds (-buildvcs=false): the git revision in each binary made every commit
      redeploy all three demos; one-time redeploy of identical code done with the table apply
- [x] internal/store: rollout record, conditional status updates (lost-race test), ActiveForRole,
      300 KB guard
- [x] Config from a local file or from GitHub (LoadFrom + FetchFile); github block; policyFile per
      role; watch values > 0; AddKeepActions edits one line
- [x] internal/githubpr (go-github v90, newest major supporting Go 1.25): OpenPolicyPR, CommentOnPR,
      OpenRevertPR, ClosePR, IsMerged, label; tested against an httptest fake GitHub
- [x] `autopilot propose` (with --dry-run), `autopilot cancel`, `autopilot status`
- [x] Real run (2026-10-02):
      - inventory dry run: 1273 -> 5 (99.6%), shadow 5/5, 0 findings
      - first two real attempts FAILED cleanly: 401 (invalid token), then 403 (token lacked Contents
        write); records moved to FAILED, nothing created on GitHub
      - PR https://github.com/singha105/iam-autopilot/pull/1 opened (label, one commit, one file),
        then cancelled: closed unmerged with a comment, branch deleted, record CANCELLED
      - config-reader dry run 305 -> 4 (98.7%), quarterly 532 -> 1 (99.8%), both shadow 0 denied
- [x] Shadow test-set fix (approved): once Access Advisor caught up, tracked actions were also tested
      on "*", so correctly scoped ssm:GetParameter / dynamodb:DescribeTable looked denied. Observed
      actions are now tested only on their observed resources; regression test added
- [x] ADR-005 (PR merge as approval; token in SSM SecureString, not Secrets Manager). The prompt calls
      it ADR-004, already used on Day 3.
- [x] `make check` passes; pushed
- [ ] CI green on GitHub for the Day 4 head (checked right after the push; tick in Day 5's first commit)

## Day 5

- [ ] (Day 5 prompt)

## Day 6

- [ ] (Day 6 prompt)

## Facts recorded

- AWS account: the `paved` profile (root login session, `aws login --profile paved`); region us-east-1 (var.region).
- GitHub OIDC provider for token.actions.githubusercontent.com: **does not exist**. Day 5 must create it.
  (The only OIDC provider in the account is Paved's leftover S3-hosted eu-west-2 one; leave it alone.)
- Budgets before Day 1: none. `iamap-zero-spend` is the only budget ($0.01/month, email on ACTUAL > $0.01).
- CloudTrail trails in the account: 0. Event history works without one.
- Go module targets `go 1.25.0`. aws-lambda-go is pinned to v1.54.0 and golang.org/x/time to v0.15.0
  because newer releases require Go 1.26. Check `go.mod` after every `go get`.

## Findings for later days

- **Day 5 approver:** `autopilot status` shows the rollout; the PR body ends with
  `<!-- rolloutId: ... -->` and the record holds prNumber/prBranch, so the approve workflow can map a
  merged PR back to its rollout. Records start at PR_OPEN; the approver must move PR_OPEN -> APPROVED
  with UpdateStatus (conditional) before applying anything.
- **The rollouts table holds 3 inventory records from Day 4:** two FAILED (token problems) and one
  CANCELLED (PR #1). ActiveForRole ignores them, so new proposals are allowed.
- **Token hygiene:** the first token was pasted into chat and typed on the command line. It was
  replaced (parameter version 2); the old one should be revoked on GitHub and the
  `put-parameter --value` line removed from ~/.zsh_history.

- **R4 as briefed over-kept (Day 3, decided with the user).** Keeping every configured data-plane action
  for any service Access Advisor marks as used kept s3 Get/Put/DeleteObject and lambda:InvokeFunction
  on * for inventory (it only lists). R4 now needs evidence; roles can override dataPlaneActions
  (ADR-003).
- **Platform calls also reach Access Advisor (Day 3).** Tracked actions include the Lambda runtime's
  logs:CreateLogStream and kms:Decrypt. The profile now has structured `excludedCalls`; a service whose
  only activity is platform calls counts as unused, and shadow skips platform-only actions.
- **Access Advisor lag again (Day 3).** In a 1-day window it reported 1 of 7 services for inventory
  and 0 of 6 for config-reader. Observed calls therefore also count as "used" for R1/R4.
- **Day 4 PR body:** summary.md is ready to paste as the PR description. Proposals encode Resource as
  an array (["*"]), so the first PR diff also changes the Day 1 files' "Resource": "*" formatting.

- **Lambda runtime calls have no invokedBy (Day 2).** At each cold start the role's session makes
  logs:CreateLogStream (user agent `awslambda-worker/1.0`) and kms:Decrypt of the function's own
  environment variables (encryption context `aws:lambda:FunctionArn`, from a Java SDK). The observer
  excludes both, plus every invokedBy call, and counts them in warnings (ADR-002). kms:Decrypt needs
  no permission on the role (quarterly has none and it succeeds); CreateLogStream comes from
  AWSLambdaBasicExecutionRole, which the autopilot never edits.
- **ListFunctions triggers Decrypt of other functions' variables (Day 2).** The 2 invokedBy Decrypt
  calls per inventory run decrypt config-reader's and quarterly's environment variables: Lambda
  does that to answer inventory's lambda:ListFunctions, using inventory's credentials.
- **Access Advisor lag seen live (Day 2).** At 00:39Z it showed iam used at 00:35:59Z but still
  reported ec2/s3/lambda last used on Sep 29, while event history already had the 00:36Z calls.
- **Day 3 generator:** logs:* in quarterly.json duplicates AWSLambdaBasicExecutionRole; the
  generated policy should not need any logs action. The ssm path resource is recorded without its
  trailing slash (parameter/iamap/demo/quarterly); confirm with the policy simulator on Day 4.

- **Service-made events under the role session (Day 2 observer; handled, see ADR-002).** Event history shows `kms:Decrypt`
  with `Username=iamap-demo-inventory` even though the app never calls KMS. The record has
  `userIdentity.invokedBy`, `userAgent` and `sourceIPAddress` all equal to `lambda.amazonaws.com`: it is
  the Lambda service acting for the function. The observer must drop events whose `invokedBy` is an AWS
  service, or the generator would keep `kms:Decrypt` for no reason.
- **Event names are not always IAM action names (Day 2 observer; handled in mapping.go).** Lambda's ListFunctions is recorded
  as `ListFunctions20150331` (API version suffix). The observer needs an eventName -> IAM action
  normalisation step (strip Lambda's date suffixes; check other services in the recorded fixtures).
- **Blind spot confirmed (Day 3).** After run 1, event history for iamap-demo-config-reader shows
  DescribeTable x5 and GetParameter x5 but no GetItem/PutItem, although every run wrote its item.
  CreateLogStream and Decrypt also appear under the demo sessions and need the same invokedBy check.
- Event history latency observed on Day 1: about 3 minutes from invoke to `lookup-events`.
- `s3:ListBuckets` sees 5 buckets in the account (Paved's). The boundary only permits listing, not reading.

## Next

- Day 5: run `aws login --profile paved` and `make traffic`, then paste the Day 5 prompt.
