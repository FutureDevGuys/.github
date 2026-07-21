# Shared Workflows

## Available Workflows

### Renovate

Shared Renovate policy lives in `renovate-config.json`. The scheduled
org runner uses `.github/renovate-config.js` only for self-hosted runtime
settings such as GitHub platform config, autodiscovery, cache, credentials, and
`globalExtends`.

Internal `FutureDevGuys` repos are picked up by the central runner. External
consumers can add a local `renovate.json` containing:

```json
{
  "extends": ["github>FutureDevGuys/.github:renovate-config"]
}
```

Renovate itself never merges PRs; it only creates and labels them. The
self-hosted runtime force-overrides both `automerge` and `platformAutomerge` to
false even if repository policy drifts. The label contract consumed by the
separate sweep is:

- `automerge-candidate` allows hands-off merge after required gates.
- `manual-review`, `major`, and `migration-required` block the shared
  automerge sweep.
- Major updates are visible manual PRs by default. Use repo-local policy only
  for exceptions that should remain dashboard-approved before a PR exists.
- Repo-local `renovate.json` files should add only repo-local policy deltas.
  They may add domain and fail-closed block labels, but the org preset alone
  assigns `automerge-candidate`. Local policy must not enable Renovate merging,
  select a merge type/strategy, assign the candidate label, or remove reserved
  block labels; the scheduled adoption audit enforces that boundary for every
  active repository discovered from the complete paginated organization
  inventory. Local `extends`, `globalExtends`, and `ignorePresets` cannot widen
  or replace the reviewed organization preset.
- Immutable `digest` and `pinDigest` updates do not inherit a release-age gate;
  non-immutable patch and minor updates retain their semantic cooldowns.

The scheduled runner pins both the GitHub Action wrapper and the Renovate image
tag/digest. It resolves the shared preset at the exact workflow commit through
an authenticated API preflight, and it makes at most two attempts inside the
job timeout. The automerge sweep uploads JSONL outcome records containing each
candidate skip reason and PR age. An aged actionable blocker with zero eligible
or merged progress marks the run degraded; policy-blocked manual work is
reported but does not count as an actionable blocker.

The automerge sweep's mutating job is currently source-kill-switched. Its future
path uses squash merges and deletes merged Renovate branches, but it cannot run
until main enforces the named checks, one approval, and conversation resolution;
refresh and merge use distinct dedicated GitHub Apps; and a merge queue or
equivalent server-enforced serialization exists. Exact-head comparison remains
one race guard and is not claimed as atomic serialization.

`.github/automerge-policy.json` is the fail-closed identity and required-check
contract. A candidate must have the exact trusted Renovate principal, the
declared same-repository immutable ID and owner, and only Renovate-authored
commits. The sweep reads check runs and commit statuses from the candidate's
current head SHA, requires every declared check (including `trivy / trivy`), and
requires every observed check/status to be completed successfully. Missing,
pending, skipped, failed, stale, partial, or duplicate required evidence blocks
the merge with a machine-readable reason. It also reads `security-scan.yml` at
that same head and applies the adoption validator against the checked-out org
revision, so a lookalike check name cannot replace the truthful shared caller.

The current Renovate token principal is an ordinary GitHub user, not a dedicated
bot/App; `context/state.md` tracks that residual identity-separation risk.

### `security-scan.yml`

Trivy filesystem scan — checks for vulnerabilities, misconfigurations, secrets, and license issues at HIGH+CRITICAL severity (ignoring unfixed).

**Features:**
- Runs on dependency-bot PRs instead of bypassing them
- Concurrency cancellation for superseded PR/ref scans
- Always uploads `scan-result.json` and `trivy-results.json` as one evidence artifact
- Receipt binds the tool version, caller repository/ref/event/commit, exact org
  workflow revision, policy digests, Trivy schema, counts, report digest, and
  execution outcome
- The final gate independently recomputes HIGH/CRITICAL counts from the uploaded
  report instead of trusting the receipt producer
- Missing, skipped, malformed, non-clean, or digest-mismatched evidence fails closed
- Embedded default `trivy.yaml` — repos without one get the org standard automatically
- The action boundary explicitly enforces vulnerability, misconfiguration,
  secret, and license scanners plus HIGH/CRITICAL severity, so a stale or
  partial repo-local config cannot silently disable a scanner

## How to Adopt in a New Repo

1. Create `.github/workflows/security-scan.yml` with this thin caller:

```yaml
name: security-scan

on:
  workflow_dispatch:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "0 9 * * 0"

permissions:
  contents: read

jobs:
  trivy:
    uses: FutureDevGuys/.github/.github/workflows/security-scan.yml@<SHA>
    with:
      workflow_revision: "<SHA>"
    permissions:
      contents: read
```

WHEN adopting the shared workflow THEN you SHALL replace both `<SHA>` values
with the same exact commit at the protected `security-contract-v1` ref.

You SHALL NOT add a job-level `if`, pass secrets, add another reusable-workflow
input, widen either permissions block beyond `contents: read`, or filter
dependency update pull requests out of this caller.

2. (Optional) Add `trivy.yaml` only for a documented repository-specific delta.
   Validate it with the exact pinned Trivy version; Trivy accepts unknown or
   obsolete key locations without necessarily applying them.
3. (Optional) Add `.trivyignore.yaml` for documented suppressions (include expiry dates).
4. Push — Renovate will auto-track the SHA pin from then on.

## Customization

- **Scan settings:** Prefer no repo-local file. When a real delta is required,
  use the pinned-version schema; for Trivy 0.69 the relevant paths are
  `scan.scanners` and `vulnerability.ignore-unfixed`. The reusable workflow
  still enforces all four scanners and HIGH/CRITICAL severity at the action
  boundary.
- **Suppressions:** Add `.trivyignore.yaml` with documented exceptions. Include `expired_at` dates.
- **Triggers:** Owned by the caller workflow. WHEN adding a caller THEN you SHALL
  enable pull request, push to `main`, weekly schedule, and manual dispatch.

## SHA Pinning and Renovate

Callers pin to a commit SHA in the `uses:` line. Renovate's `github-actions`
manager detects this and opens a labeled bump PR when the `.github` repo gets a
new commit. The org sweep merges that PR only after its identity, current-head
caller, and repository-specific checks satisfy the automerge policy.

The shared preset treats the `uses` SHA and `workflow_revision` as one
`github-digest` dependency on the `.github` repository's
`security-contract-v1` ref. Renovate updates both occurrences in one
replacement; a one-sided update is rejected by the caller contract before it
can appear green. Unrelated policy commits on `main` do not create Trivy caller
updates.

## Security contract release

`security-contract-v1` is the path-scoped authority for the reusable scan
runtime. Its manifest-closed bundle contains the reusable workflow and both
receipt programs. The resolver rejects missing, extra, dynamically imported,
non-blob, linked, gitlink, wrong-mode, or main/release byte-divergent members.

The release audit verifies the immutable repository identity, exact release
SHA, valid GitHub signature, ancestry from `main`, required signatures,
administrator enforcement, linear history, and disabled force-push/deletion on
both branches. Current status checks and reviews are absent, so the policy names
the exact activation-held future contexts and automerge stays source-disabled.
WHEN those protections are enforceable THEN you SHALL advance the policy and
activation gate together before claiming automerge readiness.

The automerge sweep uses the same governance policy but resolves bundle bytes
directly at the protected release SHA. It audits that authority before examining
candidates and again immediately before a merge, with the initially approved
SHA as an exact postcondition. It does not substitute the current `main` or the
workflow checkout SHA for the caller's required security revision.

The release helper separates planning from apply. Its digest binds the policy,
`main`, resolved release commit, observed release ref, and ordered operations.
Existing releases move only by a non-force fast-forward after protection is
verified; first creation is followed immediately by protection and a retained
postcondition receipt. The scheduled/manual workflow runs only the read-only
audit and evidence validator.

An operator can run the same paginated live audit locally through the already
authenticated GitHub CLI without exporting or copying a token:

```bash
policy_revision="$(gh api repos/FutureDevGuys/.github/git/ref/heads/security-contract-v1 --jq '.object.sha')"
python3 .github/scripts/audit_security_scan_adoption.py audit \
  --credential-source gh-session \
  --required-revision "${policy_revision}" \
  --report security-scan-adoption-report.json \
  --receipt security-scan-adoption-receipt.json
```

`gh-session` is explicitly rejected inside GitHub Actions. Scheduled and manual
workflow runs continue to require the dedicated, least-privilege
`SECURITY_AUDIT_TOKEN`; a developer login is not an implicit CI credential.
The report and receipt bind `credential_source` as `token`, `gh-session`, or
`fixture`, so locally produced evidence cannot be mistaken for the hosted
least-privilege audit.

## Updating the Shared Workflow

Edit the closed bundle in this repo (`.github`) → merge it to `main` → advance
`security-contract-v1` with the reviewed release plan → callers receive
Renovate PRs on the next cycle.

## Design Decisions

- **`workflow_call` trigger:** The reusable workflow receives the exact org
  workflow revision and verifies the checked-out receipt validator against it.
  `actions/checkout` checks out the caller's repo first, so per-repo config files
  resolve correctly.
- **Embedded defaults:** Zero-config onboarding - new repos don't need to copy `trivy.yaml`.
- **One immutable revision input:** `workflow_revision` must match the SHA in
  `jobs.trivy.uses`; the adoption audit rejects floating, mismatched, or stale
  callers that do not use the audited org commit.
