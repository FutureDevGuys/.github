# Shared Workflows

## Available Workflows

### Renovate

Shared Renovate policy lives in `renovate-config.json`. The daily
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
  They may label candidates but must not enable Renovate merging or select a
  merge type/strategy; the scheduled adoption audit enforces that boundary for
  every repository listed in `renovate_config_repositories`.
- Immutable `digest` and `pinDigest` updates do not inherit a release-age gate;
  non-immutable patch and minor updates retain their semantic cooldowns.

The scheduled runner pins both the GitHub Action wrapper and the Renovate image
tag/digest. It resolves the shared preset at the exact workflow commit through
an authenticated API preflight, and it makes at most two attempts inside the
job timeout. The automerge sweep uploads JSONL outcome records containing each
candidate skip reason and PR age. An aged actionable blocker with zero eligible
or merged progress marks the run degraded; policy-blocked manual work is
reported but does not count as an actionable blocker.

The twice-daily automerge sweep uses squash merges and deletes merged Renovate branches. The
org repositories are configured to allow squash merges only, so manual PR merges
use the same history shape as the automation.

`.github/automerge-policy.json` is the fail-closed identity and repository
adoption contract. A candidate must have the exact trusted Renovate principal,
the declared same-repository immutable ID and owner, and only Renovate-authored
commits. Every check run or commit status that exists for the current head must
be complete and successful; repositories with intentionally disabled custom CI
may have zero check records. Pending, skipped, failed, stale, partial, or
ambiguous observed evidence blocks the merge. Block labels, current-base
containment, GitHub mergeability, central-authority freshness, and exact-head
compare-and-swap remain mandatory.

The runners live only in this public `.github` repository so their runtime uses
the central credentials and does not consume private-repository Actions minutes.
Target repositories do not carry dependency-automation callers. Renovate uses
org autodiscovery; adding an immutable repository entry to
`.github/automerge-policy.json` opts it into the merge sweep.
The runtime disables the `github-actions` manager for target repositories while
their custom CI is intentionally disabled. This prevents inactive workflow
files from creating dependency PR noise without weakening pin management for
the two active workflows in this repository.

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
with the same exact commit SHA from the `.github` repository after that org
commit exists.

You SHALL NOT add a job-level `if`, pass secrets, add another reusable-workflow
input, widen either permissions block beyond `contents: read`, or filter
dependency update pull requests out of this caller.

2. (Optional) Add `trivy.yaml` only for a documented repository-specific delta.
   Validate it with the exact pinned Trivy version; Trivy accepts unknown or
   obsolete key locations without necessarily applying them.
3. (Optional) Add `.trivyignore.yaml` for documented suppressions (include expiry dates).
4. Push — while security automation remains disabled, later revision changes are
   manual and do not generate Renovate PRs.

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

Security callers pin to a commit SHA in the `uses:` line. The shared Renovate
preset intentionally does not manage those disabled callers. If security
automation is re-enabled later, update both the `uses` SHA and
`workflow_revision` together and restore an atomic manager only with its caller
contract tests.

## Updating the Shared Workflow

Edit in this repo (`.github`) → validate → merge to `main`. Active dependency
automation consumes the new central behavior on its next scheduled run.

## Design Decisions

- **`workflow_call` trigger:** The reusable workflow receives the exact org
  workflow revision and verifies the checked-out receipt validator against it.
  `actions/checkout` checks out the caller's repo first, so per-repo config files
  resolve correctly.
- **Embedded defaults:** Zero-config onboarding - new repos don't need to copy `trivy.yaml`.
- **One immutable revision input:** `workflow_revision` must match the SHA in
  `jobs.trivy.uses`; the adoption audit rejects floating, mismatched, or stale
  callers that do not use the audited org commit.
