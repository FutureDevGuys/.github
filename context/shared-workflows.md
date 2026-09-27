# Shared Workflows

## Available Workflows

### Renovate

The [repository README](../README.md#renovate) owns the shared dependency-automation workflow, current scheduling, encrypted cache/diagnostics, signing, and human approval interface. Native Renovate extraction and generic classification apply to every adopter. Repositories own optional package rules and hash-verified post-upgrade tasks in their own `renovate.json`; the central runner does not maintain workload path lists or script-version inventories.

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
