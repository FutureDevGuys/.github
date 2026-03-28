# Shared Workflows

## Available Workflows

### `security-scan.yml`

Trivy filesystem scan — checks for vulnerabilities, misconfigurations, secrets, and license issues at HIGH+CRITICAL severity (ignoring unfixed).

**Features:**
- Dependency-bot PR detection (Renovate/Dependabot) — skips scan, keeps check green
- Concurrency cancellation for superseded PR/ref scans
- JSON artifact upload (`trivy-results`) only on failure or manual dispatch
- PR step summary with vuln/misconfig counts
- Gate enforcement — fails the job on HIGH/CRITICAL findings
- Embedded default `trivy.yaml` — repos without one get the org standard automatically

## How to Adopt in a New Repo

1. Create `.github/workflows/security-scan.yml` with this thin caller:

```yaml
name: security-scan

on:
  workflow_dispatch:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]

permissions:
  contents: read

jobs:
  trivy:
    uses: FutureDevGuys/.github/.github/workflows/security-scan.yml@<SHA>
    with:
      is_dependency_bot_pr: ${{ github.event_name == 'pull_request' && (
        github.actor == 'renovate[bot]' ||
        github.actor == 'dependabot[bot]' ||
        startsWith(github.head_ref, 'renovate/') ||
        startsWith(github.head_ref, 'dependabot/')
      ) }}
    permissions:
      contents: read
```

Replace `<SHA>` with the current commit SHA of the `.github` repo's main branch.

2. (Optional) Add `trivy.yaml` in your repo root to override the default scan settings.
3. (Optional) Add `.trivyignore.yaml` for documented suppressions (include expiry dates).
4. Push — Renovate will auto-track the SHA pin from then on.

## Customization

- **Scan settings:** Override by placing a `trivy.yaml` in your repo root. The reusable workflow checks for it first; if absent, it writes the org default (HIGH+CRITICAL, ignore-unfixed, vuln/misconfig/secret/license scanners).
- **Suppressions:** Add `.trivyignore.yaml` with documented exceptions. Include `expired_at` dates.
- **Triggers:** Owned by the caller workflow. The default caller should keep `pull_request` + `workflow_dispatch` only. Add extra triggers only as an explicit repo override.

## SHA Pinning and Renovate

Callers pin to a commit SHA in the `uses:` line. Renovate's `github-actions` manager detects this and auto-bumps when the `.github` repo gets new commits. The org's automerge rules merge these bump PRs automatically.

## Updating the Shared Workflow

Edit in this repo (`.github`) → push to main → all callers receive Renovate PRs on the next cycle.

## Design Decisions

- **`workflow_call` trigger:** The reusable workflow receives a caller-provided `is_dependency_bot_pr` input instead of trying to infer Renovate/Dependabot state from callee context. `actions/checkout` checks out the caller's repo, so per-repo config files resolve correctly.
- **Embedded defaults:** Zero-config onboarding - new repos don't need to copy `trivy.yaml`.
- **Single boolean input:** The dependency-bot skip is computed in the caller workflow where `pull_request` context exists, then passed through to the shared workflow for consistent enforcement.
