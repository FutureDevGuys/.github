# FutureDevGuys Org Automation

This repository is the shared automation home for `FutureDevGuys`.

## Renovate

The shared preset is `renovate-config.json`; `.github/renovate-config.js` contains runtime configuration only. Active repositories opt in with the minimal dependency-automation marker below. They inherit the shared defaults without needing a local Renovate configuration. Repositories can add ordinary `renovate.json` package rules for their own approval requirements, disabled managers, or native post-upgrade tasks.

The default pipeline runs Renovate every six hours, then immediately runs the central merge sweep. The sweep also runs hourly for recovery. Renovate creates signed commits and labels candidates; the separate merge owner verifies repository and author identity, current base/head, all observed check/status results, GitHub mergeability, and merge postconditions. It can refresh a trusted branch and re-evaluate it in the same run. Conflicts or unsigned branches blocked by repository protection request native Renovate reconstruction, with at most one targeted recovery run in a dispatch chain. Signature enforcement follows each repository's protection; a native GitHub rebase that loses a signature does not introduce a new global hold on repositories without that requirement.

Minor, patch, pin, digest, lockfile-maintenance and rollback updates are automatically eligible after the configured release-age and check requirements. Major upgrades and replacements are created with a persistent `manual-review` label and require one current-head maintainer approval before the checked merge path. The Dependency Dashboard remains available for visibility and rebase requests; creation approval is not used as proof of merge approval. There is no central list of workload paths or repository-specific exceptions. Each repository owns any additional approval policy.

For existing manually held PRs, an approved review from a maintainer must target the current head. A maintainer who is also the PR author can instead add a label named `merge:<full-head-SHA>`, for example `merge:0123456789abcdef0123456789abcdef01234567`. The sweep verifies the labeling actor's write access and the exact current head. `do-not-merge`, failing contracts, failing/pending checks, and GitHub branch protection remain effective. A newer commit invalidates an earlier head-specific approval.

The sweep refreshes or requests a signed rebuild of a trusted manually held PR before waiting for approval, so the reviewer receives a current merge candidate. Repositories that need extra approval must configure `addLabels: ["manual-review"]` in the relevant package rule. That merge-time rule protects both existing and future PRs. Native dashboard approval only controls PR creation and must not be confused with merge authorization. Renovate preserves labels edited by another account, so an initial migration may also require reconciling old missing classification labels once.

### Latest Docker images

Use normal Compose syntax: `image: vendor/application:latest@sha256:<current-digest>`. Renovate's built-in Compose manager updates the digest while preserving `latest`. The shared preset enables digest pinning and applies no release-age delay to digest updates. A plain `latest` tag is initially pinned by Renovate; no executable comment or per-image central rule is needed. A Git-backed deployment owner can deploy the merged change through its normal webhook.

### Version annotations

The shared regex manager supports `# renovate: datasource=github-releases depName=owner/repo` followed by a YAML field such as `my_tool_version: "v1.2.3"`. Field names end in `_version` or `_VERSION`; this is for versions not already understood by a native manager. It does not turn arbitrary Compose comments into policy directives.

### Optional repository-owned hooks

Native `postUpgradeTasks` are opt-in. The shared runtime permits only a fixed Python command form that verifies a repo-owned script's SHA-256 before execution, clears its inherited environment, and supplies one literal argument. The approved relative path, hash, argument, and output `fileFilters` live in that repository's `renovate.json`, and must be updated alongside its script. The command-pattern contract is tested in `.github/tests/test_dependency_pipeline.py`. This is a source-integrity and credential-environment boundary, not a sandbox for untrusted repository owners. Do not enable arbitrary shell commands in the shared runner.

### Privacy and API limits

Detailed logs and private merge evidence are encrypted before upload; only aggregate outcome counts are published in plaintext. The complete Renovate lookup/HTTP/repository cache is also encrypted and restored between runs. Encryption uses the existing automation credential through GnuPG's standard-input interface, so credential rotation intentionally invalidates older cache/diagnostic artifacts. Administrators with custody of that credential can decrypt retained artifacts with `.github/scripts/private_artifacts.py`; never paste the credential into arguments or logs.

The runtime passes both the platform token and `GITHUB_COM_TOKEN`, with an explicit authenticated GitHub host rule. A dedicated `GITHUB_COM_TOKEN` secret is used when present, otherwise the existing platform token is reused. This avoids anonymous GitHub API limits during preset/changelog/tool lookup. The low per-repository PR creation rate and complete persistent cache reduce repeat work. Open review-held PRs do not consume a concurrent-PR or branch cap, so they cannot starve routine updates; the API-budget guard and runtime timeout still bound each run. Only the two newest encrypted cache snapshots are retained, avoiding storage growth from four runs per day; private diagnostics expire separately after seven days. Network/server failures get one bounded retry; authentication/configuration failures and exhausted API budgets do not trigger a futile retry loop. Scheduled runs provide recovery after provider outages or quota resets.

## Required Actions secrets

- `RENOVATE_TOKEN` for the configured automation principal
- `RENOVATE_GIT_PRIVATE_KEY`, a dedicated signing-only private key whose public key is registered with that principal
- `SECURITY_AUDIT_TOKEN` with read access to every private repository declared
  in `.github/security-scan-adopters.json`
- `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` when private Docker Hub access is needed
- `GHCR_USERNAME` and `GHCR_TOKEN` when private GHCR access is needed

WHEN configuring the manual security adoption audit THEN you SHALL provide
`SECURITY_AUDIT_TOKEN`; the repository-scoped workflow token cannot enumerate
private sibling repositories. WHEN enabling the root skill-projection job THEN
you SHALL also expose that read token to `FutureDevGuys/personal-containers` so
Actions can check out the exact private submodule gitlinks.

An optional portable Docker runner can extend this preset at runtime. It should
default to explicit repositories, not broad token autodiscovery.

## Execution policy

Renovate runs every six hours at minute 17; the merge recovery sweep runs hourly at minute 37. Both support `workflow_dispatch` from this repository's `main`. These remain the only automatically triggered custom workflows. Security and owner-specific CI remain subject to their separately declared policy.

Both runners derive adopters from exact default-branch commits and the same minimal marker. Ambiguous identities, unreadable or partial inventory, and malformed present markers fail closed. The merge workflow derives its repository identities from that receipt; optional identity assertions follow immutable repository IDs through renames. The policy owner is included implicitly.

The historical signing identity can be supplied through the optional `RENOVATE_GIT_IGNORED_AUTHORS` Actions variable during migration so Renovate can rebuild its own old branches. It does not authorize overwriting unrelated human edits. The current Git author is derived from the authenticated GitHub principal's verified noreply identity.

## Dependency-automation marker

To participate, install this exact file as
`.github/workflows/dependency-automation.yml`, replacing `<SHA>` with one
40-character commit SHA from this repository:

```yaml
name: dependency-automation

on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  adopt:
    uses: FutureDevGuys/.github/.github/workflows/dependency-automation-marker.yml@<SHA>
    permissions:
      contents: read
```

The marker is manual-only and contains no runtime policy. The central parser
requires this byte shape and rejects a mutable ref, another trigger, widened
permissions, inputs, secrets, conditions, steps, or an additional job. Shared
behavior remains in this repository; normal scheduled runs do not invoke the
marker workflow.

Repository-specific CI opt-outs and cross-owner release approvals belong in local Renovate configuration; they are not shared defaults.
