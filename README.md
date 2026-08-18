# FutureDevGuys Org Automation

This repository is the shared automation home for `FutureDevGuys`.

## Renovate

- Shared preset: `renovate-config.json`
- Scheduled and manual runtime: `.github/renovate-config.js` plus `.github/workflows/renovate.yml`
- Scope: org autodiscovery for `FutureDevGuys/*`
- Runtime contract: exact action SHA, exact Renovate tag and image digest, and an
  authenticated shared preset pinned to the workflow commit
- Failure contract: at most two Renovate attempts per run; automerge skips emit
  reason-and-age evidence and aged zero-progress runs degrade
- PR merge policy: the self-hosted runtime force-disables Renovate merge
  execution and Renovate only labels candidates. The separate sweep validates
  the exact Renovate principal, same-repository ID, commit identity, block
  labels, and every check or status that exists for the current head SHA before
  a squash merge with branch deletion. Repositories with intentionally disabled
  custom CI may have zero check records.

Repo-specific policy remains in each repository's own `renovate.json` (e.g.
Docker image review rules, version pin managers, submodule pointer policy).
Major updates are created as visible manual PRs with block labels; repo-local
policy can opt individual migration-heavy classes into dashboard approval.

Internal `FutureDevGuys` repos are covered by the central runner and normally
do not need a local Renovate config. External consumers can opt in with:

```json
{
  "extends": ["github>FutureDevGuys/.github:renovate-config"]
}
```

### Version pin annotations

The shared preset includes a generic regex manager that tracks
`# renovate:` comment annotations in any YAML file across the org.
To pin a version and let Renovate auto-bump it, add this pattern:

```yaml
# renovate: datasource=github-releases depName=owner/repo
my_tool_version: "v1.2.3"
```

The variable must end with `_version` and the value must be quoted.
Supported `datasource` values include `github-releases`, `github-tags`,
`pypi`, `npm`, etc. — see [Renovate datasources](https://docs.renovatebot.com/modules/datasource/).

No per-repo `renovate.json` change is needed inside `FutureDevGuys` to use
this — the org preset picks it up automatically.

Immutable repository identities live in `.github/automerge-policy.json`.
Pending, skipped, stale-head, or failed observed checks and statuses block and
are recorded as outcome reasons. The manually dispatched adoption audit reads
every declared repo-local
`renovate.json` and rejects direct Renovate automerge settings, preserving the
separate sweep as the only automated merge executor.

## Required Actions secrets

- `RENOVATE_TOKEN`
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

Renovate runs daily at 03:17 UTC and automerge sweeps at 05:37 and 17:37 UTC;
both also support explicit `workflow_dispatch` from this repository's `main`
branch. They are the only automatically triggered workflows in the managed
repositories. Security workflows remain manual and disabled, while repository-
local custom workflows remain disabled.

Dependency automation runs centrally because reusable workflows called by a
private repository are billed to that private repository and cannot read this
repository's secrets. Renovate autodiscovers non-archived `FutureDevGuys`
repositories, while `.github/automerge-policy.json` is the explicit automerge
adoption list. Adding a repository therefore requires central policy only—not a
caller workflow or duplicated credentials.
GitHub Actions dependencies in target repositories are ignored while their
custom CI remains intentionally disabled; the central `.github` repository
continues to manage its own active Renovate and automerge action pins.
Root Go and Cargo updates receive `manual-review` because they participate in
cross-language frozen-source and release contracts that Renovate cannot
regenerate safely.
