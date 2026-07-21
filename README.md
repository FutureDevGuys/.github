# FutureDevGuys Org Automation

This repository is the shared automation home for `FutureDevGuys`.

## Renovate

- Shared preset: `renovate-config.json`
- Scheduled runtime: `.github/renovate-config.js` plus `.github/workflows/renovate.yml`
- Scope: org autodiscovery for `FutureDevGuys/*`
- Runtime contract: exact action SHA, exact Renovate tag and image digest, and an
  authenticated shared preset pinned to the workflow commit
- Failure contract: at most two Renovate attempts per run; automerge skips emit
  reason-and-age evidence and aged zero-progress runs degrade
- PR merge policy: the self-hosted runtime force-disables Renovate merge
  execution and Renovate only labels candidates. The separate sweep is
  source-kill-switched until required checks/reviews, distinct GitHub App
  identities, and server-enforced merge serialization exist. Its dormant path validates
  the exact Renovate principal, same-repository ID, commit identity, immutable
  Trivy caller, and explicit successful checks for the current head SHA before a
  squash merge with branch deletion.

Repo-specific policy remains in each repository's own `renovate.json` (e.g.
Docker image review rules, version pin managers, submodule pointer policy).
Major updates are created as visible manual PRs with block labels; repo-local
policy can opt individual migration-heavy classes into dashboard approval and
add fail-closed block labels. The org preset exclusively owns
`automerge-candidate`; local policy cannot assign it or remove reserved block
labels.

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

Required checks and immutable repository identities live in
`.github/automerge-policy.json`. Missing, pending, skipped, stale-head, failed,
or ambiguously duplicated checks block and are recorded as outcome reasons.
The sweep also rejects a candidate whose current-head security caller is not a
truthful adopter of the exact checked-out org workflow revision.
The scheduled adoption audit discovers the complete paginated organization
inventory, resolves every active default branch once to an immutable commit,
and reads callers and optional `renovate.json` only at that commit. It rejects
inherited presets, direct Renovate automerge settings, local candidate-label
ownership, and reserved-label removal. The public PR fixture exercises the
same lifecycle, byte-exact caller, effective-config, report, and receipt paths
without a private token.

Trivy caller updates follow the protected `security-contract-v1` release ref,
not the unrelated organization-policy `main` tip. The adoption audit resolves
that ref to one exact commit and requires both caller pins to equal it.

## Required Actions secrets

- `RENOVATE_TOKEN`
- `SECURITY_AUDIT_TOKEN` with read access to every private repository visible
  in the complete `FutureDevGuys` organization inventory
- `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` when private Docker Hub access is needed
- `GHCR_USERNAME` and `GHCR_TOKEN` when private GHCR access is needed

WHEN configuring the scheduled security adoption audit THEN you SHALL provide
`SECURITY_AUDIT_TOKEN`; the repository-scoped workflow token cannot enumerate
private sibling repositories. WHEN enabling the root skill-projection job THEN
you SHALL also expose that read token to `FutureDevGuys/personal-containers` so
Actions can check out the exact private submodule gitlinks.

An optional portable Docker runner can extend this preset at runtime. It should
default to explicit repositories, not broad token autodiscovery.

## Security contract release authority

The reusable Trivy runtime is versioned by the protected
`security-contract-v1` branch. `.github/security-contract-governance.json`
declares the exact runtime bundle and protection contract;
`.github/scripts/security_contract_governance.py` resolves the newest `main`
commit that changed that closed bundle and audits its signed release ref,
ancestry, and branch protections.

The scheduled/manual `security-contract` workflow is read-only. It retains a
digest-bound report and receipt, and fails when the release ref, signature,
ancestry, bundle closure, or protection state drifts. The current public-policy
branches do not enforce required checks, reviews, or conversation resolution.
Policy therefore records the exact future check set as `activation_held`, and
the separate automerge workflow validates an explicit source kill switch before
its mutating job can exist in the run graph. This is a hold, not enforcement.

The automerge sweep resolves the closed bundle directly from the protected
`security-contract-v1` ref at admission and re-audits that same revision at the
merge boundary. Candidate callers are compared with that approved immutable
revision, not the workflow checkout or mutable `main`; a moved, unsigned,
unprotected, non-ancestor, or non-closed release holds the merge and retains the
authority evidence with the candidate artifacts.

Release changes use an operator-reviewed plan:

```bash
python3 .github/scripts/security_contract_governance.py \
  plan-release --main-ref origin/main --out /tmp/security-contract-release-plan.json
python3 .github/scripts/security_contract_governance.py \
  apply-release --plan /tmp/security-contract-release-plan.json \
  --approve <plan-digest> --receipt /tmp/security-contract-release-receipt.json
```

The apply helper exact-sets the currently approved release protection, permits
only a fast-forward of an existing release ref, and requires a successful
remote postcondition audit. If stronger status checks are already configured,
planning stops and requires the policy to advance instead of removing them.
WHEN creating the release branch for the first time THEN you SHALL use this
helper and retain its receipt. You SHALL NOT run the apply command from Actions,
force the release ref, or enable automerge until every activation precondition
is enforced and independently audited.
