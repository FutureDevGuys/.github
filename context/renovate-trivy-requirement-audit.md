# Renovate and Trivy requirement/evidence audit

This audit maps the approved organization-policy requirements to executable
source evidence. A source contract is not live evidence: the scheduled
cross-repository checks remain held until their declared credentials and runner
admission exist.

| Requirement | Source authority and executable evidence | Disposition |
|---|---|---|
| Exact Renovate runtime | `.github/workflows/renovate.yml` pins the action wrapper by commit and both attempts to the same exact Renovate version and image digest. `test_runtime_and_preset_are_exact_and_retry_is_bounded` exact-compares all pins. | Satisfied in source. |
| Closed Trivy release bundle | `.github/security-contract-governance.json` exact-sets the reusable workflow and its two receipt programs. `security_contract_governance.py` rejects missing, extra, linked, wrong-mode, dynamically imported, or main/release-divergent members and audits the signed protected ref. | Satisfied in source; live scheduled evidence remains subject to Actions admission. |
| Authenticated preset read | The Renovate preflight requires `RENOVATE_TOKEN`, verifies the principal, and reads `renovate-config.json` through authenticated `gh api` at the exact workflow commit before the runtime uses the same immutable preset URI. Mutable preset syntax is rejected by the runtime config and tests. | Satisfied in source. |
| Bounded transient retry | Credential, preset, and repository-visibility failures stop in preflight. A remaining Renovate action failure receives one delayed retry inside a 90-minute job; there is no third attempt. The pinned upstream action exposes no structured failure-class output, so this is a bounded best-effort retry and not a claim that every remaining failure is transient. | Satisfied to the available action boundary; changing to dedicated GitHub Apps is the planned authority improvement. |
| Immutable digest age | The final `digest`/`pinDigest` rule exact-resets `minimumReleaseAge` to null and keeps strict internal checks. Negative tests protect the override. | Satisfied in source. |
| Semantic cooldowns | Ordinary minor, patch, and mutable pin updates use a three-day minimum release age with strict internal checks. Docker and GitHub Actions patch/minor lanes repeat that contract. | Satisfied in source. |
| Stateful, database, and incompatible majors | The universal major rule adds `manual-review` and `major`; the sweep blocks both labels. Renovate itself is force-configured never to merge. Repository owners may add `migration-required`, which is also a blocking label. The adoption validator prevents local policy from assigning `automerge-candidate` or removing a reserved block label, so local precedence cannot silently reclassify a major. | Satisfied in source. |
| Explicit skip reason and age | Every candidate outcome is recorded as JSONL with reason, detail, creation/observation time, computed age, and whether it blocks progress. The summary degrades on aged actionable skips even when another PR merged or refreshed. | Satisfied in source. |
| Truthful Trivy execution evidence | A scan step always produces a receipt and report artifact. The validator requires `executed=true`, a nonempty tool version, exact caller context and workflow revision, current Trivy schema, positive report size, matching digest/counts, clean action outcome, and independently recomputed HIGH/CRITICAL counts. Missing, skipped, malformed, stale-context, or tampered evidence fails. | Satisfied in source. |
| Minimal caller and adoption | Every active repository discovered through paginated organization inventory must byte-match the release-pinned caller. Default branches resolve once to immutable commits; lifecycle, visibility totals, caller bytes, effective Renovate policy, report bytes, and receipt digests are bound. The PR fixture includes `shellrc.d` and executes without a private token; the live audit remains scheduled/manual and credential-held. | Satisfied in source; current consumers still fail the live audit. |
| Path-scoped caller release | Renovate tracks `security-contract-v1`; the adoption job and automerge sweep resolve that exact protected commit rather than using `${{ github.sha }}` from unrelated `main`. Automerge audits the closed, signed, protected release before candidate evaluation and re-audits the same SHA immediately before merge. | Corrected in this change. |

## Truthful holds

- Refresh and merge still share an ordinary-user PAT. Separate least-privilege
  GitHub App identities are required before principal separation is
  cryptographic.
- `SECURITY_AUDIT_TOKEN` is absent, so private cross-repository adoption cannot
  be called operational.
- Representative private-repository jobs still report Actions spending/admission
  failures. That does not apply to the public authority fixture contract and is
  not used as the reason for absent public branch protections. The public
  policy branches currently lack required checks/reviews, so automerge remains
  explicitly source-kill-switched.
- Refresh and merge do not have distinct GitHub App identities or a proven
  merge queue/equivalent serialization. Exact-head compare-and-swap does not
  close the base/check/status race.
- Private-repository branch-rule enforcement is unavailable under the current
  organization plan. The sweep fails closed, but it cannot prevent a separate
  human direct push or merge.
