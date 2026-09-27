# FutureDevGuys organization automation policy

## Authority and scope

This repository owns shared GitHub dependency automation and reusable security
workflows for the `FutureDevGuys` organization. Repository-local workflow callers are markers only. The shared default and runner live here; repository-specific dependency policy and native post-upgrade tasks belong in each repository's Renovate configuration. Do not add workload paths, package exceptions, repository-name lists, or owner-script hashes to the central runtime.

Renovate and automerge are the only custom workflows that MAY have automatic
triggers. Both SHALL retain a schedule and `workflow_dispatch`. Security and
other custom workflows SHALL be `workflow_dispatch`-only or
`workflow_call`-only.

## Dependency automation adoption

An active repository opts in through the byte-exact
`.github/workflows/dependency-automation.yml` contract rendered and validated by
`.github/scripts/resolve_dependency_automation_adopters.py`. The caller SHALL
contain one manual trigger, read-only permissions, and one exact-SHA call to the
central marker workflow. It SHALL NOT contain business logic, inputs, secrets,
conditions, additional jobs, permission expansion, or another trigger.

Both central runners SHALL resolve the complete token-visible organization
inventory and use the same valid-marker target rule. A present invalid caller,
partial inventory, unreadable default commit/tree/blob, mutable shared ref, or
ambiguous repository identity SHALL fail closed. The organization `.github`
repository is the implicit policy owner and does not need to call itself.
After a successful non-dry-run Renovate execution, the central workflow SHALL
dispatch the central automerge workflow with the central automation credential.
The scheduled automerge sweep remains the recovery backstop; repository-local
callers SHALL NOT receive write permissions or duplicate event logic.

## Merge safety

Renovate SHALL create and label candidates but SHALL NOT merge. The automerge
sweep SHALL retain exact repository, author, commit, head, base, check/status,
central-authority, and merge-postcondition gates. Major upgrades and replacements require one current-head maintainer merge approval by default. Their package rules retain the manual-review label so already-open PRs cannot bypass the approval boundary. Native dashboard creation approval is not merge authorization. Repositories declare any additional migration or workload approval requirements locally. Explicit do-not-merge holds and failing contracts are never bypassed. A current-head approval from a maintainer may release a manual review hold; stale approvals cannot authorize a changed head.

Only aggregate outcome counts may be public artifacts. Private repository evidence, complete Renovate lookup caches, and detailed logs must be encrypted before upload. Cache encryption uses the existing automation credential through standard input; never print it or pass it in command arguments. Signing keys remain in Actions secrets, and their public halves are registered only for commit signing.

## State and verification

Use `context/state.md` only for incomplete work, active risks, and future plans;
remove resolved items rather than recording completion. Workflow changes SHALL
pass the repository unit suite and actionlint before commit.
