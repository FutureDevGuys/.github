# FutureDevGuys organization automation policy

## Authority and scope

This repository owns shared GitHub dependency automation and reusable security
workflows for the `FutureDevGuys` organization. Repository-local dependency
automation files are markers only; shared policy and executable behavior SHALL
remain here.

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

## Merge safety

Renovate SHALL create and label candidates but SHALL NOT merge. The automerge
sweep SHALL retain exact repository, author, commit, head, base, check/status,
central-authority, and merge-postcondition gates. Major, database, stateful,
migration-bearing, manually held, or contract-failing changes SHALL remain
ineligible for automatic merge. The central risk-path policy SHALL hold known
persistent workload roots independently of Renovate labels; repository callers
SHALL NOT duplicate that classification.

## State and verification

Use `context/state.md` only for incomplete work, active risks, and future plans;
remove resolved items rather than recording completion. Workflow changes SHALL
pass the repository unit suite and actionlint before commit.
