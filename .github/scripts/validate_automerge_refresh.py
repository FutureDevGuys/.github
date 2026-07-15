#!/usr/bin/env python3
"""Authorize a stale Renovate PR branch refresh without authorizing a merge."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
PROTECTED_PREFIXES = (".github/",)


def result(
    action: str,
    reason: str,
    detail: str,
    *,
    head_sha: str = "",
    base_sha: str = "",
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "action": action,
        "refresh_eligible": action == "refresh",
        "reason": reason,
        "detail": detail,
        "head_sha": head_sha,
        "base_sha": base_sha,
    }


def blocked(
    reason: str, detail: str, *, head_sha: str = "", base_sha: str = ""
) -> dict[str, Any]:
    return result(
        "block", reason, detail, head_sha=head_sha, base_sha=base_sha
    )


def _repository_policy(
    policy: dict[str, Any], repository: str
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if policy.get("schema_version") != SCHEMA_VERSION:
        return None, blocked(
            "invalid_policy", "automerge policy schema_version must be 1"
        )
    identity = policy.get("trusted_renovate_identity")
    repositories = policy.get("repositories")
    if not isinstance(identity, dict) or not isinstance(repositories, dict):
        return None, blocked(
            "invalid_policy", "identity and repositories mappings are required"
        )
    required_identity_fields = (
        "login",
        "id",
        "commit_name",
        "commit_email",
        "refresh_committer_name",
        "refresh_committer_email",
    )
    if any(
        not isinstance(identity.get(field), str) or not identity[field].strip()
        for field in required_identity_fields
    ) or not isinstance(identity.get("is_bot"), bool):
        return None, blocked(
            "invalid_policy", "trusted Renovate and refresh identities are incomplete"
        )
    repository_policy = repositories.get(repository)
    if not isinstance(repository_policy, dict):
        return None, blocked(
            "repository_not_adopted", f"{repository} is absent from automerge policy"
        )
    repository_id = repository_policy.get("repository_id")
    head_repository_id = repository_policy.get("head_repository_id")
    if (
        not isinstance(repository_id, int)
        or isinstance(repository_id, bool)
        or repository_id <= 0
        or not isinstance(head_repository_id, str)
        or not head_repository_id.strip()
    ):
        return None, blocked(
            "invalid_policy", f"{repository} must bind exact REST and GraphQL IDs"
        )
    return {"identity": identity, "repository": repository_policy}, None


def evaluate_refresh_candidate(
    *,
    repository: str,
    policy: dict[str, Any],
    pull_request: dict[str, Any],
    commits: list[dict[str, Any]],
    changed_files: list[dict[str, Any]],
    comparison: dict[str, Any],
    current_base_sha: str,
) -> dict[str, Any]:
    loaded, error = _repository_policy(policy, repository)
    if error:
        return error
    assert loaded is not None
    identity = loaded["identity"]
    repository_policy = loaded["repository"]

    head_sha = pull_request.get("headRefOid")
    recorded_base_sha = pull_request.get("baseRefOid")
    if not isinstance(head_sha, str) or SHA_RE.fullmatch(head_sha) is None:
        return blocked("invalid_head_sha", "PR headRefOid must be an exact commit SHA")
    if not isinstance(recorded_base_sha, str) or SHA_RE.fullmatch(recorded_base_sha) is None:
        return blocked(
            "invalid_recorded_base_sha",
            "PR baseRefOid must be an exact commit SHA",
            head_sha=head_sha,
        )
    if SHA_RE.fullmatch(current_base_sha) is None:
        return blocked(
            "invalid_current_base_sha",
            "current base revision must be an exact commit SHA",
            head_sha=head_sha,
        )

    if pull_request.get("baseRefName") != "main":
        return blocked(
            "wrong_base",
            "refresh is restricted to the main base branch",
            head_sha=head_sha,
            base_sha=current_base_sha,
        )
    head_ref = pull_request.get("headRefName")
    if not isinstance(head_ref, str) or not head_ref.startswith("renovate/"):
        return blocked(
            "disallowed_head",
            "refresh is restricted to renovate/ branches",
            head_sha=head_sha,
            base_sha=current_base_sha,
        )

    author = pull_request.get("author")
    if not isinstance(author, dict) or any(
        author.get(key) != identity.get(key) for key in ("login", "id", "is_bot")
    ):
        return blocked(
            "untrusted_renovate_identity",
            f"author={author!r} does not match the trusted Renovate principal",
            head_sha=head_sha,
            base_sha=current_base_sha,
        )

    head_repository = pull_request.get("headRepository")
    head_owner = pull_request.get("headRepositoryOwner")
    expected_owner = repository.split("/", 1)[0]
    if (
        not isinstance(head_repository, dict)
        or head_repository.get("nameWithOwner") != repository
        or head_repository.get("id") != repository_policy.get("head_repository_id")
        or not isinstance(head_owner, dict)
        or head_owner.get("login") != expected_owner
    ):
        return blocked(
            "untrusted_head_repository",
            f"head repository must be the policy-owned {repository}",
            head_sha=head_sha,
            base_sha=current_base_sha,
        )

    expected_commit_count = pull_request.get("commitCount")
    if (
        not isinstance(expected_commit_count, int)
        or isinstance(expected_commit_count, bool)
        or expected_commit_count <= 0
        or expected_commit_count > 250
        or not isinstance(commits, list)
        or expected_commit_count != len(commits)
    ):
        return blocked(
            "commit_evidence_incomplete",
            "PR commit evidence is malformed, partially paginated, or exceeds the 250-commit API cap",
            head_sha=head_sha,
            base_sha=current_base_sha,
        )
    if commits[-1].get("sha") != head_sha:
        return blocked(
            "stale_commit_evidence",
            "last PR commit does not equal the current head SHA",
            head_sha=head_sha,
            base_sha=current_base_sha,
        )
    used_refresh_committer = False
    for commit in commits:
        git_commit = commit.get("commit")
        git_author = git_commit.get("author") if isinstance(git_commit, dict) else None
        git_committer = (
            git_commit.get("committer") if isinstance(git_commit, dict) else None
        )
        if not isinstance(git_author, dict) or not isinstance(git_committer, dict):
            return blocked(
                "untrusted_commit_identity",
                "commit identity is missing",
                head_sha=head_sha,
                base_sha=current_base_sha,
            )
        if (
            git_author.get("name") != identity.get("commit_name")
            or git_author.get("email") != identity.get("commit_email")
        ):
            return blocked(
                "untrusted_commit_identity",
                f"commit {commit.get('sha')} author is not the Renovate identity",
                head_sha=head_sha,
                base_sha=current_base_sha,
            )
        trusted_committers = {
            (identity.get("commit_name"), identity.get("commit_email")),
            (
                identity.get("refresh_committer_name"),
                identity.get("refresh_committer_email"),
            ),
        }
        if (git_committer.get("name"), git_committer.get("email")) not in trusted_committers:
            return blocked(
                "untrusted_commit_identity",
                f"commit {commit.get('sha')} committer is neither Renovate nor the policy-bound refresh principal",
                head_sha=head_sha,
                base_sha=current_base_sha,
            )
        if (
            git_committer.get("name") == identity.get("refresh_committer_name")
            and git_committer.get("email") == identity.get("refresh_committer_email")
        ):
            used_refresh_committer = True

    expected_file_count = pull_request.get("changedFiles")
    if (
        not isinstance(expected_file_count, int)
        or isinstance(expected_file_count, bool)
        or not isinstance(changed_files, list)
        or expected_file_count != len(changed_files)
    ):
        return blocked(
            "changed_file_evidence_incomplete",
            "changed-file evidence is malformed or partially paginated",
            head_sha=head_sha,
            base_sha=current_base_sha,
        )
    filenames: list[str] = []
    for changed_file in changed_files:
        filename = changed_file.get("filename") if isinstance(changed_file, dict) else None
        if not isinstance(filename, str) or not filename:
            return blocked(
                "changed_file_evidence_incomplete",
                "every changed file must have a non-empty filename",
                head_sha=head_sha,
                base_sha=current_base_sha,
            )
        filenames.append(filename)
    if len(filenames) != len(set(filenames)):
        return blocked(
            "changed_file_evidence_ambiguous",
            "changed-file evidence contains duplicate paths",
            head_sha=head_sha,
            base_sha=current_base_sha,
        )
    protected_changes = sorted(
        filename
        for filename in filenames
        if any(filename.startswith(prefix) for prefix in PROTECTED_PREFIXES)
    )

    base_commit = comparison.get("base_commit")
    merge_base_commit = comparison.get("merge_base_commit")
    comparison_commits = comparison.get("commits")
    if (
        not isinstance(base_commit, dict)
        or base_commit.get("sha") != current_base_sha
        or not isinstance(merge_base_commit, dict)
        or merge_base_commit.get("sha") != recorded_base_sha
        or not isinstance(comparison_commits, list)
        or not comparison_commits
        or comparison_commits[-1].get("sha") != head_sha
    ):
        return blocked(
            "comparison_evidence_stale",
            "comparison does not bind the current base, recorded base, and exact PR head",
            head_sha=head_sha,
            base_sha=current_base_sha,
        )

    behind_by = comparison.get("behind_by")
    ahead_by = comparison.get("ahead_by")
    status = comparison.get("status")
    if (
        not isinstance(behind_by, int)
        or isinstance(behind_by, bool)
        or behind_by < 0
        or not isinstance(ahead_by, int)
        or isinstance(ahead_by, bool)
        or ahead_by < 0
        or status not in {"ahead", "behind", "diverged", "identical"}
    ):
        return blocked(
            "comparison_evidence_invalid",
            "comparison status and distances must be complete",
            head_sha=head_sha,
            base_sha=current_base_sha,
        )

    if behind_by == 0:
        if recorded_base_sha != current_base_sha:
            return blocked(
                "recorded_base_stale",
                "branch is current but PR baseRefOid does not equal the current base",
                head_sha=head_sha,
                base_sha=current_base_sha,
            )
        if protected_changes and used_refresh_committer:
            return blocked(
                "refresh_committer_protected_change",
                "a refreshed commit cannot alter .github authorization or CI files",
                head_sha=head_sha,
                base_sha=current_base_sha,
            )
        return result(
            "continue",
            "branch_current",
            "branch contains the current base; evaluate merge evidence",
            head_sha=head_sha,
            base_sha=current_base_sha,
        )

    if status not in {"behind", "diverged"}:
        return blocked(
            "comparison_evidence_invalid",
            f"behind_by={behind_by} conflicts with status={status}",
            head_sha=head_sha,
            base_sha=current_base_sha,
        )

    if protected_changes:
        return blocked(
            "protected_caller_changed",
            f"refresh cannot rewrite a PR that changes {', '.join(protected_changes)}",
            head_sha=head_sha,
            base_sha=current_base_sha,
        )

    return result(
        "refresh",
        "branch_refresh_required",
        f"trusted branch is {behind_by} commit(s) behind current base",
        head_sha=head_sha,
        base_sha=current_base_sha,
    )


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--pull-request", type=Path, required=True)
    parser.add_argument("--commits", type=Path, required=True)
    parser.add_argument("--changed-files", type=Path, required=True)
    parser.add_argument("--comparison", type=Path, required=True)
    parser.add_argument("--current-base-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        evaluation = evaluate_refresh_candidate(
            repository=args.repository,
            policy=load_json(args.policy),
            pull_request=load_json(args.pull_request),
            commits=load_json(args.commits),
            changed_files=load_json(args.changed_files),
            comparison=load_json(args.comparison),
            current_base_sha=args.current_base_sha,
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        evaluation = blocked("refresh_evidence_invalid", str(error))
    args.output.write_text(
        json.dumps(evaluation, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(evaluation, sort_keys=True))
    return 0 if evaluation["action"] in {"continue", "refresh"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
