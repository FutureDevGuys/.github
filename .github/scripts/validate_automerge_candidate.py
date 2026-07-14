#!/usr/bin/env python3
"""Fail-closed identity, adoption, and current-head CI gate for automerge."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from audit_security_scan_adoption import validate_caller  # noqa: E402


SCHEMA_VERSION = 1
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def blocked(reason: str, detail: str, head_sha: str = "") -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "eligible": False,
        "reason": reason,
        "detail": detail,
        "head_sha": head_sha,
    }


def eligible(head_sha: str, check_count: int, status_count: int) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "eligible": True,
        "reason": "eligible",
        "detail": f"validated {check_count} check runs and {status_count} commit statuses",
        "head_sha": head_sha,
    }


def _load_repository_policy(
    policy: dict[str, Any], repository: str
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if policy.get("schema_version") != SCHEMA_VERSION:
        return None, blocked("invalid_policy", "automerge policy schema_version must be 1")
    identity = policy.get("trusted_renovate_identity")
    repositories = policy.get("repositories")
    if not isinstance(identity, dict) or not isinstance(repositories, dict):
        return None, blocked("invalid_policy", "identity and repositories mappings are required")
    repository_policy = repositories.get(repository)
    if not isinstance(repository_policy, dict):
        return None, blocked("repository_not_adopted", f"{repository} is absent from automerge policy")
    required_checks = repository_policy.get("required_checks")
    if not isinstance(required_checks, list) or not required_checks:
        return None, blocked("invalid_policy", f"{repository} has no required checks")
    if not all(
        isinstance(item, dict)
        and isinstance(item.get("name"), str)
        and item["name"].strip()
        and isinstance(item.get("app_slug"), str)
        and item["app_slug"].strip()
        for item in required_checks
    ):
        return None, blocked("invalid_policy", f"{repository} required checks are malformed")
    if not any(item["name"] == "trivy / trivy" for item in required_checks):
        return None, blocked("invalid_policy", f"{repository} must require truthful trivy")
    return {"identity": identity, "repository": repository_policy}, None


def evaluate_candidate(
    *,
    repository: str,
    policy: dict[str, Any],
    pull_request: dict[str, Any],
    commits: list[dict[str, Any]],
    checks: dict[str, Any],
    statuses: dict[str, Any],
    caller_text: str,
    required_security_revision: str,
) -> dict[str, Any]:
    loaded, error = _load_repository_policy(policy, repository)
    if error:
        return error
    assert loaded is not None
    identity = loaded["identity"]
    repository_policy = loaded["repository"]

    head_sha = pull_request.get("headRefOid")
    if not isinstance(head_sha, str) or SHA_RE.fullmatch(head_sha) is None:
        return blocked("invalid_head_sha", "PR headRefOid must be an exact commit SHA")
    if SHA_RE.fullmatch(required_security_revision) is None:
        return blocked(
            "invalid_security_revision",
            "required security workflow revision must be an exact commit SHA",
            head_sha,
        )

    author = pull_request.get("author")
    if not isinstance(author, dict) or any(
        author.get(key) != identity.get(key) for key in ("login", "id", "is_bot")
    ):
        return blocked(
            "untrusted_renovate_identity",
            f"author={author!r} does not match the trusted Renovate principal",
            head_sha,
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
            head_sha,
        )

    if not isinstance(commits, list) or not commits:
        return blocked("commit_evidence_missing", "PR commit evidence is empty", head_sha)
    if commits[-1].get("sha") != head_sha:
        return blocked(
            "stale_commit_evidence",
            "last PR commit does not equal the current head SHA",
            head_sha,
        )
    for commit in commits:
        git_commit = commit.get("commit")
        git_author = git_commit.get("author") if isinstance(git_commit, dict) else None
        git_committer = git_commit.get("committer") if isinstance(git_commit, dict) else None
        if not isinstance(git_author, dict) or not isinstance(git_committer, dict):
            return blocked("untrusted_commit_identity", "commit identity is missing", head_sha)
        for role, value in (("author", git_author), ("committer", git_committer)):
            if (
                value.get("name") != identity.get("commit_name")
                or value.get("email") != identity.get("commit_email")
            ):
                return blocked(
                    "untrusted_commit_identity",
                    f"commit {commit.get('sha')} {role} is not the Renovate identity",
                    head_sha,
                )

    caller_errors = validate_caller(caller_text, required_security_revision)
    if caller_errors:
        return blocked(
            "invalid_security_caller",
            "; ".join(caller_errors),
            head_sha,
        )

    check_runs = checks.get("check_runs")
    total_count = checks.get("total_count")
    if (
        not isinstance(check_runs, list)
        or not isinstance(total_count, int)
        or isinstance(total_count, bool)
        or total_count != len(check_runs)
    ):
        return blocked(
            "check_evidence_incomplete",
            "check-runs response is missing, malformed, or partially paginated",
            head_sha,
        )
    required_checks = repository_policy["required_checks"]
    for required in required_checks:
        matches = [
            check
            for check in check_runs
            if check.get("name") == required["name"]
            and isinstance(check.get("app"), dict)
            and check["app"].get("slug") == required["app_slug"]
        ]
        if not matches:
            return blocked(
                "required_check_missing",
                f"missing {required['app_slug']} check {required['name']}",
                head_sha,
            )
        if len(matches) != 1:
            return blocked(
                "required_check_ambiguous",
                f"expected one {required['name']} check, found {len(matches)}",
                head_sha,
            )

    for check in check_runs:
        name = str(check.get("name", "<unnamed>"))
        if check.get("head_sha") != head_sha:
            return blocked(
                "stale_check_run",
                f"check {name} does not target current head {head_sha}",
                head_sha,
            )
        status = str(check.get("status", "")).lower()
        conclusion = str(check.get("conclusion", "")).lower()
        if status != "completed":
            return blocked(
                "check_pending",
                f"check {name} has status {status or 'missing'}",
                head_sha,
            )
        if conclusion == "skipped":
            return blocked("check_skipped", f"check {name} was skipped", head_sha)
        if conclusion != "success":
            return blocked(
                "check_not_successful",
                f"check {name} concluded {conclusion or 'missing'}",
                head_sha,
            )

    status_entries = statuses.get("statuses")
    status_total = statuses.get("total_count")
    if (
        statuses.get("sha") != head_sha
        or not isinstance(status_entries, list)
        or not isinstance(status_total, int)
        or isinstance(status_total, bool)
        or status_total != len(status_entries)
    ):
        return blocked(
            "status_evidence_incomplete",
            "combined status evidence is stale, malformed, or partially paginated",
            head_sha,
        )
    contexts = [str(status.get("context", "")) for status in status_entries]
    if len(contexts) != len(set(contexts)):
        return blocked(
            "status_context_ambiguous",
            "combined status evidence contains duplicate contexts",
            head_sha,
        )
    for status in status_entries:
        state = str(status.get("state", "")).lower()
        context = str(status.get("context", "<unnamed>"))
        if state == "pending":
            return blocked("status_pending", f"status {context} is pending", head_sha)
        if state != "success":
            return blocked(
                "status_not_successful",
                f"status {context} is {state or 'missing'}",
                head_sha,
            )

    return eligible(head_sha, len(check_runs), len(status_entries))


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--pull-request", type=Path, required=True)
    parser.add_argument("--commits", type=Path, required=True)
    parser.add_argument("--checks", type=Path, required=True)
    parser.add_argument("--statuses", type=Path, required=True)
    parser.add_argument("--caller", type=Path, required=True)
    parser.add_argument("--required-security-revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = evaluate_candidate(
            repository=args.repository,
            policy=load_json(args.policy),
            pull_request=load_json(args.pull_request),
            commits=load_json(args.commits),
            checks=load_json(args.checks),
            statuses=load_json(args.statuses),
            caller_text=args.caller.read_text(encoding="utf-8"),
            required_security_revision=args.required_security_revision,
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        result = blocked("candidate_evidence_invalid", str(error))
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["eligible"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
