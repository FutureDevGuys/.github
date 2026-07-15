#!/usr/bin/env python3
"""Prove that a successful merge request actually merged the authorized head."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def evaluation(
    verified: bool,
    reason: str,
    detail: str,
    *,
    head_sha: str = "",
    merge_commit_sha: str = "",
    base_sha: str = "",
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "verified": verified,
        "reason": reason,
        "detail": detail,
        "head_sha": head_sha,
        "merge_commit_sha": merge_commit_sha,
        "base_sha": base_sha,
    }


def evaluate_merge_postcondition(
    *,
    authorized_head_sha: str,
    authorized_base_sha: str,
    current_base_sha: str,
    pull_request: dict[str, Any],
    merge_commit: dict[str, Any],
    comparison: dict[str, Any],
) -> dict[str, Any]:
    if (
        SHA_RE.fullmatch(authorized_head_sha) is None
        or SHA_RE.fullmatch(authorized_base_sha) is None
        or SHA_RE.fullmatch(current_base_sha) is None
    ):
        return evaluation(
            False,
            "invalid_merge_input",
            "authorized head and current base must be exact commit SHAs",
            head_sha=authorized_head_sha,
            base_sha=current_base_sha,
        )

    pr_merge_commit = pull_request.get("mergeCommit")
    merge_commit_sha = (
        pr_merge_commit.get("oid") if isinstance(pr_merge_commit, dict) else None
    )
    merged_at = pull_request.get("mergedAt")
    if (
        pull_request.get("state") != "MERGED"
        or pull_request.get("baseRefName") != "main"
        or pull_request.get("headRefOid") != authorized_head_sha
        or not isinstance(merge_commit_sha, str)
        or SHA_RE.fullmatch(merge_commit_sha) is None
        or not isinstance(merged_at, str)
        or not merged_at.strip()
    ):
        return evaluation(
            False,
            "merge_pending_or_mismatched",
            "PR is not merged on main with the exact authorized head and merge commit",
            head_sha=authorized_head_sha,
            merge_commit_sha=merge_commit_sha or "",
            base_sha=current_base_sha,
        )
    try:
        parsed_merged_at = datetime.fromisoformat(merged_at.replace("Z", "+00:00"))
    except ValueError:
        parsed_merged_at = None
    if parsed_merged_at is None or parsed_merged_at.tzinfo is None:
        return evaluation(
            False,
            "invalid_merged_timestamp",
            "mergedAt must be a timezone-qualified timestamp",
            head_sha=authorized_head_sha,
            merge_commit_sha=merge_commit_sha,
            base_sha=current_base_sha,
        )

    commit_parents = merge_commit.get("parents")
    if (
        merge_commit.get("sha") != merge_commit_sha
        or not isinstance(commit_parents, list)
        or len(commit_parents) != 1
        or not isinstance(commit_parents[0], dict)
        or commit_parents[0].get("sha") != authorized_base_sha
    ):
        return evaluation(
            False,
            "merge_parent_mismatch",
            "squash merge parent does not equal the exact premerge authorized base",
            head_sha=authorized_head_sha,
            merge_commit_sha=merge_commit_sha,
            base_sha=current_base_sha,
        )

    base_commit = comparison.get("base_commit")
    merge_base_commit = comparison.get("merge_base_commit")
    commits = comparison.get("commits")
    behind_by = comparison.get("behind_by")
    ahead_by = comparison.get("ahead_by")
    status = comparison.get("status")
    if (
        not isinstance(base_commit, dict)
        or base_commit.get("sha") != merge_commit_sha
        or not isinstance(merge_base_commit, dict)
        or merge_base_commit.get("sha") != merge_commit_sha
        or not isinstance(commits, list)
    ):
        return evaluation(
            False,
            "merge_reachability_stale",
            "comparison does not start at the exact merge commit",
            head_sha=authorized_head_sha,
            merge_commit_sha=merge_commit_sha,
            base_sha=current_base_sha,
        )
    if (
        not isinstance(behind_by, int)
        or isinstance(behind_by, bool)
        or not isinstance(ahead_by, int)
        or isinstance(ahead_by, bool)
        or behind_by != 0
        or ahead_by < 0
        or status not in {"ahead", "identical"}
        or (status == "identical" and merge_commit_sha != current_base_sha)
        or (
            status == "ahead"
            and (not commits or commits[-1].get("sha") != current_base_sha)
        )
    ):
        return evaluation(
            False,
            "merge_not_reachable_from_base",
            f"merge-to-base comparison status={status!r} ahead={ahead_by!r} behind={behind_by!r}",
            head_sha=authorized_head_sha,
            merge_commit_sha=merge_commit_sha,
            base_sha=current_base_sha,
        )

    return evaluation(
        True,
        "merge_verified",
        "exact authorized head merged and merge commit is reachable from current main",
        head_sha=authorized_head_sha,
        merge_commit_sha=merge_commit_sha,
        base_sha=current_base_sha,
    )


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorized-head-sha", required=True)
    parser.add_argument("--authorized-base-sha", required=True)
    parser.add_argument("--current-base-sha", required=True)
    parser.add_argument("--pull-request", type=Path, required=True)
    parser.add_argument("--merge-commit", type=Path, required=True)
    parser.add_argument("--comparison", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = evaluate_merge_postcondition(
            authorized_head_sha=args.authorized_head_sha,
            authorized_base_sha=args.authorized_base_sha,
            current_base_sha=args.current_base_sha,
            pull_request=load_json(args.pull_request),
            merge_commit=load_json(args.merge_commit),
            comparison=load_json(args.comparison),
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        result = evaluation(False, "merge_postcondition_invalid", str(error))
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, sort_keys=True))
    return 0 if result["verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
