#!/usr/bin/env python3
"""Prove that an accepted Renovate branch refresh actually completed."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def evaluation(
    verified: bool,
    reason: str,
    detail: str,
    *,
    old_head_sha: str = "",
    new_head_sha: str = "",
    base_sha: str = "",
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "verified": verified,
        "reason": reason,
        "detail": detail,
        "old_head_sha": old_head_sha,
        "new_head_sha": new_head_sha,
        "base_sha": base_sha,
    }


def evaluate_refresh_postcondition(
    *,
    old_head_sha: str,
    current_base_sha: str,
    pull_request: dict[str, Any],
    comparison: dict[str, Any],
) -> dict[str, Any]:
    if SHA_RE.fullmatch(old_head_sha) is None or SHA_RE.fullmatch(current_base_sha) is None:
        return evaluation(
            False,
            "invalid_refresh_input",
            "old head and current base must be exact commit SHAs",
            old_head_sha=old_head_sha,
            base_sha=current_base_sha,
        )

    new_head_sha = pull_request.get("headRefOid")
    recorded_base_sha = pull_request.get("baseRefOid")
    if not isinstance(new_head_sha, str) or SHA_RE.fullmatch(new_head_sha) is None:
        return evaluation(
            False,
            "invalid_refreshed_head",
            "refreshed PR head must be an exact commit SHA",
            old_head_sha=old_head_sha,
            base_sha=current_base_sha,
        )
    if new_head_sha == old_head_sha:
        return evaluation(
            False,
            "refresh_pending",
            "accepted refresh has not changed the PR head",
            old_head_sha=old_head_sha,
            new_head_sha=new_head_sha,
            base_sha=current_base_sha,
        )
    if pull_request.get("baseRefName") != "main" or recorded_base_sha != current_base_sha:
        return evaluation(
            False,
            "refreshed_base_mismatch",
            "refreshed PR does not bind the observed current main commit",
            old_head_sha=old_head_sha,
            new_head_sha=new_head_sha,
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
        or base_commit.get("sha") != current_base_sha
        or not isinstance(merge_base_commit, dict)
        or merge_base_commit.get("sha") != current_base_sha
        or not isinstance(commits, list)
        or not commits
        or commits[-1].get("sha") != new_head_sha
    ):
        return evaluation(
            False,
            "refresh_comparison_stale",
            "comparison does not bind the current base and new exact head",
            old_head_sha=old_head_sha,
            new_head_sha=new_head_sha,
            base_sha=current_base_sha,
        )
    if (
        not isinstance(behind_by, int)
        or isinstance(behind_by, bool)
        or not isinstance(ahead_by, int)
        or isinstance(ahead_by, bool)
        or behind_by != 0
        or ahead_by <= 0
        or status != "ahead"
    ):
        return evaluation(
            False,
            "refresh_still_behind",
            f"post-refresh comparison status={status!r} ahead={ahead_by!r} behind={behind_by!r}",
            old_head_sha=old_head_sha,
            new_head_sha=new_head_sha,
            base_sha=current_base_sha,
        )

    return evaluation(
        True,
        "refresh_verified",
        "new exact head contains the observed current base",
        old_head_sha=old_head_sha,
        new_head_sha=new_head_sha,
        base_sha=current_base_sha,
    )


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old-head-sha", required=True)
    parser.add_argument("--current-base-sha", required=True)
    parser.add_argument("--pull-request", type=Path, required=True)
    parser.add_argument("--comparison", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = evaluate_refresh_postcondition(
            old_head_sha=args.old_head_sha,
            current_base_sha=args.current_base_sha,
            pull_request=load_json(args.pull_request),
            comparison=load_json(args.comparison),
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        result = evaluation(False, "refresh_postcondition_invalid", str(error))
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, sort_keys=True))
    return 0 if result["verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
