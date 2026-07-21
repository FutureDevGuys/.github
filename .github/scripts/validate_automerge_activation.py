#!/usr/bin/env python3
"""Validate and receipt the source-controlled automerge kill switch."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any


class ActivationError(RuntimeError):
    pass


EXPECTED_REASONS = [
    "public_policy_branch_required_checks_and_reviews_are_not_enforced",
    "refresh_and_merge_use_one_ordinary_user_credential",
    "cross_repository_merge_queue_or_equivalent_serialization_is_not_proven",
]


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_policy(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > 1024 * 1024
    ):
        raise ActivationError("activation policy must be one bounded regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationError("activation policy is not valid UTF-8 JSON") from error
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "enabled",
        "kill_switch",
        "reasons",
        "required_preconditions",
    }:
        raise ActivationError("activation policy fields are not exact")
    if (
        value.get("schema_version") != 1
        or value.get("enabled") is not False
        or value.get("kill_switch") is not True
        or value.get("reasons") != EXPECTED_REASONS
    ):
        raise ActivationError("automerge must remain explicitly kill-switched")
    preconditions = value.get("required_preconditions")
    if not isinstance(preconditions, dict) or set(preconditions) != {
        "main_branch",
        "release_branch",
        "identities",
        "merge_serialization",
    }:
        raise ActivationError("activation preconditions are not exact")
    main = preconditions["main_branch"]
    release = preconditions["release_branch"]
    identities = preconditions["identities"]
    serialization = preconditions["merge_serialization"]
    if main != {
        "required_status_checks": [
            "actionlint",
            "adoption-fixture-audit",
            "authority-fixture-audit",
            "scan-contract-tests",
            "trivy-contract-smoke",
        ],
        "required_approving_reviews": 1,
        "required_conversation_resolution": True,
    }:
        raise ActivationError("main branch activation preconditions are incomplete")
    if release != {
        "required_signatures": True,
        "enforce_admins": True,
        "required_linear_history": True,
        "allow_force_pushes": False,
        "allow_deletions": False,
    }:
        raise ActivationError("release branch activation preconditions are incomplete")
    if identities != {
        "refresh": "dedicated_github_app",
        "merge": "separate_dedicated_github_app",
        "must_be_distinct": True,
    }:
        raise ActivationError("refresh and merge identities are not separated")
    if serialization != {
        "mode": "merge_queue_or_equivalent_server_enforced_queue",
        "head_compare_and_swap_is_sufficient": False,
    }:
        raise ActivationError("merge serialization precondition is not fail closed")
    return value


def write_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_json(value))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        policy = load_policy(args.policy)
    except (ActivationError, OSError) as error:
        raise SystemExit(str(error)) from error
    receipt = {
        "schema_version": 1,
        "executed": True,
        "tool": {"name": "automerge-activation-gate", "version": "1.0.0"},
        "policy_sha256": digest(args.policy.read_bytes()),
        "enabled": policy["enabled"],
        "kill_switch": policy["kill_switch"],
        "reasons": policy["reasons"],
        "result": {"status": "held", "safe_to_mutate": False},
    }
    write_atomic(args.output, receipt)
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
