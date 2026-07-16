#!/usr/bin/env python3
"""Plan and verify fail-closed movement of the security-contract release ref."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Sequence

SCHEMA_VERSION = 1
RECEIPT_SCHEMA_VERSION = 2
RELEASE_REF = "refs/heads/security-contract-v1"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class ReleaseError(RuntimeError):
    """The release ref cannot be safely planned or verified."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseError(f"JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ReleaseError(f"cannot read {label}: {error}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > 1024 * 1024
    ):
        raise ReleaseError(f"{label} must be one bounded regular file")
    try:
        value = json.loads(
            path.read_bytes(),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseError(f"{label} is not strict JSON: {error}") from error
    if not isinstance(value, dict):
        raise ReleaseError(f"{label} must be a JSON object")
    return value


def _git(repo: Path, arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=repo,
        check=False,
        capture_output=True,
        text=True,
    )


def _desired_target(receipt: dict[str, Any]) -> str:
    if receipt.get("schema_version") != RECEIPT_SCHEMA_VERSION:
        raise ReleaseError("security authority receipt schema is unsupported")
    if receipt.get("authority") != "generated":
        raise ReleaseError("security authority receipt is not generated authority")
    if receipt.get("release_ref") != RELEASE_REF:
        raise ReleaseError("security authority receipt release ref is invalid")
    desired = receipt.get("security_contract_revision")
    if not isinstance(desired, str) or SHA_RE.fullmatch(desired) is None:
        raise ReleaseError("security authority receipt target is malformed")
    return desired


def plan_release(
    repo: Path,
    receipt: dict[str, Any],
    current_target: str | None,
    *,
    bootstrap: bool,
) -> dict[str, Any]:
    repo = repo.resolve()
    desired = _desired_target(receipt)
    if _git(repo, ["cat-file", "-e", f"{desired}^{{commit}}"]).returncode != 0:
        raise ReleaseError("desired security contract target is not a local commit")

    action: str
    reason: str
    if current_target is None:
        if bootstrap:
            action = "create"
            reason = "explicit_bootstrap_of_missing_release_ref"
        else:
            action = "held"
            reason = "release_ref_missing_bootstrap_required"
    elif SHA_RE.fullmatch(current_target) is None:
        action = "held"
        reason = "release_ref_target_malformed"
    elif current_target == desired:
        action = "noop"
        reason = "release_ref_already_current"
    else:
        ancestor = _git(repo, ["merge-base", "--is-ancestor", current_target, desired])
        if ancestor.returncode == 0:
            action = "update"
            reason = "protected_contract_advanced"
        elif ancestor.returncode == 1:
            action = "held"
            reason = "release_ref_not_ancestor_of_desired_target"
        else:
            action = "held"
            reason = "release_ref_target_not_resolvable"

    return {
        "schema_version": SCHEMA_VERSION,
        "authority": "generated",
        "release_ref": RELEASE_REF,
        "current_target": current_target,
        "desired_target": desired,
        "bootstrap": bootstrap,
        "action": action,
        "reason": reason,
    }


def verify_release(plan: dict[str, Any], observed_target: str) -> None:
    expected_fields = {
        "schema_version",
        "authority",
        "release_ref",
        "current_target",
        "desired_target",
        "bootstrap",
        "action",
        "reason",
    }
    if set(plan) != expected_fields:
        raise ReleaseError("security contract release plan fields are not exact")
    if (
        plan.get("schema_version") != SCHEMA_VERSION
        or plan.get("authority") != "generated"
    ):
        raise ReleaseError("security contract release plan is not trusted")
    if plan.get("release_ref") != RELEASE_REF:
        raise ReleaseError("security contract release plan ref is invalid")
    if plan.get("action") not in {"create", "update", "noop"}:
        raise ReleaseError(
            "held or unknown release plans cannot satisfy a postcondition"
        )
    desired = plan.get("desired_target")
    if not isinstance(desired, str) or SHA_RE.fullmatch(desired) is None:
        raise ReleaseError("security contract release plan target is malformed")
    if SHA_RE.fullmatch(observed_target) is None or observed_target != desired:
        raise ReleaseError("security contract release ref postcondition is not exact")


def write_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan = subparsers.add_parser("plan")
    plan.add_argument("--repo", type=Path, default=Path.cwd())
    plan.add_argument("--receipt", type=Path, required=True)
    plan.add_argument("--current-target")
    plan.add_argument("--bootstrap", action="store_true")
    plan.add_argument("--output", type=Path, required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--plan", type=Path, required=True)
    verify.add_argument("--observed-target", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "plan":
            plan = plan_release(
                args.repo,
                _read_object(args.receipt, "security authority receipt"),
                args.current_target,
                bootstrap=args.bootstrap,
            )
            write_atomic(args.output, plan)
            print(json.dumps(plan, sort_keys=True))
            return 0 if plan["action"] != "held" else 2
        verify_release(
            _read_object(args.plan, "security contract release plan"),
            args.observed_target,
        )
    except (OSError, ReleaseError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
