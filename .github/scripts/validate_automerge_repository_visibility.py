#!/usr/bin/env python3
"""Prove that the automerge token can enumerate every policy-adopted repository."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


def result(
    eligible: bool,
    reason: str,
    detail: str,
    *,
    repositories: list[str] | None = None,
    visible_count: int = 0,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "eligible": eligible,
        "reason": reason,
        "detail": detail,
        "repositories": repositories or [],
        "visible_count": visible_count,
    }


def blocked(reason: str, detail: str) -> dict[str, Any]:
    return result(False, reason, detail)


def evaluate_repository_visibility(
    *,
    organization: str,
    policy: Any,
    discovered: Any,
) -> dict[str, Any]:
    if not isinstance(policy, dict):
        return blocked("invalid_policy", "automerge policy must be an object")
    if policy.get("schema_version") != SCHEMA_VERSION:
        return blocked("invalid_policy", "automerge policy schema_version must be 1")

    organization_policy = policy.get("organization")
    repositories = policy.get("repositories")
    if not isinstance(organization_policy, dict) or not isinstance(repositories, dict):
        return blocked(
            "invalid_policy", "organization and repositories mappings are required"
        )
    if not repositories:
        return blocked("invalid_policy", "at least one adopted repository is required")

    expected_org = organization_policy.get("login")
    expected_org_id = organization_policy.get("id")
    expected_org_node_id = organization_policy.get("node_id")
    if (
        not isinstance(expected_org, str)
        or not expected_org.strip()
        or organization != expected_org
        or not isinstance(expected_org_id, int)
        or isinstance(expected_org_id, bool)
        or expected_org_id <= 0
        or not isinstance(expected_org_node_id, str)
        or not expected_org_node_id.strip()
    ):
        return blocked(
            "invalid_policy",
            "workflow organization must equal the policy-bound login and exact IDs",
        )

    if not isinstance(discovered, list):
        return blocked(
            "repository_visibility_invalid", "discovery result must be a list"
        )

    visible_by_name: dict[str, dict[str, Any]] = {}
    visible_ids: set[int] = set()
    visible_node_ids: set[str] = set()
    for repository in discovered:
        if not isinstance(repository, dict):
            return blocked(
                "repository_visibility_invalid",
                "discovered repository must be an object",
            )
        name = repository.get("full_name")
        repository_id = repository.get("id")
        node_id = repository.get("node_id")
        owner = repository.get("owner")
        if (
            not isinstance(name, str)
            or not name.strip()
            or not isinstance(repository_id, int)
            or isinstance(repository_id, bool)
            or repository_id <= 0
            or not isinstance(node_id, str)
            or not node_id.strip()
            or repository.get("archived") is not False
            or not isinstance(owner, dict)
            or owner.get("login") != expected_org
            or owner.get("id") != expected_org_id
            or owner.get("node_id") != expected_org_node_id
        ):
            return blocked(
                "repository_visibility_invalid",
                f"discovered repository has incomplete or mismatched identity: {name!r}",
            )
        if (
            name in visible_by_name
            or repository_id in visible_ids
            or node_id in visible_node_ids
        ):
            return blocked(
                "repository_visibility_ambiguous",
                f"duplicate discovered repository name or identity: {name}",
            )
        visible_by_name[name] = repository
        visible_ids.add(repository_id)
        visible_node_ids.add(node_id)

    adopted_names = list(repositories)
    if any(
        not isinstance(name, str) or not name.startswith(f"{expected_org}/")
        for name in adopted_names
    ):
        return blocked(
            "invalid_policy",
            "adopted repository names must belong to the policy-bound organization",
        )
    adopted_names.sort()
    missing = [name for name in adopted_names if name not in visible_by_name]
    if missing:
        return blocked(
            "adopted_repository_not_visible",
            "RENOVATE_TOKEN enumeration omitted adopted repositories: "
            + ", ".join(missing),
        )

    for name in adopted_names:
        repository_policy = repositories.get(name)
        if not isinstance(repository_policy, dict):
            return blocked("invalid_policy", f"{name} policy must be an object")
        expected_id = repository_policy.get("repository_id")
        expected_node_id = repository_policy.get("head_repository_id")
        if (
            not isinstance(expected_id, int)
            or isinstance(expected_id, bool)
            or expected_id <= 0
            or not isinstance(expected_node_id, str)
            or not expected_node_id.strip()
        ):
            return blocked(
                "invalid_policy", f"{name} must bind exact REST and GraphQL IDs"
            )
        observed = visible_by_name[name]
        if observed["id"] != expected_id or observed["node_id"] != expected_node_id:
            return blocked(
                "repository_identity_mismatch",
                f"{name} does not match its policy-bound REST and GraphQL IDs",
            )

    return result(
        True,
        "repository_visibility_complete",
        f"all {len(adopted_names)} adopted repositories are visible with exact identities",
        repositories=adopted_names,
        visible_count=len(visible_by_name),
    )


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--organization", required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--discovered", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        evaluation = evaluate_repository_visibility(
            organization=args.organization,
            policy=load_json(args.policy),
            discovered=load_json(args.discovered),
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        evaluation = blocked("repository_visibility_invalid", str(error))
    args.output.write_text(
        json.dumps(evaluation, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(evaluation, sort_keys=True))
    return 0 if evaluation["eligible"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
