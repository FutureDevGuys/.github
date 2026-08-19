#!/usr/bin/env python3
"""Resolve active repositories with the exact dependency-automation marker."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote


SCHEMA_VERSION = 1
CALLER_PATH = ".github/workflows/dependency-automation.yml"
SHARED_WORKFLOW = (
    "FutureDevGuys/.github/.github/workflows/dependency-automation-marker.yml"
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
USES_RE = re.compile(r"^    uses:\s+(\S+)@([^\s]+)$", re.MULTILINE)


class ContractError(RuntimeError):
    """The active-repository or marker contract is not trustworthy."""


@dataclass(frozen=True)
class Caller:
    revision: str


def render_caller(revision: str) -> str:
    """Render the only accepted repository-local marker shape."""

    if SHA_RE.fullmatch(revision) is None:
        raise ContractError("caller reusable workflow ref must be an exact lowercase SHA")
    return f"""name: dependency-automation

on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  adopt:
    uses: {SHARED_WORKFLOW}@{revision}
    permissions:
      contents: read
"""


def parse_caller(text: str) -> Caller:
    """Validate a byte-exact marker and return its immutable shared revision."""

    matches = USES_RE.findall(text)
    if len(matches) != 1 or matches[0][0] != SHARED_WORKFLOW:
        raise ContractError(
            "caller must use the shared dependency-automation marker exactly once"
        )
    revision = matches[0][1]
    if SHA_RE.fullmatch(revision) is None:
        raise ContractError("caller reusable workflow ref must be an exact lowercase SHA")
    if text != render_caller(revision):
        raise ContractError(
            "caller must match the byte-exact minimal marker; triggers, permissions, "
            "inputs, conditions, steps, and additional jobs are forbidden"
        )
    return Caller(revision=revision)


MarkerLoader = Callable[[dict[str, Any]], tuple[str, str] | None]


def validate_inventory_completeness(
    organization_metadata: Any,
    organization: str,
    repositories: Any,
) -> None:
    """Prove pagination saw the organization's complete public/private inventory."""

    if not isinstance(organization_metadata, dict) or not isinstance(
        repositories, list
    ):
        raise ContractError("organization metadata and repository inventory are required")
    expected_public = organization_metadata.get("public_repos")
    expected_private = organization_metadata.get("total_private_repos")
    if (
        organization_metadata.get("login") != organization
        or not isinstance(expected_public, int)
        or isinstance(expected_public, bool)
        or expected_public < 0
        or not isinstance(expected_private, int)
        or isinstance(expected_private, bool)
        or expected_private < 0
    ):
        raise ContractError(
            "organization metadata must expose exact public and private repository counts"
        )
    visible_public = sum(
        1
        for repository in repositories
        if isinstance(repository, dict) and repository.get("private") is False
    )
    visible_private = sum(
        1
        for repository in repositories
        if isinstance(repository, dict) and repository.get("private") is True
    )
    if visible_public + visible_private != len(repositories):
        raise ContractError("repository inventory contains an unknown visibility")
    if visible_public != expected_public or visible_private != expected_private:
        raise ContractError(
            "organization repository inventory is incomplete: "
            f"visible public/private={visible_public}/{visible_private}, "
            f"expected={expected_public}/{expected_private}"
        )


def resolve_adopters(
    organization: str,
    repositories: Any,
    load_marker: MarkerLoader,
) -> dict[str, Any]:
    """Select the policy owner and active repositories with valid markers."""

    if not isinstance(organization, str) or not organization.strip():
        raise ContractError("organization must be a non-empty string")
    if not isinstance(repositories, list):
        raise ContractError("organization repository inventory must be a list")

    active: list[dict[str, Any]] = []
    identities: set[tuple[int, str]] = set()
    names: set[str] = set()
    for repository in repositories:
        if not isinstance(repository, dict):
            raise ContractError("every organization repository must be an object")
        if (
            repository.get("archived") is True
            or repository.get("disabled") is True
            or repository.get("fork") is True
        ):
            continue
        name = repository.get("full_name")
        repository_id = repository.get("id")
        node_id = repository.get("node_id")
        default_branch = repository.get("default_branch")
        if (
            not isinstance(name, str)
            or not name.startswith(f"{organization}/")
            or not isinstance(repository_id, int)
            or isinstance(repository_id, bool)
            or repository_id <= 0
            or not isinstance(node_id, str)
            or not node_id.strip()
            or not isinstance(default_branch, str)
            or not default_branch.strip()
        ):
            raise ContractError(f"active repository identity is incomplete: {name!r}")
        identity = (repository_id, node_id)
        if name in names or identity in identities:
            raise ContractError(f"active repository identity is ambiguous: {name}")
        names.add(name)
        identities.add(identity)
        active.append(repository)

    selected: list[dict[str, Any]] = []
    policy_owner = f"{organization}/.github"
    for repository in sorted(active, key=lambda value: value["full_name"]):
        name = repository["full_name"]
        if name == policy_owner:
            selected.append(
                {
                    "repository": name,
                    "repository_id": repository["id"],
                    "head_repository_id": repository["node_id"],
                    "default_branch": repository["default_branch"],
                    "default_revision": "",
                    "caller_revision": "",
                    "policy_owner": True,
                }
            )
            continue

        loaded = load_marker(repository)
        if loaded is None:
            continue
        default_revision, text = loaded
        if SHA_RE.fullmatch(default_revision) is None:
            raise ContractError(f"{name}: default revision must be an exact commit SHA")
        try:
            caller = parse_caller(text)
        except ContractError as error:
            raise ContractError(f"{name}: {error}") from error
        selected.append(
            {
                "repository": name,
                "repository_id": repository["id"],
                "head_repository_id": repository["node_id"],
                "default_branch": repository["default_branch"],
                "default_revision": default_revision,
                "caller_revision": caller.revision,
                "policy_owner": False,
            }
        )

    if not any(row["policy_owner"] for row in selected):
        raise ContractError(f"active policy owner {policy_owner} is not visible")
    return {
        "schema_version": SCHEMA_VERSION,
        "organization": organization,
        "caller_path": CALLER_PATH,
        "active_repository_count": len(active),
        "repositories": selected,
        "selected_repositories": [row["repository"] for row in selected],
    }


class GitHubClient:
    """Minimal checked subprocess boundary for authenticated GitHub API reads."""

    def api(self, endpoint: str, *, paginate: bool = False) -> Any:
        command = ["gh", "api", endpoint]
        if paginate:
            command.extend(["--paginate", "--slurp"])
        try:
            completed = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
                timeout=120,
            )
            return json.loads(completed.stdout)
        except FileNotFoundError as error:
            raise ContractError("gh CLI is required for adopter discovery") from error
        except subprocess.TimeoutExpired as error:
            raise ContractError(f"GitHub API read timed out: {endpoint}") from error
        except subprocess.CalledProcessError as error:
            detail = error.stderr.strip() or "gh api returned nonzero"
            raise ContractError(
                f"GitHub API read failed for {endpoint}: {detail}"
            ) from error
        except json.JSONDecodeError as error:
            raise ContractError(f"GitHub API returned invalid JSON for {endpoint}") from error


def load_remote_marker(
    client: GitHubClient,
    repository: dict[str, Any],
) -> tuple[str, str] | None:
    """Read the marker only when the exact default-commit tree contains it."""

    name = repository["full_name"]
    default_branch = repository["default_branch"]
    commit = client.api(f"repos/{name}/commits/{quote(default_branch, safe='')}")
    revision = commit.get("sha") if isinstance(commit, dict) else None
    if not isinstance(revision, str) or SHA_RE.fullmatch(revision) is None:
        raise ContractError(f"{name}: default branch did not resolve to one exact commit")

    tree = client.api(f"repos/{name}/git/trees/{revision}?recursive=1")
    if not isinstance(tree, dict) or tree.get("truncated") is not False:
        raise ContractError(f"{name}: complete default-commit tree is required")
    rows = tree.get("tree")
    if not isinstance(rows, list):
        raise ContractError(f"{name}: default-commit tree is malformed")
    matches = [
        row
        for row in rows
        if isinstance(row, dict) and row.get("path") == CALLER_PATH
    ]
    if not matches:
        return None
    if len(matches) != 1:
        raise ContractError(f"{name}: dependency-automation marker path is ambiguous")
    marker = matches[0]
    blob_sha = marker.get("sha")
    if (
        marker.get("type") != "blob"
        or marker.get("mode") != "100644"
        or not isinstance(blob_sha, str)
        or SHA_RE.fullmatch(blob_sha) is None
    ):
        raise ContractError(
            f"{name}: dependency-automation marker must be a regular 0644 blob"
        )
    blob = client.api(f"repos/{name}/git/blobs/{blob_sha}")
    if not isinstance(blob, dict) or blob.get("encoding") != "base64":
        raise ContractError(f"{name}: dependency-automation marker blob is malformed")
    encoded = blob.get("content")
    if not isinstance(encoded, str):
        raise ContractError(f"{name}: dependency-automation marker content is missing")
    try:
        text = base64.b64decode("".join(encoded.split()), validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as error:
        raise ContractError(f"{name}: dependency-automation marker is not UTF-8") from error
    return revision, text


def build_effective_policy(base_policy: Any, receipt: dict[str, Any]) -> dict[str, Any]:
    """Bind the central identity policy to the exact repositories in one receipt."""

    if not isinstance(base_policy, dict) or base_policy.get("schema_version") != 1:
        raise ContractError("automerge base policy schema_version must be 1")
    identity = base_policy.get("trusted_renovate_identity")
    organization_policy = base_policy.get("organization")
    if not isinstance(identity, dict) or not isinstance(organization_policy, dict):
        raise ContractError("automerge base policy identity contracts are missing")
    if organization_policy.get("login") != receipt.get("organization"):
        raise ContractError("automerge base policy organization does not match receipt")
    configured = base_policy.get("repositories", {})
    if not isinstance(configured, dict):
        raise ContractError("automerge base policy repositories must be an object")

    effective = dict(base_policy)
    effective["repositories"] = {}
    for row in receipt["repositories"]:
        existing = configured.get(row["repository"], {})
        if not isinstance(existing, dict):
            raise ContractError(f"{row['repository']}: configured policy must be an object")
        if existing and (
            existing.get("repository_id") != row["repository_id"]
            or existing.get("head_repository_id") != row["head_repository_id"]
        ):
            raise ContractError(
                f"{row['repository']}: discovered identity conflicts with its central assertion"
            )
        required_checks = existing.get("required_checks", [])
        if not isinstance(required_checks, list):
            raise ContractError(f"{row['repository']}: required_checks must be a list")
        effective["repositories"][row["repository"]] = {
            "repository_id": row["repository_id"],
            "head_repository_id": row["head_repository_id"],
            "required_checks": required_checks,
        }
    return effective


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--organization", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--base-policy", type=Path)
    parser.add_argument("--effective-policy", type=Path)
    parser.add_argument(
        "--requested",
        default="",
        help="Optional comma-separated subset for a manual Renovate run.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not os.environ.get("GH_TOKEN", "").strip():
        print("ERROR: GH_TOKEN is required for complete adopter discovery", file=sys.stderr)
        return 1
    if bool(args.base_policy) != bool(args.effective_policy):
        print(
            "ERROR: --base-policy and --effective-policy must be supplied together",
            file=sys.stderr,
        )
        return 1
    try:
        client = GitHubClient()
        pages = client.api(
            f"orgs/{args.organization}/repos?per_page=100&type=all", paginate=True
        )
        if not isinstance(pages, list) or not pages or any(
            not isinstance(page, list) for page in pages
        ):
            raise ContractError("complete paginated organization inventory is required")
        repositories = [repository for page in pages for repository in page]
        organization_metadata = client.api(f"orgs/{args.organization}")
        validate_inventory_completeness(
            organization_metadata, args.organization, repositories
        )
        receipt = resolve_adopters(
            args.organization,
            repositories,
            lambda repository: load_remote_marker(client, repository),
        )
        requested = [
            value.strip() for value in args.requested.split(",") if value.strip()
        ]
        if requested:
            available = set(receipt["selected_repositories"])
            unknown = sorted(set(requested) - available)
            if unknown:
                raise ContractError(
                    "requested repositories are not valid adopters: " + ", ".join(unknown)
                )
            receipt["selected_repositories"] = sorted(set(requested))
        args.output.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        if args.base_policy and args.effective_policy:
            base_policy = json.loads(args.base_policy.read_text(encoding="utf-8"))
            effective = build_effective_policy(base_policy, receipt)
            args.effective_policy.write_text(
                json.dumps(effective, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
    except (ContractError, OSError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(
        f"Resolved {len(receipt['repositories'])} dependency-automation adopters "
        f"from {receipt['active_repository_count']} active repositories."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
