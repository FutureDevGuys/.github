#!/usr/bin/env python3
"""Audit repositories for truthful Trivy callers and label-only Renovate config."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
from pathlib import Path


USES_RE = re.compile(
    r"^\s+uses:\s+FutureDevGuys/\.github/\.github/workflows/security-scan\.yml@([0-9a-f]{40})\s*$",
    re.MULTILINE,
)
REVISION_RE = re.compile(
    r"^      workflow_revision:\s*[\"']?([0-9a-f]{40})[\"']?\s*$",
    re.MULTILINE,
)
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
FORBIDDEN_AUTOMERGE_KEYS = {"automergeType", "automergeStrategy"}
ORG_CANDIDATE_LABEL = "automerge-candidate"
ORG_BLOCK_LABELS = {"do-not-merge", "manual-review", "migration-required", "major"}
ORG_RESERVED_LABELS = {ORG_CANDIDATE_LABEL, *ORG_BLOCK_LABELS}


def indented_block(text: str, key: str, indent: int) -> str | None:
    lines = text.splitlines(keepends=True)
    opener = re.compile(rf"^{re.escape(' ' * indent + key)}:\s*$")
    for index, line in enumerate(lines):
        if not opener.match(line.rstrip("\r\n")):
            continue
        block: list[str] = []
        for candidate in lines[index + 1 :]:
            stripped = candidate.strip()
            candidate_indent = len(candidate) - len(candidate.lstrip(" "))
            if stripped and not candidate.lstrip().startswith("#") and candidate_indent <= indent:
                break
            block.append(candidate)
        return "".join(block)
    return None


def direct_mapping_entries(block: str, indent: int) -> list[tuple[str, str]]:
    """Return direct scalar mapping entries without accepting nested lookalikes."""

    pattern = re.compile(
        rf"^{' ' * indent}([A-Za-z0-9_-]+):\s*([^#\r\n]*?)\s*(?:#.*)?$",
        re.MULTILINE,
    )
    return [(key, value.strip()) for key, value in pattern.findall(block)]


def direct_mapping_keys(block: str, indent: int) -> list[str]:
    """Return every direct mapping key, including block-valued entries."""

    pattern = re.compile(
        rf"^{' ' * indent}([A-Za-z0-9_-]+):(?:\s|$)",
        re.MULTILINE,
    )
    return pattern.findall(block)


def validate_read_only_permissions(
    block: str | None,
    indent: int,
    location: str,
) -> list[str]:
    if block is None:
        return [f"{location} must declare block-style contents: read permissions"]
    entries = direct_mapping_entries(block, indent)
    if entries != [("contents", "read")]:
        return [f"{location} permissions must contain only contents: read"]
    return []


def validate_caller(text: str, required_revision: str | None = None) -> list[str]:
    errors: list[str] = []
    top_level_keys = direct_mapping_keys(text, 0)
    if any(top_level_keys.count(key) != 1 for key in ("on", "permissions", "jobs")):
        errors.append("caller must declare on, permissions, and jobs exactly once")
    on_block = indented_block(text, "on", 0)
    jobs_block = indented_block(text, "jobs", 0)
    trivy_block = indented_block(jobs_block or "", "trivy", 2)
    with_block = indented_block(trivy_block or "", "with", 4)
    uses = USES_RE.findall(trivy_block or "")
    revisions = REVISION_RE.findall(with_block or "")
    if on_block is None:
        errors.append("caller must define a block-style top-level on mapping")
        on_block = ""
    if jobs_block is None:
        errors.append("caller must define a block-style top-level jobs mapping")
    elif direct_mapping_keys(jobs_block, 2) != ["trivy"]:
        errors.append("caller jobs mapping must contain exactly one trivy job")
    if trivy_block is None:
        errors.append("caller must expose the stable trivy job name")
        trivy_block = ""
    elif sorted(direct_mapping_keys(trivy_block, 4)) != [
        "permissions",
        "uses",
        "with",
    ]:
        errors.append(
            "caller trivy job must contain only uses, with, and permissions once each"
        )
    errors.extend(
        validate_read_only_permissions(
            indented_block(text, "permissions", 0),
            2,
            "workflow",
        )
    )
    errors.extend(
        validate_read_only_permissions(
            indented_block(trivy_block, "permissions", 4),
            6,
            "jobs.trivy",
        )
    )
    if len(uses) != 1:
        errors.append("caller must use the shared security workflow at one exact 40-character SHA")
    if len(revisions) != 1:
        errors.append("caller must pass workflow_revision as one exact 40-character SHA")
    if with_block is None:
        errors.append("caller must pass workflow_revision in jobs.trivy.with")
    elif [key for key, _ in direct_mapping_entries(with_block, 6)] != [
        "workflow_revision"
    ]:
        errors.append("jobs.trivy.with must contain only workflow_revision")
    if len(uses) == 1 and len(revisions) == 1 and uses[0] != revisions[0]:
        errors.append("workflow_revision must equal the SHA in jobs.trivy.uses")
    if len(uses) == 1 and required_revision and uses[0] != required_revision:
        errors.append(
            f"caller revision {uses[0]} does not match required org revision {required_revision}"
        )
    for trigger in ("pull_request", "push", "schedule", "workflow_dispatch"):
        if not re.search(rf"^  {trigger}:\s*(?:$|\{{|\[)", on_block, re.MULTILINE):
            errors.append(f"caller is missing the {trigger} trigger")
    if sorted(direct_mapping_keys(on_block, 2)) != [
        "pull_request",
        "push",
        "schedule",
        "workflow_dispatch",
    ]:
        errors.append(
            "caller on mapping must contain each required trigger exactly once"
        )
    pull_request_block = indented_block(on_block, "pull_request", 2) or ""
    if re.search(
        r"^    (?:branches|branches-ignore|paths|paths-ignore):\s*",
        pull_request_block,
        re.MULTILINE,
    ):
        errors.append("caller pull_request trigger must not filter dependency update PRs")
    types_match = re.search(
        r"^    types:\s*\[([^\]]*)\]\s*$",
        pull_request_block,
        re.MULTILINE,
    )
    if "types:" in pull_request_block and types_match is None:
        errors.append("caller pull_request types must use the audited inline form")
    elif types_match is not None:
        configured_types = {
            item.strip().strip("\"'")
            for item in types_match.group(1).split(",")
            if item.strip()
        }
        required_types = {"opened", "synchronize", "reopened", "ready_for_review"}
        if not required_types.issubset(configured_types):
            errors.append(
                "caller pull_request types must include opened, synchronize, reopened, and ready_for_review"
            )
    push_block = indented_block(on_block, "push", 2) or ""
    if not re.search(r"^    branches:\s*\[main\]\s*$", push_block, re.MULTILINE):
        errors.append("caller must constrain its push trigger to main")
    schedule_block = indented_block(on_block, "schedule", 2) or ""
    if not re.search(r"^    - cron:\s*[\"'][^\"']+[\"']\s*$", schedule_block, re.MULTILINE):
        errors.append("caller schedule trigger must declare a quoted cron expression")
    if "is_dependency_bot_pr" in text:
        errors.append("caller must not skip dependency-bot pull requests")
    if re.search(r"^    if:\s*", trivy_block, re.MULTILINE):
        errors.append("caller trivy job must not have a conditional skip")
    if re.search(r"^    secrets:\s*", trivy_block, re.MULTILINE):
        errors.append("caller trivy job must not pass repository secrets")
    return errors


def validate_renovate_config(text: str) -> list[str]:
    """Reject repository-local settings that bypass the org merge sweep."""

    try:
        config = json.loads(text)
    except json.JSONDecodeError as error:
        return [f"renovate.json is not valid JSON: {error}"]
    if not isinstance(config, dict):
        return ["renovate.json root must be an object"]

    errors: list[str] = []

    def visit(value: object, path: str) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = f"{path}.{key}"
                if key in {"automerge", "platformAutomerge"} and child is True:
                    errors.append(f"{child_path} must not enable Renovate merging")
                if key in FORBIDDEN_AUTOMERGE_KEYS:
                    errors.append(
                        f"{child_path} must not be present; the org sweep owns merge execution"
                    )
                if key in {"addLabels", "labels"} and isinstance(child, list):
                    normalized = {
                        item.casefold() for item in child if isinstance(item, str)
                    }
                    if ORG_CANDIDATE_LABEL in normalized:
                        errors.append(
                            f"{child_path} must not assign {ORG_CANDIDATE_LABEL}; "
                            "the org preset owns merge eligibility"
                        )
                if key == "removeLabels" and isinstance(child, list):
                    normalized = {
                        item.casefold() for item in child if isinstance(item, str)
                    }
                    removed = sorted(normalized & ORG_RESERVED_LABELS)
                    if removed:
                        errors.append(
                            f"{child_path} must not remove reserved org automation "
                            f"labels: {', '.join(removed)}"
                        )
                visit(child, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]")

    visit(config, "renovate")
    return errors


def read_remote_file(repository: str, ref: str, path: str) -> str:
    endpoint = f"repos/{repository}/contents/{path}?ref={ref}"
    completed = subprocess.run(
        ["gh", "api", endpoint, "--jq", ".content"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return base64.b64decode(completed.stdout).decode("utf-8")


def read_remote_workflow(repository: str, ref: str) -> str:
    return read_remote_file(repository, ref, ".github/workflows/security-scan.yml")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(".github/security-scan-adopters.json"),
    )
    parser.add_argument("--ref", default="main")
    parser.add_argument(
        "--required-revision",
        required=True,
        help="Exact org workflow commit every caller must use.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.required_revision and not COMMIT_RE.fullmatch(args.required_revision):
        print(
            "ERROR: --required-revision must be an exact 40-character lowercase commit SHA",
            file=sys.stderr,
        )
        return 1
    if not os.environ.get("GH_TOKEN", "").strip():
        print(
            "ERROR: GH_TOKEN is required and must be a read token with access to every declared repository",
            file=sys.stderr,
        )
        return 1
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot load adopter manifest: {exc}", file=sys.stderr)
        return 1
    repositories = manifest.get("repositories")
    if not isinstance(repositories, list) or not all(
        isinstance(repository, str) and "/" in repository
        for repository in repositories
    ):
        print("ERROR: repositories must be a list of owner/name strings", file=sys.stderr)
        return 1
    renovate_repositories = manifest.get("renovate_config_repositories")
    if not isinstance(renovate_repositories, list) or not all(
        isinstance(repository, str) and "/" in repository
        for repository in renovate_repositories
    ):
        print(
            "ERROR: renovate_config_repositories must be a list of owner/name strings",
            file=sys.stderr,
        )
        return 1
    unknown_renovate_repositories = set(renovate_repositories) - set(repositories)
    if unknown_renovate_repositories:
        print(
            "ERROR: renovate_config_repositories must be a subset of repositories",
            file=sys.stderr,
        )
        return 1

    errors: list[str] = []
    for repository in sorted(set(repositories)):
        try:
            workflow = read_remote_workflow(repository, args.ref)
        except (subprocess.CalledProcessError, ValueError, UnicodeDecodeError) as exc:
            errors.append(
                f"{repository}: cannot read security-scan.yml at {args.ref}: {exc}"
            )
            continue
        for validation_error in validate_caller(workflow, args.required_revision):
            errors.append(f"{repository}: {validation_error}")

    for repository in sorted(set(renovate_repositories)):
        try:
            config = read_remote_file(repository, args.ref, "renovate.json")
        except (subprocess.CalledProcessError, ValueError, UnicodeDecodeError) as exc:
            errors.append(f"{repository}: cannot read renovate.json at {args.ref}: {exc}")
            continue
        for validation_error in validate_renovate_config(config):
            errors.append(f"{repository}: {validation_error}")

    if errors:
        for validation_error in errors:
            print(f"ERROR: {validation_error}", file=sys.stderr)
        return 1
    print(
        f"Validated truthful Trivy adoption in {len(set(repositories))} repositories "
        f"and label-only local Renovate policy in {len(set(renovate_repositories))} repositories."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
