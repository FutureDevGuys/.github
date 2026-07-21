#!/usr/bin/env python3
"""Audit repositories for truthful Trivy callers and label-only Renovate config."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote


USES_RE = re.compile(
    r"^\s+uses:\s+FutureDevGuys/\.github/\.github/workflows/security-scan\.yml@([0-9a-f]{40})\s*$",
    re.MULTILINE,
)
REVISION_RE = re.compile(
    r"^      workflow_revision:\s*[\"']?([0-9a-f]{40})[\"']?\s*$",
    re.MULTILINE,
)
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
HTTP_STATUS_RE = re.compile(r"HTTP\s+([0-9]{3})")
FORBIDDEN_AUTOMERGE_KEYS = {"automergeType", "automergeStrategy"}
ORG_CANDIDATE_LABEL = "automerge-candidate"
ORG_BLOCK_LABELS = {"do-not-merge", "manual-review", "migration-required", "major"}
ORG_RESERVED_LABELS = {ORG_CANDIDATE_LABEL, *ORG_BLOCK_LABELS}
CALLER_TEMPLATE = (
    Path(__file__).resolve().parents[1]
    / "tests/fixtures/security-scan-caller.yml"
)
SHARED_PRESET = Path(__file__).resolve().parents[2] / "renovate-config.json"
APPROVED_SHARED_EXTENDS = [
    "config:recommended",
    ":label(renovate)",
    ":semanticCommits",
    ":configMigration",
    "docker:pinDigests",
    "helpers:pinGitHubActionDigests",
    "mergeConfidence:all-badges",
]
REPORT_SCHEMA_VERSION = 1
RECEIPT_SCHEMA_VERSION = 1
TOOL_NAME = "security-scan-adoption-audit"
TOOL_VERSION = "2.0.0"


class AdoptionError(RuntimeError):
    """Discovery, policy, evidence, or remote content is not trustworthy."""


class ContentUnavailable(AdoptionError):
    pass


class InventoryProvider(Protocol):
    def organization(self) -> dict[str, Any]: ...

    def repositories(self) -> list[dict[str, Any]]: ...

    def default_revision(self, repository: str, branch: str) -> str: ...

    def file(self, repository: str, ref: str, path: str) -> str | None: ...


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


def canonical_caller(revision: str) -> str:
    if COMMIT_RE.fullmatch(revision) is None:
        raise AdoptionError("canonical caller revision must be one exact commit SHA")
    template = CALLER_TEMPLATE.read_text(encoding="utf-8")
    placeholder = "1" * 40
    if template.count(placeholder) != 2:
        raise AdoptionError("canonical caller template must contain two revision pins")
    return template.replace(placeholder, revision)


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
    canonical_revision = required_revision
    if canonical_revision is None and len(uses) == 1 and len(revisions) == 1:
        if uses[0] == revisions[0]:
            canonical_revision = uses[0]
    if canonical_revision is not None and COMMIT_RE.fullmatch(canonical_revision):
        if text != canonical_caller(canonical_revision):
            errors.append(
                "caller bytes must exactly match the approved organization artifact"
            )
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
                if key == "extends" and child != []:
                    errors.append(
                        f"{child_path} must be absent or empty; repository policy "
                        "cannot inherit unapproved presets"
                    )
                if key == "ignorePresets":
                    errors.append(
                        f"{child_path} must not be present; the organization preset "
                        "is mandatory"
                    )
                if key == "globalExtends":
                    errors.append(
                        f"{child_path} must not be present; repository policy cannot "
                        "change preset resolution"
                    )
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


def validate_shared_preset(text: str) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        preset = json.loads(text)
    except json.JSONDecodeError as error:
        return None, [f"shared preset is not valid JSON: {error}"]
    if not isinstance(preset, dict):
        return None, ["shared preset root must be an object"]
    errors: list[str] = []
    if preset.get("extends") != APPROVED_SHARED_EXTENDS:
        errors.append("shared preset extends must equal the closed built-in allowlist")
    if preset.get("platformAutomerge") is not False:
        errors.append("shared preset must disable platformAutomerge")
    rules = preset.get("packageRules")
    if not isinstance(rules, list):
        errors.append("shared preset packageRules must be a list")
        return preset, errors
    major_rules = [
        rule
        for rule in rules
        if isinstance(rule, dict) and rule.get("matchUpdateTypes") == ["major"]
    ]
    if len(major_rules) != 1:
        errors.append("shared preset must contain one exact major-update safety rule")
    else:
        major = major_rules[0]
        labels = major.get("addLabels")
        if major.get("automerge") is not False or not isinstance(labels, list):
            errors.append("shared major-update rule must disable automerge and add labels")
        elif not {"manual-review", "major"}.issubset(
            {label.casefold() for label in labels if isinstance(label, str)}
        ):
            errors.append("shared major-update rule must add manual-review and major")
    candidate_rules = [
        rule
        for rule in rules
        if isinstance(rule, dict)
        and isinstance(rule.get("addLabels"), list)
        and ORG_CANDIDATE_LABEL
        in {
            label.casefold()
            for label in rule["addLabels"]
            if isinstance(label, str)
        }
    ]
    if not candidate_rules:
        errors.append("shared preset must own at least one automerge-candidate rule")
    for rule in candidate_rules:
        if rule.get("automerge") is not False:
            errors.append("every shared automerge-candidate rule must disable Renovate merging")

    def visit(value: object, path: str) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = f"{path}.{key}"
                if key in {"ignorePresets", "globalExtends"}:
                    errors.append(
                        f"{child_path} must not be present; shared preset resolution "
                        "is closed"
                    )
                if key == "extends" and path != "shared":
                    errors.append(
                        f"{child_path} must not be present; nested shared preset "
                        "inheritance is forbidden"
                    )
                if key == "automerge" and child is True:
                    errors.append(f"{child_path} must not enable Renovate merging")
                if key in FORBIDDEN_AUTOMERGE_KEYS:
                    errors.append(f"{child_path} must not delegate merge execution")
                if key == "removeLabels" and isinstance(child, list):
                    removed = {
                        label.casefold()
                        for label in child
                        if isinstance(label, str)
                    }
                    if removed & ORG_RESERVED_LABELS:
                        errors.append(f"{child_path} must not remove reserved labels")
                visit(child, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]")

    visit(preset, "shared")
    return preset, errors


def effective_config_proof(
    shared_preset_text: str, local_config_text: str
) -> tuple[dict[str, Any], list[str]]:
    _, shared_errors = validate_shared_preset(shared_preset_text)
    local_errors = validate_renovate_config(local_config_text)
    proof = {
        "shared_preset_sha256": hashlib.sha256(
            shared_preset_text.encode("utf-8")
        ).hexdigest(),
        "local_config_sha256": hashlib.sha256(
            local_config_text.encode("utf-8")
        ).hexdigest(),
        "shared_extends_allowlist_exact": not shared_errors,
        "local_extends_closed": not any(
            control in error
            for error in local_errors
            for control in ("extends", "ignorePresets", "globalExtends", "preset resolution")
        ),
        "local_candidate_label_forbidden": not any(
            ORG_CANDIDATE_LABEL in error for error in local_errors
        ),
        "reserved_label_removal_forbidden": not any(
            "remove reserved" in error for error in local_errors
        ),
        "renovate_merge_execution_forbidden": not any(
            "Renovate merging" in error or "merge execution" in error
            for error in local_errors
        ),
        "major_manual_review_invariant": not shared_errors
        and not any("remove reserved" in error for error in local_errors),
    }
    return proof, [*shared_errors, *local_errors]


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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


def load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise AdoptionError(f"cannot read {label}: {error}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size > 5 * 1024 * 1024
        or metadata.st_nlink != 1
    ):
        raise AdoptionError(f"{label} must be one bounded regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdoptionError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise AdoptionError(f"{label} root must be an object")
    return value


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise AdoptionError(f"{label} keys must be exactly {sorted(expected)}")


def load_policy(path: Path) -> dict[str, Any]:
    policy = load_json_object(path, "adoption policy")
    exact_keys(
        policy,
        {
            "schema_version",
            "organization",
            "default_lifecycle",
            "lifecycle_overrides",
            "requirements",
        },
        "policy",
    )
    if policy["schema_version"] != 2 or policy["default_lifecycle"] != "active":
        raise AdoptionError("policy schema or default lifecycle is unsupported")
    organization = policy["organization"]
    overrides = policy["lifecycle_overrides"]
    requirements = policy["requirements"]
    if not isinstance(organization, dict):
        raise AdoptionError("policy.organization must be an object")
    exact_keys(organization, {"login", "id", "node_id"}, "policy.organization")
    if (
        organization.get("login") != "FutureDevGuys"
        or not isinstance(organization.get("id"), int)
        or not isinstance(organization.get("node_id"), str)
    ):
        raise AdoptionError("policy organization identity is invalid")
    if not isinstance(overrides, dict) or not isinstance(requirements, dict):
        raise AdoptionError("policy lifecycle overrides and requirements must be objects")
    expected_requirements = {
        "active": {
            "security_scan": "required",
            "renovate_config": "validate_if_present",
        },
        "authority": {
            "security_scan": "provider",
            "renovate_config": "not_applicable",
        },
        "archived": {
            "security_scan": "not_applicable",
            "renovate_config": "not_applicable",
        },
    }
    if requirements != expected_requirements:
        raise AdoptionError("policy lifecycle requirements are not exact")
    for repository, override in overrides.items():
        if not isinstance(repository, str) or not repository.startswith("FutureDevGuys/"):
            raise AdoptionError("policy lifecycle override repository is invalid")
        if not isinstance(override, dict):
            raise AdoptionError(f"override for {repository} must be an object")
        exact_keys(
            override,
            {"repository_id", "node_id", "lifecycle"},
            f"override {repository}",
        )
        if (
            not isinstance(override.get("repository_id"), int)
            or not isinstance(override.get("node_id"), str)
            or override.get("lifecycle") not in {"authority", "archived"}
        ):
            raise AdoptionError(f"override for {repository} is invalid")
    return policy


class GitHubProvider:
    def _json(self, endpoint: str, *, paginate: bool = False) -> Any:
        command = ["gh", "api", endpoint]
        if paginate:
            command.extend(["--paginate", "--slurp"])
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if completed.returncode != 0:
            match = HTTP_STATUS_RE.search(completed.stderr)
            status = int(match.group(1)) if match else None
            raise ContentUnavailable(
                f"GitHub API request failed for {endpoint}"
                + (f" (HTTP {status})" if status else "")
            )
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise ContentUnavailable(
                f"GitHub API returned invalid JSON for {endpoint}"
            ) from error

    def organization(self) -> dict[str, Any]:
        value = self._json("orgs/FutureDevGuys")
        if not isinstance(value, dict):
            raise ContentUnavailable("organization metadata is not an object")
        return value

    def repositories(self) -> list[dict[str, Any]]:
        pages = self._json(
            "orgs/FutureDevGuys/repos?per_page=100&type=all", paginate=True
        )
        if not isinstance(pages, list) or not all(
            isinstance(page, list) for page in pages
        ):
            raise ContentUnavailable("paginated repository inventory is malformed")
        return [repository for page in pages for repository in page]

    def default_revision(self, repository: str, branch: str) -> str:
        value = self._json(
            f"repos/{repository}/git/ref/heads/{quote(branch, safe='')}"
        )
        target = value.get("object") if isinstance(value, dict) else None
        revision = target.get("sha") if isinstance(target, dict) else None
        if (
            not isinstance(value, dict)
            or value.get("ref") != f"refs/heads/{branch}"
            or not isinstance(target, dict)
            or target.get("type") != "commit"
            or not isinstance(revision, str)
            or COMMIT_RE.fullmatch(revision) is None
        ):
            raise ContentUnavailable(
                f"default branch ref for {repository} is not one exact commit"
            )
        return revision

    def file(self, repository: str, ref: str, path: str) -> str | None:
        endpoint = f"repos/{repository}/contents/{path}?ref={ref}"
        completed = subprocess.run(
            ["gh", "api", endpoint, "--jq", ".content"],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if completed.returncode != 0:
            match = HTTP_STATUS_RE.search(completed.stderr)
            if match and int(match.group(1)) == 404:
                return None
            raise ContentUnavailable(f"cannot read {repository}/{path} at {ref}")
        try:
            encoded = "".join(completed.stdout.split())
            return base64.b64decode(encoded, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as error:
            raise ContentUnavailable(
                f"{repository}/{path} at {ref} is not canonical UTF-8 content"
            ) from error


class FixtureProvider:
    def __init__(self, path: Path) -> None:
        fixture = load_json_object(path, "adoption fixture")
        exact_keys(fixture, {"organization", "repositories"}, "adoption fixture")
        organization = fixture["organization"]
        repositories = fixture["repositories"]
        if not isinstance(organization, dict) or not isinstance(repositories, list):
            raise AdoptionError("adoption fixture inventory is malformed")
        self._organization = organization
        self._repositories: list[dict[str, Any]] = []
        self._files: dict[tuple[str, str], str] = {}
        self._default_revisions: dict[str, str] = {}
        for row in repositories:
            if (
                not isinstance(row, dict)
                or "files" not in row
                or "default_revision" not in row
            ):
                raise AdoptionError("adoption fixture repository is malformed")
            files = row["files"]
            default_revision = row["default_revision"]
            metadata = {
                key: value
                for key, value in row.items()
                if key not in {"files", "default_revision"}
            }
            if not isinstance(files, dict) or not all(
                isinstance(key, str) and isinstance(value, str)
                for key, value in files.items()
            ):
                raise AdoptionError("adoption fixture file map is malformed")
            repository = metadata.get("full_name")
            if (
                not isinstance(repository, str)
                or not isinstance(default_revision, str)
            ):
                raise AdoptionError("adoption fixture repository name is invalid")
            self._repositories.append(metadata)
            self._default_revisions[repository] = default_revision
            for name, content in files.items():
                self._files[(repository, name)] = content

    def organization(self) -> dict[str, Any]:
        return self._organization

    def repositories(self) -> list[dict[str, Any]]:
        return self._repositories

    def default_revision(self, repository: str, branch: str) -> str:
        metadata = next(
            (
                row
                for row in self._repositories
                if row.get("full_name") == repository
            ),
            None,
        )
        if not isinstance(metadata, dict) or metadata.get("default_branch") != branch:
            raise ContentUnavailable(
                f"default branch for {repository} differs from the fixture"
            )
        try:
            return self._default_revisions[repository]
        except KeyError as error:
            raise ContentUnavailable(
                f"default branch revision for {repository} is unavailable"
            ) from error

    def file(self, repository: str, ref: str, path: str) -> str | None:
        if self._default_revisions.get(repository) != ref:
            raise ContentUnavailable(
                f"fixture read for {repository}/{path} did not use its exact default revision"
            )
        return self._files.get((repository, path))


def normalized_repository(repository: dict[str, Any]) -> dict[str, Any]:
    owner = repository.get("owner")
    if not isinstance(owner, dict):
        raise AdoptionError("repository owner identity is missing")
    fields = {
        "full_name": repository.get("full_name"),
        "id": repository.get("id"),
        "node_id": repository.get("node_id"),
        "archived": repository.get("archived"),
        "disabled": repository.get("disabled"),
        "private": repository.get("private"),
        "visibility": repository.get("visibility"),
        "default_branch": repository.get("default_branch"),
        "owner": {
            "login": owner.get("login"),
            "id": owner.get("id"),
            "node_id": owner.get("node_id"),
        },
    }
    if (
        not isinstance(fields["full_name"], str)
        or not isinstance(fields["id"], int)
        or not isinstance(fields["node_id"], str)
        or not isinstance(fields["archived"], bool)
        or not isinstance(fields["disabled"], bool)
        or not isinstance(fields["private"], bool)
        or fields["visibility"] not in {"public", "private"}
        or not isinstance(fields["default_branch"], str)
    ):
        raise AdoptionError("repository inventory contains invalid fields")
    return fields


def classify_repository(
    repository: dict[str, Any], policy: dict[str, Any]
) -> tuple[str, list[str]]:
    name = repository["full_name"]
    override = policy["lifecycle_overrides"].get(name)
    findings: list[str] = []
    if override is None:
        if repository["archived"]:
            findings.append("archived repository lacks an explicit lifecycle override")
            return "archived", findings
        return policy["default_lifecycle"], findings
    if (
        repository["id"] != override["repository_id"]
        or repository["node_id"] != override["node_id"]
    ):
        findings.append("repository identity differs from lifecycle override")
    lifecycle = override["lifecycle"]
    if lifecycle == "archived" and not repository["archived"]:
        findings.append("repository is classified archived but live metadata is active")
    if lifecycle == "authority" and repository["archived"]:
        findings.append("authority repository must not be archived")
    return lifecycle, findings


def audit_adoption(
    provider: InventoryProvider,
    policy_path: Path,
    required_revision: str,
    shared_preset_path: Path,
) -> dict[str, Any]:
    if COMMIT_RE.fullmatch(required_revision) is None:
        raise AdoptionError("required revision must be one exact commit SHA")
    policy = load_policy(policy_path)
    shared_preset_text = shared_preset_path.read_text(encoding="utf-8")
    organization = provider.organization()
    repositories = [normalized_repository(row) for row in provider.repositories()]
    repositories.sort(key=lambda row: row["full_name"])
    names = [row["full_name"] for row in repositories]
    if len(names) != len(set(names)):
        raise AdoptionError("paginated repository inventory contains duplicates")
    findings: list[str] = []
    expected_organization = policy["organization"]
    organization_exact = all(
        organization.get(key) == expected_organization[key]
        for key in ("login", "id", "node_id")
    )
    if not organization_exact:
        findings.append("organization identity differs from policy")
    public_repos = organization.get("public_repos")
    private_repos = organization.get("total_private_repos")
    expected_count = (
        public_repos + private_repos
        if isinstance(public_repos, int)
        and not isinstance(public_repos, bool)
        and isinstance(private_repos, int)
        and not isinstance(private_repos, bool)
        else None
    )
    count_exact = expected_count == len(repositories)
    if not count_exact:
        findings.append("paginated repository count does not match organization totals")
    for repository in repositories:
        if repository["owner"] != expected_organization:
            findings.append(f"{repository['full_name']}: owner identity differs from policy")
        if not repository["full_name"].startswith("FutureDevGuys/"):
            findings.append(f"{repository['full_name']}: repository is outside the organization")
    missing_overrides = sorted(set(policy["lifecycle_overrides"]) - set(names))
    for repository in missing_overrides:
        findings.append(f"{repository}: lifecycle override is absent from discovery")

    rows: list[dict[str, Any]] = []
    for repository in repositories:
        name = repository["full_name"]
        lifecycle, lifecycle_findings = classify_repository(repository, policy)
        row_findings = [f"{name}: {message}" for message in lifecycle_findings]
        if repository["disabled"]:
            row_findings.append(f"{name}: repository is disabled")
        caller_status = "not_applicable"
        renovate_status = "not_applicable"
        proof: dict[str, Any] | None = None
        default_revision: str | None = None
        if lifecycle == "active":
            try:
                candidate_revision = provider.default_revision(
                    name, repository["default_branch"]
                )
                if COMMIT_RE.fullmatch(candidate_revision) is None:
                    raise ContentUnavailable(
                        f"default branch ref for {name} is not one exact commit"
                    )
                default_revision = candidate_revision
            except ContentUnavailable as error:
                row_findings.append(f"{name}: {error}")
            ref = default_revision
            if ref is None:
                caller_status = "unknown"
                renovate_status = "unknown"
                findings.extend(row_findings)
                rows.append(
                    {
                        **repository,
                        "default_revision": None,
                        "lifecycle": lifecycle,
                        "security_scan": caller_status,
                        "renovate_effective_config": renovate_status,
                        "effective_config_proof": proof,
                        "findings": row_findings,
                    }
                )
                continue
            try:
                caller = provider.file(
                    name, ref, ".github/workflows/security-scan.yml"
                )
            except ContentUnavailable as error:
                caller = None
                row_findings.append(f"{name}: {error}")
            if caller is None:
                caller_status = "missing"
                row_findings.append(f"{name}: security-scan caller is missing")
            else:
                caller_errors = validate_caller(caller, required_revision)
                caller_status = "pass" if not caller_errors else "fail"
                row_findings.extend(f"{name}: {error}" for error in caller_errors)
            try:
                local_config = provider.file(name, ref, "renovate.json")
            except ContentUnavailable as error:
                local_config = None
                row_findings.append(f"{name}: {error}")
            if local_config is None:
                local_config = "{}\n"
                renovate_status = "absent_pass"
            proof, effective_errors = effective_config_proof(
                shared_preset_text, local_config
            )
            if effective_errors:
                renovate_status = "fail"
                row_findings.extend(f"{name}: {error}" for error in effective_errors)
            elif renovate_status != "absent_pass":
                renovate_status = "pass"
        findings.extend(row_findings)
        rows.append(
            {
                **repository,
                "default_revision": default_revision,
                "lifecycle": lifecycle,
                "security_scan": caller_status,
                "renovate_effective_config": renovate_status,
                "effective_config_proof": proof,
                "findings": row_findings,
            }
        )
    inventory_bytes = canonical_json(repositories)
    active_revisions = [
        {
            "repository": row["full_name"],
            "revision": row["default_revision"],
        }
        for row in rows
        if row["lifecycle"] == "active"
    ]
    active_revisions_bytes = canonical_json(active_revisions)
    result = {"status": "pass" if not findings else "fail", "finding_count": len(findings)}
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "executed": True,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "policy": {
            "path": policy_path.name,
            "sha256": digest(policy_path.read_bytes()),
        },
        "inputs": {
            "required_revision": required_revision,
            "shared_preset_sha256": digest(shared_preset_text.encode("utf-8")),
            "active_revisions_sha256": digest(active_revisions_bytes),
        },
        "visibility": {
            "organization_identity_exact": organization_exact,
            "expected_repository_count": expected_count,
            "discovered_repository_count": len(repositories),
            "repository_count_exact": count_exact,
            "paginated": True,
            "inventory_sha256": digest(inventory_bytes),
            "complete": organization_exact
            and count_exact
            and not missing_overrides,
        },
        "repositories": rows,
        "findings": findings,
        "result": result,
    }


def build_receipt(report_path: Path, report: dict[str, Any]) -> dict[str, Any]:
    raw = report_path.read_bytes()
    return {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "executed": True,
        "tool": report["tool"],
        "inputs": {
            "policy_sha256": report["policy"]["sha256"],
            "required_revision": report["inputs"]["required_revision"],
            "shared_preset_sha256": report["inputs"]["shared_preset_sha256"],
            "inventory_sha256": report["visibility"]["inventory_sha256"],
            "active_revisions_sha256": report["inputs"][
                "active_revisions_sha256"
            ],
            "repository_count": report["visibility"]["discovered_repository_count"],
        },
        "result": report["result"],
        "artifact": {
            "path": report_path.name,
            "sha256": digest(raw),
            "size_bytes": len(raw),
        },
    }


def validate_evidence(report_path: Path, receipt_path: Path) -> list[str]:
    try:
        report = load_json_object(report_path, "adoption report")
        receipt = load_json_object(receipt_path, "adoption receipt")
    except AdoptionError as error:
        return [str(error)]
    errors: list[str] = []
    if report.get("schema_version") != REPORT_SCHEMA_VERSION or report.get("executed") is not True:
        errors.append("report does not prove execution")
    visibility = report.get("visibility")
    repositories = report.get("repositories")
    if not isinstance(visibility, dict) or not isinstance(repositories, list):
        errors.append("report visibility or repositories are missing")
    else:
        if visibility.get("paginated") is not True:
            errors.append("report does not prove paginated discovery")
        normalized = [
            {
                key: row[key]
                for key in (
                    "full_name",
                    "id",
                    "node_id",
                    "archived",
                    "disabled",
                    "private",
                    "visibility",
                    "default_branch",
                    "owner",
                )
            }
            for row in repositories
            if isinstance(row, dict)
            and all(
                key in row
                for key in (
                    "full_name",
                    "id",
                    "node_id",
                    "archived",
                    "disabled",
                    "private",
                    "visibility",
                    "default_branch",
                    "owner",
                )
            )
        ]
        if len(normalized) != len(repositories):
            errors.append("report repository inventory is malformed")
        elif visibility.get("inventory_sha256") != digest(canonical_json(normalized)):
            errors.append("report repository inventory digest does not match")
        if visibility.get("discovered_repository_count") != len(repositories):
            errors.append("report repository count does not match inventory")
        if visibility.get("complete") is not True:
            errors.append("report does not prove complete organization visibility")
        active_revisions: list[dict[str, str]] = []
        for row in repositories:
            if not isinstance(row, dict) or row.get("lifecycle") != "active":
                continue
            revision = row.get("default_revision")
            if not isinstance(revision, str) or COMMIT_RE.fullmatch(revision) is None:
                errors.append(
                    "active repository does not bind one exact default revision"
                )
                continue
            active_revisions.append(
                {"repository": row["full_name"], "revision": revision}
            )
        inputs = report.get("inputs")
        if (
            not isinstance(inputs, dict)
            or inputs.get("active_revisions_sha256")
            != digest(canonical_json(active_revisions))
        ):
            errors.append("report active revision digest does not match")
    raw = report_path.read_bytes()
    artifact = receipt.get("artifact")
    if not isinstance(artifact, dict):
        errors.append("receipt artifact binding is missing")
    else:
        if artifact.get("path") != report_path.name:
            errors.append("receipt artifact path does not match")
        if artifact.get("sha256") != digest(raw):
            errors.append("receipt artifact digest does not match")
        if artifact.get("size_bytes") != len(raw):
            errors.append("receipt artifact size does not match")
    expected_inputs = {
        "policy_sha256": report.get("policy", {}).get("sha256")
        if isinstance(report.get("policy"), dict)
        else None,
        "required_revision": report.get("inputs", {}).get("required_revision")
        if isinstance(report.get("inputs"), dict)
        else None,
        "shared_preset_sha256": report.get("inputs", {}).get("shared_preset_sha256")
        if isinstance(report.get("inputs"), dict)
        else None,
        "inventory_sha256": visibility.get("inventory_sha256")
        if isinstance(visibility, dict)
        else None,
        "active_revisions_sha256": report.get("inputs", {}).get(
            "active_revisions_sha256"
        )
        if isinstance(report.get("inputs"), dict)
        else None,
        "repository_count": visibility.get("discovered_repository_count")
        if isinstance(visibility, dict)
        else None,
    }
    if receipt.get("inputs") != expected_inputs:
        errors.append("receipt inputs do not bind report inputs")
    if receipt.get("result") != report.get("result") or receipt.get("executed") is not True:
        errors.append("receipt does not bind executed report result")
    if report.get("result") != {"status": "pass", "finding_count": 0}:
        errors.append("adoption audit result is not pass")
    return errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(".github/security-scan-adopters.json"),
    )
    parser.add_argument("--shared-preset", type=Path, default=SHARED_PRESET)
    commands = parser.add_subparsers(dest="command", required=True)
    audit = commands.add_parser("audit")
    audit.add_argument("--required-revision", required=True)
    audit.add_argument("--inventory-fixture", type=Path)
    audit.add_argument("--report", type=Path, required=True)
    audit.add_argument("--receipt", type=Path, required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--report", type=Path, required=True)
    validate.add_argument("--receipt", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "validate":
            errors = validate_evidence(args.report, args.receipt)
            for error in errors:
                print(f"ERROR: {error}", file=sys.stderr)
            return 1 if errors else 0
        if args.inventory_fixture is None:
            if not os.environ.get("GH_TOKEN", "").strip():
                raise AdoptionError(
                    "GH_TOKEN is required for live paginated organization discovery"
                )
            provider: InventoryProvider = GitHubProvider()
        else:
            provider = FixtureProvider(args.inventory_fixture)
        report = audit_adoption(
            provider,
            args.manifest,
            args.required_revision,
            args.shared_preset,
        )
        write_atomic(args.report, report)
        write_atomic(args.receipt, build_receipt(args.report, report))
        for finding_value in report["findings"]:
            print(f"ERROR: {finding_value}", file=sys.stderr)
        return 0 if report["result"]["status"] == "pass" else 1
    except (AdoptionError, OSError, UnicodeDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
