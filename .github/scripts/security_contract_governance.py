#!/usr/bin/env python3
"""Resolve, audit, and safely release the shared security contract authority."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Protocol, cast
from urllib.parse import quote


TOOL_NAME = "security-contract-governance"
TOOL_VERSION = "1.0.0"
SCHEMA_VERSION = 1
SHA40 = re.compile(r"^[0-9a-f]{40}$")
BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
HTTP_STATUS = re.compile(r"HTTP\s+([0-9]{3})")
WORKFLOW_SCRIPT = re.compile(
    r"(?:\.security-contract/)?(\.github/scripts/[A-Za-z0-9_./-]+\.py)"
)
FORBIDDEN_EVIDENCE_KEYS = {
    "authorization",
    "cookie",
    "credential",
    "credentials",
    "password",
    "secret",
    "token",
}


class GovernanceError(RuntimeError):
    """A deterministic policy, repository, or remote-state failure."""


class ApiError(GovernanceError):
    def __init__(self, endpoint: str, status: int | None = None) -> None:
        self.endpoint = endpoint
        self.status = status
        suffix = f" (HTTP {status})" if status is not None else ""
        super().__init__(f"GitHub API request failed for {endpoint}{suffix}")


class GitHub(Protocol):
    def api(
        self,
        endpoint: str,
        *,
        method: str = "GET",
        payload: dict[str, Any] | None = None,
    ) -> Any: ...


class GhClient:
    """Small sanitized gh-api boundary used by audit and explicit release apply."""

    def api(
        self,
        endpoint: str,
        *,
        method: str = "GET",
        payload: dict[str, Any] | None = None,
    ) -> Any:
        command = ["gh", "api", "--method", method, endpoint]
        input_text = None
        if payload is not None:
            command.extend(["--input", "-"])
            input_text = json.dumps(payload, separators=(",", ":"))
        try:
            completed = subprocess.run(
                command,
                input=input_text,
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ApiError(endpoint) from error
        if completed.returncode != 0:
            match = HTTP_STATUS.search(completed.stderr)
            raise ApiError(endpoint, int(match.group(1)) if match else None)
        if not completed.stdout.strip():
            return {}
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise ApiError(endpoint) from error


@dataclass(frozen=True)
class Policy:
    path: Path
    raw: dict[str, Any]
    repository: str
    database_id: int
    node_id: str
    default_branch: str
    release_branch: str
    entrypoint: str
    paths: dict[str, str]
    python_roots: tuple[str, ...]
    status_checks_mode: str
    status_checks_reason: str

    @property
    def digest(self) -> str:
        return sha256(self.path.read_bytes())


@dataclass(frozen=True)
class TreeEntry:
    mode: str
    object_type: str
    oid: str
    path: str


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def sha256(value: bytes) -> str:
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


def exact_keys(value: dict[str, Any], expected: set[str], location: str) -> None:
    if set(value) != expected:
        raise GovernanceError(f"{location} keys must be exactly {sorted(expected)}")


def safe_branch(value: Any, location: str) -> str:
    if (
        not isinstance(value, str)
        or BRANCH.fullmatch(value) is None
        or ".." in value
        or "//" in value
        or "@{" in value
        or value.endswith(("/", ".", ".lock"))
    ):
        raise GovernanceError(f"{location} is not a safe branch name")
    return value


def safe_path(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value:
        raise GovernanceError(f"{location} must be a nonempty path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or str(path) != value:
        raise GovernanceError(f"{location} must be a normalized repository path")
    return value


def load_policy(path: Path) -> Policy:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise GovernanceError("governance policy is unreadable or invalid") from error
    if not isinstance(raw, dict):
        raise GovernanceError("governance policy root must be an object")
    exact_keys(
        raw,
        {"schema_version", "repository", "release_branch", "bundle", "protection"},
        "policy",
    )
    if raw["schema_version"] != SCHEMA_VERSION:
        raise GovernanceError("unsupported governance policy schema_version")
    repository = raw["repository"]
    bundle = raw["bundle"]
    protection = raw["protection"]
    if not all(isinstance(item, dict) for item in (repository, bundle, protection)):
        raise GovernanceError("repository, bundle, and protection must be objects")
    exact_keys(
        repository,
        {"full_name", "database_id", "node_id", "default_branch"},
        "policy.repository",
    )
    exact_keys(bundle, {"entrypoint", "paths", "python_roots"}, "policy.bundle")
    exact_keys(
        protection,
        {
            "required_signatures",
            "enforce_admins",
            "required_linear_history",
            "allow_force_pushes",
            "allow_deletions",
            "required_status_checks",
        },
        "policy.protection",
    )
    required_booleans = {
        "required_signatures": True,
        "enforce_admins": True,
        "required_linear_history": True,
        "allow_force_pushes": False,
        "allow_deletions": False,
    }
    for field, required in required_booleans.items():
        if protection.get(field) is not required:
            raise GovernanceError(f"policy.protection.{field} must be {required}")
    checks = protection["required_status_checks"]
    if not isinstance(checks, dict):
        raise GovernanceError("required_status_checks must be an object")
    exact_keys(checks, {"mode", "reason", "contexts"}, "required_status_checks")
    if checks.get("mode") != "intentionally_absent":
        raise GovernanceError("only intentionally_absent status checks are supported")
    if checks.get("reason") != "github_actions_billing_admission_blocked":
        raise GovernanceError("status-check absence must name the billing admission blocker")
    if checks.get("contexts") != []:
        raise GovernanceError("intentionally absent status checks cannot declare contexts")
    paths = bundle["paths"]
    roots = bundle["python_roots"]
    if not isinstance(paths, dict) or not paths:
        raise GovernanceError("bundle.paths must be a nonempty object")
    normalized_paths: dict[str, str] = {}
    for index, (name, mode) in enumerate(paths.items()):
        normalized = safe_path(name, f"bundle.paths[{index}]")
        if mode != "100644":
            raise GovernanceError(f"bundle path {normalized} must require mode 100644")
        normalized_paths[normalized] = mode
    if not isinstance(roots, list) or not roots:
        raise GovernanceError("bundle.python_roots must be a nonempty list")
    normalized_roots = tuple(
        safe_path(value, f"bundle.python_roots[{index}]")
        for index, value in enumerate(roots)
    )
    entrypoint = safe_path(bundle["entrypoint"], "bundle.entrypoint")
    if entrypoint not in normalized_paths:
        raise GovernanceError("bundle.entrypoint must be declared in bundle.paths")
    full_name = repository["full_name"]
    if full_name != "FutureDevGuys/.github":
        raise GovernanceError("policy repository must be FutureDevGuys/.github")
    if not isinstance(repository["database_id"], int) or repository["database_id"] <= 0:
        raise GovernanceError("repository.database_id must be a positive integer")
    if not isinstance(repository["node_id"], str) or not repository["node_id"]:
        raise GovernanceError("repository.node_id must be nonempty")
    return Policy(
        path=path,
        raw=raw,
        repository=full_name,
        database_id=repository["database_id"],
        node_id=repository["node_id"],
        default_branch=safe_branch(repository["default_branch"], "default_branch"),
        release_branch=safe_branch(raw["release_branch"], "release_branch"),
        entrypoint=entrypoint,
        paths=dict(sorted(normalized_paths.items())),
        python_roots=normalized_roots,
        status_checks_mode=checks["mode"],
        status_checks_reason=checks["reason"],
    )


def run_git(repo: Path, arguments: list[str], *, text: bool = True) -> str | bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), *arguments],
            check=False,
            capture_output=True,
            text=text,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise GovernanceError("git command failed") from error
    if completed.returncode != 0:
        raise GovernanceError(f"git command failed: {' '.join(arguments[:2])}")
    return cast(str | bytes, completed.stdout)


def exact_revision(repo: Path, ref: str) -> str:
    revision = str(run_git(repo, ["rev-parse", "--verify", f"{ref}^{{commit}}"])).strip()
    if SHA40.fullmatch(revision) is None:
        raise GovernanceError(f"{ref} did not resolve to an exact commit")
    return revision


def tree_entry(repo: Path, revision: str, path: str) -> TreeEntry:
    raw = str(run_git(repo, ["ls-tree", revision, "--", path])).rstrip("\n")
    if not raw or "\t" not in raw:
        raise GovernanceError(f"bundle path is absent at {revision}: {path}")
    metadata, observed_path = raw.split("\t", 1)
    fields = metadata.split()
    if len(fields) != 3 or observed_path != path:
        raise GovernanceError(f"bundle path has ambiguous tree metadata: {path}")
    return TreeEntry(fields[0], fields[1], fields[2], observed_path)


def blob(repo: Path, revision: str, path: str) -> bytes:
    value = run_git(repo, ["show", f"{revision}:{path}"], text=False)
    if not isinstance(value, bytes):
        raise GovernanceError("git blob read returned text unexpectedly")
    return value


def local_python_modules(repo: Path, revision: str, roots: tuple[str, ...]) -> dict[str, str]:
    modules: dict[str, str] = {}
    for root in roots:
        output = str(run_git(repo, ["ls-tree", "-r", "--name-only", revision, "--", root]))
        for line in output.splitlines():
            if not line.endswith(".py"):
                continue
            relative = PurePosixPath(line).relative_to(PurePosixPath(root))
            dotted = ".".join(relative.with_suffix("").parts)
            modules[dotted] = line
            modules.setdefault(dotted.split(".")[0], line)
    return modules


def python_dependencies(path: str, content: bytes, local_modules: dict[str, str]) -> set[str]:
    try:
        root = ast.parse(content.decode("utf-8"), filename=path)
    except (UnicodeDecodeError, SyntaxError) as error:
        raise GovernanceError(f"cannot statically parse bundle Python source: {path}") from error
    dependencies: set[str] = set()
    for node in ast.walk(root):
        if isinstance(node, ast.Call):
            dynamic = (
                isinstance(node.func, ast.Name) and node.func.id == "__import__"
            ) or (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "importlib"
                and node.func.attr == "import_module"
            )
            if dynamic:
                raise GovernanceError(f"dynamic imports are forbidden in bundle source: {path}")
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                raise GovernanceError(f"relative imports are forbidden in bundle source: {path}")
            if node.module:
                names = [node.module]
        for name in names:
            exact = local_modules.get(name) or local_modules.get(name.split(".")[0])
            if exact:
                dependencies.add(exact)
    return dependencies


def resolve_bundle(repo: Path, policy: Policy, main_ref: str) -> dict[str, Any]:
    main_revision = exact_revision(repo, main_ref)
    candidate = str(
        run_git(
            repo,
            ["rev-list", "-1", main_revision, "--", *sorted(policy.paths)],
        )
    ).strip()
    if SHA40.fullmatch(candidate) is None:
        raise GovernanceError("no release commit changes the declared bundle")
    contents: dict[str, bytes] = {}
    files: list[dict[str, Any]] = []
    for path, required_mode in policy.paths.items():
        release_entry = tree_entry(repo, candidate, path)
        main_entry = tree_entry(repo, main_revision, path)
        for location, entry in (("release", release_entry), ("main", main_entry)):
            if entry.object_type != "blob" or entry.mode != required_mode:
                raise GovernanceError(
                    f"{location} bundle path must be a regular {required_mode} blob: {path}"
                )
        if release_entry.oid != main_entry.oid:
            raise GovernanceError(f"bundle bytes at main differ from the resolved release: {path}")
        content = blob(repo, candidate, path)
        contents[path] = content
        files.append(
            {
                "path": path,
                "mode": release_entry.mode,
                "git_blob": release_entry.oid,
                "sha256": sha256(content),
                "size_bytes": len(content),
            }
        )
    workflow_text = contents[policy.entrypoint].decode("utf-8")
    workflow_dependencies = set(WORKFLOW_SCRIPT.findall(workflow_text))
    local_modules = local_python_modules(repo, candidate, policy.python_roots)
    python_deps: set[str] = set()
    for path, content in contents.items():
        if path.endswith(".py"):
            python_deps.update(python_dependencies(path, content, local_modules))
    discovered = {policy.entrypoint, *workflow_dependencies, *python_deps}
    declared = set(policy.paths)
    if discovered != declared:
        missing = sorted(discovered - declared)
        excess = sorted(declared - discovered)
        raise GovernanceError(
            f"bundle manifest is not closed (undeclared={missing}, unreachable={excess})"
        )
    return {
        "default_revision": main_revision,
        "release_revision": candidate,
        "manifest_closed": True,
        "files": files,
    }


def finding(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


def enabled(raw: Any, field: str) -> bool:
    value = raw.get(field) if isinstance(raw, dict) else None
    if not isinstance(value, dict) or not isinstance(value.get("enabled"), bool):
        raise GovernanceError(f"branch protection lacks {field}")
    return bool(value["enabled"])


def inspect_protection(
    client: GitHub, policy: Policy, branch: str
) -> tuple[dict[str, Any] | None, list[dict[str, str]]]:
    repository = policy.repository
    encoded = quote(branch, safe="")
    findings: list[dict[str, str]] = []
    try:
        raw = client.api(f"repos/{repository}/branches/{encoded}/protection")
    except ApiError as error:
        code = "branch_unprotected" if error.status == 404 else "branch_protection_read_failed"
        findings.append(finding(code, f"cannot verify protection for {branch}"))
        return None, findings
    try:
        signatures = client.api(
            f"repos/{repository}/branches/{encoded}/protection/required_signatures"
        )
        signatures_enabled = (
            signatures.get("enabled") if isinstance(signatures, dict) else None
        )
    except ApiError as error:
        if error.status == 404:
            signatures_enabled = False
        else:
            findings.append(
                finding(
                    "branch_signature_protection_read_failed",
                    f"cannot verify required signatures for {branch}",
                )
            )
            return None, findings
    try:
        state = {
            "required_signatures": signatures_enabled,
            "enforce_admins": enabled(raw, "enforce_admins"),
            "required_linear_history": enabled(raw, "required_linear_history"),
            "allow_force_pushes": enabled(raw, "allow_force_pushes"),
            "allow_deletions": enabled(raw, "allow_deletions"),
            "required_status_checks": (
                "absent" if isinstance(raw, dict) and raw.get("required_status_checks") is None
                else "configured"
            ),
            "status_checks_reason": policy.status_checks_reason,
        }
        expected = {
            "required_signatures": True,
            "enforce_admins": True,
            "required_linear_history": True,
            "allow_force_pushes": False,
            "allow_deletions": False,
            "required_status_checks": "absent",
            "status_checks_reason": policy.status_checks_reason,
        }
        state["contract_exact"] = state == expected
        if not state["contract_exact"]:
            findings.append(
                finding(
                    "branch_protection_drift",
                    f"{branch} protection differs from the declared fail-closed contract",
                )
            )
        return state, findings
    except GovernanceError:
        findings.append(
            finding("branch_protection_invalid", f"invalid protection response for {branch}")
        )
    return None, findings


def audit_authority(
    client: GitHub, policy: Policy, resolution: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    repository = policy.repository
    expected_release = resolution["release_revision"]
    main_revision = resolution["default_revision"]
    findings: list[dict[str, str]] = []
    authority: dict[str, Any] = {
        "repository_identity_exact": False,
        "default_revision": main_revision,
        "default_ref_exact": False,
        "release_revision": None,
        "release_ref_exact": False,
        "release_commit_signature_verified": False,
        "release_ancestor_of_default": False,
        "default_protection": None,
        "release_protection": None,
    }
    try:
        metadata = client.api(f"repos/{repository}")
        authority["repository_identity_exact"] = (
            isinstance(metadata, dict)
            and metadata.get("full_name") == repository
            and metadata.get("id") == policy.database_id
            and metadata.get("node_id") == policy.node_id
            and metadata.get("default_branch") == policy.default_branch
            and metadata.get("archived") is False
            and metadata.get("disabled") is False
        )
        if not authority["repository_identity_exact"]:
            findings.append(finding("repository_identity_drift", "repository identity changed"))
    except ApiError:
        findings.append(finding("repository_read_failed", "repository metadata is unavailable"))
    try:
        authority["default_ref_exact"] = (
            read_branch_ref(client, policy, policy.default_branch) == main_revision
        )
        if not authority["default_ref_exact"]:
            findings.append(
                finding("default_ref_drift", "remote main moved from the audited revision")
            )
    except (ApiError, GovernanceError):
        findings.append(finding("default_ref_read_failed", "default branch cannot be verified"))
    try:
        ref = client.api(
            f"repos/{repository}/git/ref/heads/{quote(policy.release_branch, safe='')}"
        )
        obj = ref.get("object") if isinstance(ref, dict) else None
        release_revision = obj.get("sha") if isinstance(obj, dict) else None
        authority["release_revision"] = release_revision
        authority["release_ref_exact"] = (
            isinstance(ref, dict)
            and ref.get("ref") == f"refs/heads/{policy.release_branch}"
            and isinstance(obj, dict)
            and obj.get("type") == "commit"
            and release_revision == expected_release
        )
        if not authority["release_ref_exact"]:
            findings.append(
                finding("release_ref_drift", "release branch does not equal resolved bundle commit")
            )
    except ApiError as error:
        code = "release_ref_missing" if error.status == 404 else "release_ref_read_failed"
        findings.append(finding(code, "release branch cannot be verified"))
    try:
        commit = client.api(f"repos/{repository}/commits/{expected_release}")
        metadata = commit.get("commit") if isinstance(commit, dict) else None
        verification = metadata.get("verification") if isinstance(metadata, dict) else None
        authority["release_commit_signature_verified"] = (
            isinstance(commit, dict)
            and commit.get("sha") == expected_release
            and isinstance(verification, dict)
            and verification.get("verified") is True
            and verification.get("reason") == "valid"
        )
        if not authority["release_commit_signature_verified"]:
            findings.append(
                finding("release_commit_unverified", "release commit signature is not valid")
            )
    except ApiError:
        findings.append(finding("release_commit_read_failed", "release commit is unavailable"))
    try:
        comparison = client.api(
            f"repos/{repository}/compare/{expected_release}...{main_revision}"
        )
        merge_base = comparison.get("merge_base_commit") if isinstance(comparison, dict) else None
        base_commit = comparison.get("base_commit") if isinstance(comparison, dict) else None
        authority["release_ancestor_of_default"] = (
            isinstance(comparison, dict)
            and comparison.get("status") in {"ahead", "identical"}
            and isinstance(merge_base, dict)
            and merge_base.get("sha") == expected_release
            and isinstance(base_commit, dict)
            and base_commit.get("sha") == expected_release
        )
        if not authority["release_ancestor_of_default"]:
            findings.append(
                finding("release_not_ancestor", "release commit is not an ancestor of main")
            )
    except ApiError:
        findings.append(finding("release_ancestry_read_failed", "release ancestry is unavailable"))
    for branch, field in (
        (policy.default_branch, "default_protection"),
        (policy.release_branch, "release_protection"),
    ):
        protection, protection_findings = inspect_protection(client, policy, branch)
        authority[field] = protection
        findings.extend(protection_findings)
    return authority, findings


def build_report(
    policy: Policy,
    resolution: dict[str, Any],
    authority: dict[str, Any],
    findings: list[dict[str, str]],
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "execution": {
            "executed": True,
            "status": "completed",
            "completed_at": datetime.now(UTC).isoformat(),
        },
        "policy": {"path": policy.path.name, "sha256": policy.digest},
        "contract": {
            "repository": policy.repository,
            "default_branch": policy.default_branch,
            "release_branch": policy.release_branch,
            "status_checks": {
                "mode": policy.status_checks_mode,
                "reason": policy.status_checks_reason,
                "contexts": [],
            },
        },
        "resolution": resolution,
        "authority": authority,
        "findings": findings,
        "result": {
            "status": "pass" if not findings else "fail",
            "finding_count": len(findings),
        },
    }


def build_receipt(policy: Policy, report_path: Path, report: dict[str, Any]) -> dict[str, Any]:
    report_bytes = report_path.read_bytes()
    return {
        "schema_version": SCHEMA_VERSION,
        "executed": True,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "inputs": {
            "repository": policy.repository,
            "policy_sha256": policy.digest,
            "default_revision": report["resolution"]["default_revision"],
            "release_revision": report["resolution"]["release_revision"],
            "status_checks_mode": policy.status_checks_mode,
        },
        "result": report["result"],
        "artifact": {
            "path": report_path.name,
            "sha256": sha256(report_bytes),
            "size_bytes": len(report_bytes),
        },
    }


def evidence_has_forbidden_key(value: Any) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if any(forbidden in normalized for forbidden in FORBIDDEN_EVIDENCE_KEYS):
                return True
            if evidence_has_forbidden_key(nested):
                return True
    elif isinstance(value, list):
        return any(evidence_has_forbidden_key(item) for item in value)
    return False


def validate_evidence(
    policy: Policy, report_path: Path, receipt_path: Path
) -> list[str]:
    errors: list[str] = []
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ["report or receipt is missing or invalid JSON"]
    if evidence_has_forbidden_key(report) or evidence_has_forbidden_key(receipt):
        errors.append("evidence contains a forbidden secret-like key")
    if report.get("schema_version") != SCHEMA_VERSION:
        errors.append("report schema_version is invalid")
    execution = report.get("execution")
    if not isinstance(execution, dict) or execution.get("executed") is not True or execution.get("status") != "completed":
        errors.append("report does not prove completed execution")
    if report.get("policy") != {"path": policy.path.name, "sha256": policy.digest}:
        errors.append("report policy binding does not match")
    contract = report.get("contract")
    if not isinstance(contract, dict) or contract.get("repository") != policy.repository:
        errors.append("report repository contract does not match")
    else:
        checks = contract.get("status_checks")
        if checks != {
            "mode": "intentionally_absent",
            "reason": policy.status_checks_reason,
            "contexts": [],
        }:
            errors.append("report does not truthfully bind absent status checks")
    resolution = report.get("resolution")
    if not isinstance(resolution, dict) or resolution.get("manifest_closed") is not True:
        errors.append("report does not prove a manifest-closed bundle")
    authority = report.get("authority")
    if not isinstance(authority, dict):
        errors.append("report authority is missing")
    else:
        for field in (
            "repository_identity_exact",
            "default_ref_exact",
            "release_ref_exact",
            "release_commit_signature_verified",
            "release_ancestor_of_default",
        ):
            if authority.get(field) is not True:
                errors.append(f"report authority does not prove {field}")
        for field in ("default_protection", "release_protection"):
            value = authority.get(field)
            if not isinstance(value, dict) or value.get("contract_exact") is not True:
                errors.append(f"report authority does not prove {field}")
    if report.get("findings") != []:
        errors.append("report contains findings")
    if report.get("result") != {"status": "pass", "finding_count": 0}:
        errors.append("report result is not pass")
    report_bytes = report_path.read_bytes()
    artifact = receipt.get("artifact")
    if not isinstance(artifact, dict):
        errors.append("receipt artifact binding is missing")
    else:
        if artifact.get("path") != report_path.name:
            errors.append("receipt artifact path does not match")
        if artifact.get("sha256") != sha256(report_bytes):
            errors.append("receipt artifact digest does not match")
        if artifact.get("size_bytes") != len(report_bytes):
            errors.append("receipt artifact size does not match")
    if receipt.get("executed") is not True or receipt.get("result") != report.get("result"):
        errors.append("receipt does not bind successful execution")
    inputs = receipt.get("inputs")
    if not isinstance(inputs, dict) or inputs.get("policy_sha256") != policy.digest:
        errors.append("receipt policy binding does not match")
    elif isinstance(resolution, dict) and (
        inputs.get("default_revision") != resolution.get("default_revision")
        or inputs.get("release_revision") != resolution.get("release_revision")
        or inputs.get("status_checks_mode") != policy.status_checks_mode
    ):
        errors.append("receipt resolution binding does not match")
    return errors


def protection_payload() -> dict[str, Any]:
    return {
        "required_status_checks": None,
        "enforce_admins": True,
        "required_pull_request_reviews": None,
        "restrictions": None,
        "required_linear_history": True,
        "allow_force_pushes": False,
        "allow_deletions": False,
        "block_creations": False,
        "required_conversation_resolution": False,
        "lock_branch": False,
        "allow_fork_syncing": False,
    }


def read_branch_ref(
    client: GitHub, policy: Policy, branch: str, *, missing_ok: bool = False
) -> str | None:
    endpoint = f"repos/{policy.repository}/git/ref/heads/{quote(branch, safe='')}"
    try:
        raw = client.api(endpoint)
    except ApiError as error:
        if error.status == 404 and missing_ok:
            return None
        raise
    obj = raw.get("object") if isinstance(raw, dict) else None
    revision = obj.get("sha") if isinstance(obj, dict) else None
    if (
        not isinstance(raw, dict)
        or raw.get("ref") != f"refs/heads/{branch}"
        or not isinstance(obj, dict)
        or obj.get("type") != "commit"
        or not isinstance(revision, str)
        or SHA40.fullmatch(revision) is None
    ):
        raise GovernanceError("release ref response is invalid")
    return revision


def require_signed_ancestor(
    client: GitHub, policy: Policy, candidate: str, main_revision: str
) -> None:
    commit = client.api(f"repos/{policy.repository}/commits/{candidate}")
    metadata = commit.get("commit") if isinstance(commit, dict) else None
    verification = metadata.get("verification") if isinstance(metadata, dict) else None
    if (
        not isinstance(commit, dict)
        or commit.get("sha") != candidate
        or not isinstance(verification, dict)
        or verification.get("verified") is not True
        or verification.get("reason") != "valid"
    ):
        raise GovernanceError("release candidate does not have a valid signature")
    comparison = client.api(
        f"repos/{policy.repository}/compare/{candidate}...{main_revision}"
    )
    merge_base = comparison.get("merge_base_commit") if isinstance(comparison, dict) else None
    if (
        not isinstance(comparison, dict)
        or comparison.get("status") not in {"ahead", "identical"}
        or not isinstance(merge_base, dict)
        or merge_base.get("sha") != candidate
    ):
        raise GovernanceError("release candidate is not an ancestor of main")


def make_release_plan(
    client: GitHub, repo: Path, policy: Policy, main_ref: str
) -> dict[str, Any]:
    resolution = resolve_bundle(repo, policy, main_ref)
    candidate = resolution["release_revision"]
    main_revision = resolution["default_revision"]
    require_signed_ancestor(client, policy, candidate, main_revision)
    remote_main = read_branch_ref(client, policy, policy.default_branch)
    if remote_main != main_revision:
        raise GovernanceError("remote main moved from the locally resolved revision")
    observed_release = read_branch_ref(
        client, policy, policy.release_branch, missing_ok=True
    )
    if observed_release and observed_release != candidate:
        comparison = client.api(
            f"repos/{policy.repository}/compare/{observed_release}...{candidate}"
        )
        merge_base = comparison.get("merge_base_commit") if isinstance(comparison, dict) else None
        if (
            not isinstance(comparison, dict)
            or comparison.get("status") not in {"ahead", "identical"}
            or not isinstance(merge_base, dict)
            or merge_base.get("sha") != observed_release
        ):
            raise GovernanceError("release update would not be a fast-forward")
    operations: list[dict[str, Any]] = []
    default_protection, default_findings = inspect_protection(
        client, policy, policy.default_branch
    )
    if default_protection is None:
        raise GovernanceError("default branch protection cannot be read safely")
    if default_findings:
        operations.extend(
            [
                {"operation": "protect_branch", "branch": policy.default_branch},
                {"operation": "require_signatures", "branch": policy.default_branch},
            ]
        )
    if observed_release is None:
        operations.append(
            {
                "operation": "create_release_ref",
                "branch": policy.release_branch,
                "revision": candidate,
            }
        )
    else:
        release_protection, findings = inspect_protection(
            client, policy, policy.release_branch
        )
        if release_protection is None:
            raise GovernanceError("release branch protection cannot be read safely")
        if observed_release != candidate and (
            findings or release_protection.get("contract_exact") is not True
        ):
            raise GovernanceError("existing release branch must be protected before fast-forward")
        if observed_release != candidate:
            operations.append(
                {
                    "operation": "fast_forward_release_ref",
                    "branch": policy.release_branch,
                    "from": observed_release,
                    "to": candidate,
                    "force": False,
                }
            )
        elif findings:
            operations.extend(
                [
                    {"operation": "protect_branch", "branch": policy.release_branch},
                    {"operation": "require_signatures", "branch": policy.release_branch},
                ]
            )
    if observed_release is None:
        operations.extend(
            [
                {"operation": "protect_branch", "branch": policy.release_branch},
                {"operation": "require_signatures", "branch": policy.release_branch},
            ]
        )
    operations.append({"operation": "audit_postcondition"})
    unsigned = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "repository": policy.repository,
        "policy_sha256": policy.digest,
        "default_revision": main_revision,
        "release_revision": candidate,
        "observed_release_revision": observed_release,
        "operations": operations,
    }
    return {**unsigned, "plan_digest": sha256(canonical_json(unsigned))}


def validate_plan(plan: dict[str, Any], policy: Policy, approved: str) -> None:
    if not isinstance(plan, dict) or plan.get("schema_version") != SCHEMA_VERSION:
        raise GovernanceError("release plan schema is invalid")
    digest = plan.get("plan_digest")
    if not isinstance(digest, str) or digest != approved:
        raise GovernanceError("approved digest does not match release plan")
    unsigned = {key: value for key, value in plan.items() if key != "plan_digest"}
    if sha256(canonical_json(unsigned)) != digest:
        raise GovernanceError("release plan digest is invalid")
    if plan.get("policy_sha256") != policy.digest or plan.get("repository") != policy.repository:
        raise GovernanceError("release plan policy binding changed")


def apply_release_plan(
    client: GitHub,
    repo: Path,
    policy: Policy,
    plan: dict[str, Any],
    receipt_path: Path,
) -> int:
    completed: list[dict[str, Any]] = []
    status = "fail"
    error_code: str | None = None
    try:
        resolution = resolve_bundle(repo, policy, plan["default_revision"])
        if (
            resolution["default_revision"] != plan["default_revision"]
            or resolution["release_revision"] != plan["release_revision"]
        ):
            raise GovernanceError("release plan inputs changed before apply")
        expected_plan = make_release_plan(
            client, repo, policy, plan["default_revision"]
        )
        if expected_plan != plan:
            raise GovernanceError("release plan no longer matches exact live operations")
        remote_main = read_branch_ref(client, policy, policy.default_branch)
        if remote_main != plan["default_revision"]:
            raise GovernanceError("remote main moved after planning")
        observed = read_branch_ref(
            client, policy, policy.release_branch, missing_ok=True
        )
        if observed != plan.get("observed_release_revision"):
            raise GovernanceError("release ref moved after planning")
        require_signed_ancestor(
            client,
            policy,
            plan["release_revision"],
            plan["default_revision"],
        )
        for operation in plan["operations"]:
            name = operation["operation"]
            branch = operation.get("branch")
            encoded = quote(branch, safe="") if isinstance(branch, str) else ""
            if name == "protect_branch":
                client.api(
                    f"repos/{policy.repository}/branches/{encoded}/protection",
                    method="PUT",
                    payload=protection_payload(),
                )
            elif name == "require_signatures":
                client.api(
                    f"repos/{policy.repository}/branches/{encoded}/protection/required_signatures",
                    method="POST",
                )
            elif name == "create_release_ref":
                client.api(
                    f"repos/{policy.repository}/git/refs",
                    method="POST",
                    payload={
                        "ref": f"refs/heads/{policy.release_branch}",
                        "sha": plan["release_revision"],
                    },
                )
            elif name == "fast_forward_release_ref":
                client.api(
                    f"repos/{policy.repository}/git/refs/heads/{quote(policy.release_branch, safe='')}",
                    method="PATCH",
                    payload={"sha": plan["release_revision"], "force": False},
                )
            elif name == "audit_postcondition":
                authority, findings = audit_authority(client, policy, resolution)
                if findings or authority.get("release_ref_exact") is not True:
                    raise GovernanceError("release protection postcondition failed")
            else:
                raise GovernanceError(f"unsupported release operation: {name}")
            completed.append({"operation": name, "status": "completed"})
        status = "pass"
    except (GovernanceError, ApiError) as error:
        error_code = type(error).__name__
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "executed": True,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "plan_digest": plan.get("plan_digest"),
        "completed_operations": completed,
        "result": {"status": status, "error_code": error_code},
    }
    write_atomic(receipt_path, receipt)
    return 0 if status == "pass" else 1


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument(
        "--policy",
        type=Path,
        default=Path(".github/security-contract-governance.json"),
    )
    root.add_argument("--repo", type=Path, default=Path("."))
    commands = root.add_subparsers(dest="command", required=True)
    audit = commands.add_parser("audit", help="Run the read-only live authority audit.")
    audit.add_argument("--main-ref", default="origin/main")
    audit.add_argument("--report", type=Path, required=True)
    audit.add_argument("--receipt", type=Path, required=True)
    validate = commands.add_parser("validate", help="Validate retained audit evidence.")
    validate.add_argument("--report", type=Path, required=True)
    validate.add_argument("--receipt", type=Path, required=True)
    plan = commands.add_parser("plan-release", help="Build an immutable release plan.")
    plan.add_argument("--main-ref", default="origin/main")
    plan.add_argument("--out", type=Path, required=True)
    apply = commands.add_parser("apply-release", help="Apply an approved release plan.")
    apply.add_argument("--plan", type=Path, required=True)
    apply.add_argument("--approve", required=True)
    apply.add_argument("--receipt", type=Path, required=True)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        policy = load_policy(args.policy)
        repo = args.repo.resolve()
        client = GhClient()
        if args.command == "audit":
            resolution = resolve_bundle(repo, policy, args.main_ref)
            authority, findings = audit_authority(client, policy, resolution)
            report = build_report(policy, resolution, authority, findings)
            write_atomic(args.report, report)
            write_atomic(args.receipt, build_receipt(policy, args.report, report))
            return 0 if not findings else 1
        if args.command == "validate":
            errors = validate_evidence(policy, args.report, args.receipt)
            for error in errors:
                print(f"ERROR: {error}", file=sys.stderr)
            return 1 if errors else 0
        if args.command == "plan-release":
            plan = make_release_plan(client, repo, policy, args.main_ref)
            write_atomic(args.out, plan)
            print(plan["plan_digest"])
            return 0
        if args.command == "apply-release":
            plan = json.loads(args.plan.read_text(encoding="utf-8"))
            validate_plan(plan, policy, args.approve)
            return apply_release_plan(client, repo, policy, plan, args.receipt)
    except (GovernanceError, ApiError, OSError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
