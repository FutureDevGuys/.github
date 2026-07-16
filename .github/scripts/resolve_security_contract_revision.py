#!/usr/bin/env python3
"""Resolve and revalidate the immutable reusable-security contract revision."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Sequence

SCHEMA_VERSION = 2
MANIFEST_SCHEMA_VERSION = 1
DEPENDENCY_MANIFEST_PATH = ".github/security-contract-dependencies.v1.json"
DEPENDENCY_MANIFEST_OWNER = "FutureDevGuys/.github/security-scan"
SECURITY_CONTRACT_RELEASE_REF = "refs/heads/security-contract-v1"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
REGULAR_GIT_MODES = {"100644", "100755"}
WORKFLOW_RUNTIME_PATH_RE = re.compile(
    r"\.security-contract/(?P<path>\.github/[A-Za-z0-9._/-]+)"
)
LOCAL_SCRIPT_PATH_RE = re.compile(r"(?P<path>\.github/scripts/[A-Za-z0-9._/-]+)")
DYNAMIC_IMPORT_CALLS = {
    "__import__",
    "compile",
    "eval",
    "exec",
    "import_module",
    "importlib.import_module",
    "run_module",
    "run_path",
    "runpy.run_module",
    "runpy.run_path",
}


class RevisionError(RuntimeError):
    """The checked-out repository cannot prove one exact contract revision."""


def _git(repo: Path, arguments: Sequence[str], *, binary: bool = False) -> str | bytes:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        check=False,
        capture_output=True,
        text=not binary,
    )
    if result.returncode != 0:
        stderr = (
            result.stderr.decode("utf-8", "replace") if binary else result.stderr
        ).strip()
        raise RevisionError(f"git {' '.join(arguments)} failed: {stderr}")
    return result.stdout


def _exact_sha(value: str, label: str) -> str:
    value = value.strip()
    if SHA_RE.fullmatch(value) is None:
        raise RevisionError(
            f"{label} is not an exact lowercase 40-character commit SHA"
        )
    return value


def _safe_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or SAFE_PATH_RE.fullmatch(value) is None:
        raise RevisionError(f"{label} is not a safe repository-relative path")
    parsed = PurePosixPath(value)
    if (
        parsed.is_absolute()
        or value != parsed.as_posix()
        or not parsed.parts
        or ".." in parsed.parts
        or parsed.parts[0] == ".git"
    ):
        raise RevisionError(f"{label} is not a canonical repository-relative path")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RevisionError(f"JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def _decode_json_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RevisionError(f"{label} is not strict JSON: {error}") from error
    if not isinstance(value, dict):
        raise RevisionError(f"{label} must be a JSON object")
    return value


def _tree_entry(repo: Path, revision: str, path: str) -> tuple[str, str]:
    raw = _git(
        repo,
        ["ls-tree", "-z", revision, "--", path],
        binary=True,
    )
    assert isinstance(raw, bytes)
    records = [record for record in raw.split(b"\0") if record]
    if len(records) != 1 or b"\t" not in records[0]:
        raise RevisionError(f"{path} is missing or ambiguous at {revision}")
    metadata, raw_path = records[0].split(b"\t", 1)
    try:
        mode, object_type, object_id = metadata.decode("ascii").split(" ")
        decoded_path = raw_path.decode("utf-8")
    except (UnicodeDecodeError, ValueError) as error:
        raise RevisionError(f"{path} has malformed Git tree metadata") from error
    if decoded_path != path or object_type != "blob" or not SHA_RE.fullmatch(object_id):
        raise RevisionError(f"{path} is not one exact Git blob at {revision}")
    return mode, object_id


def _blob(repo: Path, revision: str, path: str) -> bytes:
    raw = _git(repo, ["show", f"{revision}:{path}"], binary=True)
    assert isinstance(raw, bytes)
    return raw


def _worktree_blob(repo: Path, path: str, expected_mode: str) -> bytes:
    candidate = repo
    parts = PurePosixPath(path).parts
    for index, part in enumerate(parts):
        candidate = candidate / part
        try:
            metadata = candidate.lstat()
        except OSError as error:
            raise RevisionError(
                f"worktree dependency {path} cannot be read: {error}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode):
            raise RevisionError(f"worktree dependency {path} traverses a symbolic link")
        if index < len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise RevisionError(
                f"worktree dependency {path} has a non-directory parent"
            )
    if not stat.S_ISREG(metadata.st_mode):
        raise RevisionError(f"worktree dependency {path} is not a regular file")
    actual_mode = "100755" if metadata.st_mode & 0o111 else "100644"
    if actual_mode != expected_mode:
        raise RevisionError(
            f"worktree dependency {path} mode {actual_mode} differs from {expected_mode}"
        )
    return candidate.read_bytes()


def _manifest(
    repo: Path, head: str
) -> tuple[dict[str, Any], bytes, list[dict[str, str]]]:
    mode, _ = _tree_entry(repo, head, DEPENDENCY_MANIFEST_PATH)
    if mode != "100644":
        raise RevisionError(
            "security dependency manifest must be one regular 100644 blob"
        )
    raw = _blob(repo, head, DEPENDENCY_MANIFEST_PATH)
    if _worktree_blob(repo, DEPENDENCY_MANIFEST_PATH, mode) != raw:
        raise RevisionError(
            "security dependency manifest worktree bytes differ from HEAD"
        )
    value = _decode_json_object(raw, "security dependency manifest")
    if set(value) != {
        "schema_version",
        "authority",
        "owner",
        "entrypoint",
        "dependencies",
        "release_ref",
    }:
        raise RevisionError("security dependency manifest fields are not exact")
    if (
        value.get("schema_version") != MANIFEST_SCHEMA_VERSION
        or value.get("authority") != "canonical"
        or value.get("owner") != DEPENDENCY_MANIFEST_OWNER
        or value.get("release_ref") != SECURITY_CONTRACT_RELEASE_REF
    ):
        raise RevisionError("security dependency manifest authority is invalid")
    entrypoint = _safe_path(value.get("entrypoint"), "manifest entrypoint")
    dependencies = value.get("dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        raise RevisionError(
            "security dependency manifest dependencies must be nonempty"
        )
    normalized: list[dict[str, str]] = []
    for index, row in enumerate(dependencies):
        if not isinstance(row, dict) or set(row) != {"path", "git_mode", "kind"}:
            raise RevisionError(f"manifest dependency {index} fields are not exact")
        path = _safe_path(row.get("path"), f"manifest dependency {index} path")
        git_mode = row.get("git_mode")
        kind = row.get("kind")
        if git_mode not in REGULAR_GIT_MODES:
            raise RevisionError(
                f"manifest dependency {path} must declare a regular Git mode"
            )
        if kind not in {"python", "workflow"}:
            raise RevisionError(f"manifest dependency {path} kind is unsupported")
        if kind == "python" and not path.endswith(".py"):
            raise RevisionError(f"manifest Python dependency {path} must end in .py")
        normalized.append({"path": path, "git_mode": git_mode, "kind": kind})
    paths = [row["path"] for row in normalized]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise RevisionError(
            "security dependency manifest paths must be sorted and unique"
        )
    workflow_rows = [row for row in normalized if row["kind"] == "workflow"]
    if workflow_rows != [
        {"path": entrypoint, "git_mode": "100644", "kind": "workflow"}
    ]:
        raise RevisionError(
            "security dependency manifest must declare one 100644 entrypoint"
        )
    return value, raw, normalized


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _repository_python_modules(repo: Path, head: str) -> dict[str, set[str]]:
    raw = _git(
        repo,
        ["ls-tree", "-r", "-z", "--name-only", head, "--", ".github/scripts"],
        binary=True,
    )
    assert isinstance(raw, bytes)
    result: dict[str, set[str]] = {}
    for encoded in raw.split(b"\0"):
        if not encoded:
            continue
        try:
            path = encoded.decode("utf-8")
        except UnicodeDecodeError as error:
            raise RevisionError("repository-local Python path is not UTF-8") from error
        if not path.startswith(".github/scripts/") or not path.endswith(".py"):
            continue
        relative = path.removeprefix(".github/scripts/")
        top_level = relative.split("/", 1)[0].removesuffix(".py")
        result.setdefault(top_level, set()).add(path)
    return result


def _validate_runtime_dependency_closure(
    repo: Path,
    head: str,
    dependencies: list[dict[str, str]],
    blobs: dict[str, bytes],
) -> list[dict[str, str]]:
    entrypoint = next(row["path"] for row in dependencies if row["kind"] == "workflow")
    try:
        workflow = blobs[entrypoint].decode("utf-8")
    except UnicodeDecodeError as error:
        raise RevisionError("security workflow is not UTF-8") from error
    direct_paths = {
        match.group("path") for match in WORKFLOW_RUNTIME_PATH_RE.finditer(workflow)
    }
    declared_python = {row["path"] for row in dependencies if row["kind"] == "python"}
    if direct_paths - declared_python:
        raise RevisionError(
            "security workflow references untracked local dependencies: "
            + ", ".join(sorted(direct_paths - declared_python))
        )

    local_modules = _repository_python_modules(repo, head)
    declared_by_module = {PurePosixPath(path).stem: path for path in declared_python}
    edges: dict[str, set[str]] = {entrypoint: set(direct_paths)}
    for path in sorted(declared_python):
        try:
            source = blobs[path].decode("utf-8")
            tree = ast.parse(source, filename=path)
        except (UnicodeDecodeError, SyntaxError) as error:
            raise RevisionError(
                f"protected Python dependency {path} is invalid: {error}"
            ) from error
        edges[path] = set()
        for node in ast.walk(tree):
            imported: list[str] = []
            if isinstance(node, ast.Import):
                imported = [alias.name.split(".", 1)[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported = [node.module.split(".", 1)[0]]
            for module in imported:
                if module not in local_modules:
                    continue
                candidates = local_modules[module]
                target = declared_by_module.get(module)
                if target is None or candidates != {target}:
                    raise RevisionError(
                        f"protected Python dependency {path} imports untracked or ambiguous local module {module}"
                    )
                edges[path].add(target)
            if isinstance(node, ast.Call):
                name = _call_name(node.func)
                if name in DYNAMIC_IMPORT_CALLS or name.startswith("sys.path."):
                    raise RevisionError(
                        f"protected Python dependency {path} uses non-closed runtime edge {name}"
                    )
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                for match in LOCAL_SCRIPT_PATH_RE.finditer(node.value):
                    referenced = match.group("path")
                    if referenced not in declared_python:
                        raise RevisionError(
                            f"protected Python dependency {path} names untracked local script {referenced}"
                        )
                    edges[path].add(referenced)

    reachable: set[str] = set()
    pending = list(edges[entrypoint])
    while pending:
        path = pending.pop()
        if path in reachable:
            continue
        reachable.add(path)
        pending.extend(edges.get(path, set()))
    if reachable != declared_python:
        missing = sorted(declared_python - reachable)
        raise RevisionError(
            "security dependency manifest contains unreachable local dependencies: "
            + ", ".join(missing)
        )
    return [
        {"source": source, "target": target}
        for source in sorted(edges)
        for target in sorted(edges[source])
    ]


def resolve_revision(repo: Path) -> dict[str, Any]:
    repo = repo.resolve()
    if str(_git(repo, ["rev-parse", "--is-inside-work-tree"])).strip() != "true":
        raise RevisionError("repository is not a Git work tree")
    top_level = Path(
        str(_git(repo, ["rev-parse", "--show-toplevel"])).strip()
    ).resolve()
    if top_level != repo:
        raise RevisionError("--repo must name the Git work-tree root")
    if str(_git(repo, ["rev-parse", "--is-shallow-repository"])).strip() != "false":
        raise RevisionError(
            "full Git history is required to resolve the contract revision"
        )

    head = _exact_sha(str(_git(repo, ["rev-parse", "HEAD"])), "HEAD")
    manifest, manifest_raw, dependencies = _manifest(repo, head)
    protected_paths = [row["path"] for row in dependencies]
    revision = _exact_sha(
        str(
            _git(
                repo,
                ["log", "-1", "--format=%H", "--", *protected_paths],
            )
        ),
        "security contract revision",
    )
    _git(repo, ["merge-base", "--is-ancestor", revision, head])

    files: list[dict[str, str]] = []
    head_blobs: dict[str, bytes] = {}
    for row in dependencies:
        path = row["path"]
        expected_mode = row["git_mode"]
        head_mode, _ = _tree_entry(repo, head, path)
        revision_mode, _ = _tree_entry(repo, revision, path)
        if head_mode != expected_mode or revision_mode != expected_mode:
            raise RevisionError(
                f"protected dependency {path} Git mode differs from manifest"
            )
        raw = _blob(repo, revision, path)
        current = _blob(repo, head, path)
        if raw != current:
            raise RevisionError(
                f"protected dependency {path} differs after the resolved contract revision"
            )
        if _worktree_blob(repo, path, expected_mode) != current:
            raise RevisionError(
                f"protected dependency {path} worktree bytes differ from HEAD"
            )
        head_blobs[path] = current
        files.append(
            {
                "git_mode": expected_mode,
                "kind": row["kind"],
                "path": path,
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )

    edges = _validate_runtime_dependency_closure(repo, head, dependencies, head_blobs)
    manifest_binding = {
        "git_mode": "100644",
        "path": DEPENDENCY_MANIFEST_PATH,
        "schema_version": manifest["schema_version"],
        "sha256": hashlib.sha256(manifest_raw).hexdigest(),
    }
    bundle_raw = json.dumps(
        {
            "dependency_manifest": manifest_binding,
            "protected_files": files,
            "runtime_dependency_edges": edges,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return {
        "schema_version": SCHEMA_VERSION,
        "authority": "generated",
        "head_revision": head,
        "security_contract_revision": revision,
        "release_ref": manifest["release_ref"],
        "derivation": "latest-commit-changing-manifest-declared-runtime-dependency-set",
        "dependency_manifest": manifest_binding,
        "protected_files": files,
        "runtime_dependency_edges": edges,
        "authority_bundle_digest": hashlib.sha256(bundle_raw).hexdigest(),
    }


def validate_freshness(
    initial: dict[str, Any],
    final: dict[str, Any],
    current_default_head: str,
) -> None:
    current_default_head = _exact_sha(
        current_default_head, "current default-branch HEAD"
    )
    required_fields = {
        "schema_version",
        "authority",
        "head_revision",
        "security_contract_revision",
        "release_ref",
        "derivation",
        "dependency_manifest",
        "protected_files",
        "runtime_dependency_edges",
        "authority_bundle_digest",
    }
    for label, receipt in (("initial", initial), ("final", final)):
        if set(receipt) != required_fields:
            raise RevisionError(
                f"{label} security authority receipt fields are not exact"
            )
        if (
            receipt.get("schema_version") != SCHEMA_VERSION
            or receipt.get("authority") != "generated"
        ):
            raise RevisionError(f"{label} security authority receipt is not trusted")
        if not SHA_RE.fullmatch(str(receipt.get("head_revision", ""))):
            raise RevisionError(f"{label} security authority head is malformed")
        if not SHA_RE.fullmatch(str(receipt.get("security_contract_revision", ""))):
            raise RevisionError(f"{label} security contract revision is malformed")
        if receipt.get("release_ref") != SECURITY_CONTRACT_RELEASE_REF:
            raise RevisionError(f"{label} security contract release ref is invalid")
        if not SHA256_RE.fullmatch(str(receipt.get("authority_bundle_digest", ""))):
            raise RevisionError(
                f"{label} security authority bundle digest is malformed"
            )
    if initial["head_revision"] != current_default_head:
        raise RevisionError(
            "organization default branch advanced after automerge authority was loaded"
        )
    if final != initial:
        raise RevisionError(
            "organization security authority bundle changed during the sweep"
        )


def validate_release_ref(receipt: dict[str, Any], release_ref_target: str) -> None:
    release_ref_target = _exact_sha(
        release_ref_target,
        "security contract release-ref target",
    )
    if receipt.get("release_ref") != SECURITY_CONTRACT_RELEASE_REF:
        raise RevisionError("security contract receipt release ref is invalid")
    if receipt.get("security_contract_revision") != release_ref_target:
        raise RevisionError(
            "security contract release ref does not target the latest protected-path revision"
        )


def _read_receipt(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise RevisionError(
            f"cannot read initial authority receipt: {error}"
        ) from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > 1024 * 1024
    ):
        raise RevisionError(
            "initial authority receipt must be one bounded regular file"
        )
    return _decode_json_object(path.read_bytes(), "initial authority receipt")


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
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--initial-receipt", type=Path)
    parser.add_argument("--current-default-head")
    parser.add_argument("--release-ref-target")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if (args.initial_receipt is None) != (args.current_default_head is None):
            raise RevisionError(
                "--initial-receipt and --current-default-head must be supplied together"
            )
        receipt = resolve_revision(args.repo)
        if args.release_ref_target is not None:
            validate_release_ref(receipt, args.release_ref_target)
        write_atomic(args.output, receipt)
        if args.initial_receipt is not None:
            validate_freshness(
                _read_receipt(args.initial_receipt),
                receipt,
                args.current_default_head,
            )
    except (OSError, RevisionError) as error:
        raise SystemExit(str(error)) from error
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
