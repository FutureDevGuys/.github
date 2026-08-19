#!/usr/bin/env python3
"""Hold dependency PRs that touch centrally declared stateful or database paths."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def evaluate(repository: str, policy: Any, changed_files: Any) -> dict[str, Any]:
    if not isinstance(policy, dict) or policy.get("schema_version") != 1:
        raise ValueError("risk-path policy must be a schema_version 1 object")
    repositories = policy.get("repositories")
    if not isinstance(repositories, dict):
        raise ValueError("risk-path policy repositories must be an object")

    for name, rule in repositories.items():
        if not isinstance(name, str) or not name or not isinstance(rule, dict):
            raise ValueError("risk-path repository rules must be named objects")
        prefixes = rule.get("path_prefixes")
        if not isinstance(prefixes, list) or not prefixes:
            raise ValueError(f"{name} path_prefixes must be a nonempty list")
        if any(
            not isinstance(prefix, str)
            or not prefix
            or prefix.startswith("/")
            or ".." in Path(prefix).parts
            or not prefix.endswith("/")
            for prefix in prefixes
        ):
            raise ValueError(f"{name} has an unsafe or malformed path prefix")
        if len(prefixes) != len(set(prefixes)):
            raise ValueError(f"{name} has duplicate path prefixes")

    if not isinstance(changed_files, list):
        raise ValueError("changed-files evidence must be an array")
    filenames: list[str] = []
    for entry in changed_files:
        if not isinstance(entry, dict):
            raise ValueError("changed-files entries must be objects")
        filename = entry.get("filename")
        if (
            not isinstance(filename, str)
            or not filename
            or filename.startswith("/")
            or ".." in Path(filename).parts
        ):
            raise ValueError("changed-files evidence contains an unsafe filename")
        filenames.append(filename)

    rule = repositories.get(repository)
    if rule is None:
        return {
            "schema_version": 1,
            "repository": repository,
            "eligible": True,
            "matched_paths": [],
        }

    prefixes = rule["path_prefixes"]
    matched = sorted(
        filename
        for filename in filenames
        if any(filename.startswith(prefix) for prefix in prefixes)
    )
    return {
        "schema_version": 1,
        "repository": repository,
        "eligible": not matched,
        "matched_paths": matched,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--changed-files", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        result = evaluate(
            args.repository,
            _load_json(args.policy),
            _load_json(args.changed_files),
        )
        args.output.write_text(
            json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    return 0 if result["eligible"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
