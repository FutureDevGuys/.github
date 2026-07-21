#!/usr/bin/env python3
"""Discover and validate the one allowed repository-level Renovate config."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from security_scan_adoption_contract import canonical_findings, digest


CANONICAL_RENOVATE_CONFIG = "renovate.json"
# Renovate's documented repository-config search order. The self-hosted runtime
# additionally pins configFileNames to the canonical path; finding any alternate
# remains a policy failure so the runtime and repository cannot silently diverge.
ALTERNATE_RENOVATE_CONFIGS = (
    "renovate.jsonc",
    "renovate.json5",
    ".github/renovate.json",
    ".github/renovate.jsonc",
    ".github/renovate.json5",
    ".gitlab/renovate.json",
    ".gitlab/renovate.jsonc",
    ".gitlab/renovate.json5",
    ".renovaterc",
    ".renovaterc.json",
    ".renovaterc.jsonc",
    ".renovaterc.json5",
)
PACKAGE_JSON_CONFIG = "package.json"
RENOVATE_CONFIG_PATHS = (
    CANONICAL_RENOVATE_CONFIG,
    *ALTERNATE_RENOVATE_CONFIGS,
    PACKAGE_JSON_CONFIG,
)

ConfigReader = Callable[[str], tuple[str | None, str | None]]


def inspect_config_sources(
    read_file: ConfigReader,
) -> tuple[list[dict[str, Any]], str | None, list[str]]:
    """Inspect every config candidate through a revision-bound reader."""

    sources: list[dict[str, Any]] = []
    findings: list[str] = []
    canonical_text: str | None = None
    for path in RENOVATE_CONFIG_PATHS:
        content, error = read_file(path)
        if error is not None:
            sources.append({"path": path, "state": "unknown", "sha256": None})
            findings.append(
                f"Renovate config source inspection failed for {path}: {error}"
            )
            continue
        if content is None:
            sources.append({"path": path, "state": "absent", "sha256": None})
            continue
        content_digest = digest(content.encode("utf-8"))
        if path == CANONICAL_RENOVATE_CONFIG:
            canonical_text = content
            sources.append(
                {"path": path, "state": "present", "sha256": content_digest}
            )
            continue
        if path == PACKAGE_JSON_CONFIG:
            try:
                package = json.loads(content)
            except json.JSONDecodeError:
                sources.append(
                    {"path": path, "state": "unknown", "sha256": content_digest}
                )
                findings.append(
                    "cannot determine Renovate config presence in package.json: invalid JSON"
                )
                continue
            if not isinstance(package, dict):
                sources.append(
                    {"path": path, "state": "unknown", "sha256": content_digest}
                )
                findings.append(
                    "cannot determine Renovate config presence in package.json: root is not an object"
                )
                continue
            state = (
                "renovate_present"
                if "renovate" in package
                else "present_without_renovate"
            )
            sources.append({"path": path, "state": state, "sha256": content_digest})
            if state == "renovate_present":
                findings.append(
                    "alternate Renovate config source is forbidden: package.json#renovate"
                )
            continue
        sources.append({"path": path, "state": "present", "sha256": content_digest})
        findings.append(f"alternate Renovate config source is forbidden: {path}")
    return sources, canonical_text, canonical_findings(findings)


def validate_config_sources(
    value: object, repository: str
) -> tuple[list[dict[str, Any]], list[str]]:
    if not isinstance(value, list) or len(value) != len(RENOVATE_CONFIG_PATHS):
        return [], [f"{repository} Renovate config-source inventory is incomplete"]
    sources: list[dict[str, Any]] = []
    errors: list[str] = []
    for index, path in enumerate(RENOVATE_CONFIG_PATHS):
        source = value[index]
        if not isinstance(source, dict) or set(source) != {"path", "state", "sha256"}:
            errors.append(f"{repository} Renovate config-source entry is malformed")
            continue
        if source.get("path") != path:
            errors.append(f"{repository} Renovate config-source order does not match")
        state = source.get("state")
        content_digest = source.get("sha256")
        allowed_states = {"absent", "present", "unknown"}
        if path == PACKAGE_JSON_CONFIG:
            allowed_states = {
                "absent",
                "present_without_renovate",
                "renovate_present",
                "unknown",
            }
        if state not in allowed_states:
            errors.append(f"{repository} Renovate config-source state is invalid")
        digest_required = state in {
            "present",
            "present_without_renovate",
            "renovate_present",
        }
        if digest_required and (
            not isinstance(content_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", content_digest) is None
        ):
            errors.append(f"{repository} Renovate config-source digest is missing")
        if state == "absent" and content_digest is not None:
            errors.append(f"{repository} absent Renovate config source has a digest")
        if state == "unknown" and content_digest is not None and (
            not isinstance(content_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", content_digest) is None
        ):
            errors.append(f"{repository} unknown Renovate config-source digest is invalid")
        sources.append(source)
    return sources, errors
