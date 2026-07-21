#!/usr/bin/env python3
"""Shared immutable contracts for the security-scan adoption audit."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
REPORT_SCHEMA_VERSION = 3
RECEIPT_SCHEMA_VERSION = 3
TOOL_NAME = "security-scan-adoption-audit"
TOOL_VERSION = "2.3.0"
CALLER_REVISION_PLACEHOLDER = "1" * 40


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_findings(values: list[str]) -> list[str]:
    """Return the stable, duplicate-free finding order used by evidence."""

    return sorted(set(values))


def render_canonical_caller(template: str, revision: str) -> str:
    """Render the immutable caller fixture at one exact workflow revision."""

    if COMMIT_RE.fullmatch(revision) is None:
        raise ValueError("canonical caller revision must be one exact commit SHA")
    if template.count(CALLER_REVISION_PLACEHOLDER) != 2:
        raise ValueError("canonical caller template must contain two revision pins")
    return template.replace(CALLER_REVISION_PLACEHOLDER, revision)
