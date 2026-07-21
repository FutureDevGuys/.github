#!/usr/bin/env python3
"""Canonical lifecycle policy semantics for security-scan adoption."""

from __future__ import annotations

from typing import Any


EXPECTED_REQUIREMENTS = {
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


class PolicyError(ValueError):
    """The lifecycle policy cannot be used as semantic authority."""


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise PolicyError(f"{label} keys must be exactly {sorted(expected)}")


def validate_policy(value: dict[str, Any]) -> dict[str, Any]:
    """Validate and return the closed organization lifecycle policy."""

    _exact_keys(
        value,
        {
            "schema_version",
            "organization",
            "default_lifecycle",
            "lifecycle_overrides",
            "requirements",
        },
        "policy",
    )
    if value.get("schema_version") != 2 or value.get("default_lifecycle") != "active":
        raise PolicyError("policy schema or default lifecycle is unsupported")
    organization = value.get("organization")
    overrides = value.get("lifecycle_overrides")
    if not isinstance(organization, dict):
        raise PolicyError("policy.organization must be an object")
    _exact_keys(organization, {"login", "id", "node_id"}, "policy.organization")
    if (
        organization.get("login") != "FutureDevGuys"
        or not isinstance(organization.get("id"), int)
        or isinstance(organization.get("id"), bool)
        or not isinstance(organization.get("node_id"), str)
    ):
        raise PolicyError("policy organization identity is invalid")
    if not isinstance(overrides, dict) or value.get("requirements") != EXPECTED_REQUIREMENTS:
        raise PolicyError("policy lifecycle overrides or requirements are not exact")
    for repository, override in overrides.items():
        if not isinstance(repository, str) or not repository.startswith("FutureDevGuys/"):
            raise PolicyError("policy lifecycle override repository is invalid")
        if not isinstance(override, dict):
            raise PolicyError(f"override for {repository} must be an object")
        _exact_keys(
            override,
            {"repository_id", "node_id", "lifecycle"},
            f"override {repository}",
        )
        if (
            not isinstance(override.get("repository_id"), int)
            or isinstance(override.get("repository_id"), bool)
            or not isinstance(override.get("node_id"), str)
            or override.get("lifecycle") not in {"authority", "archived"}
        ):
            raise PolicyError(f"override for {repository} is invalid")
    return value


def classify_repository(
    repository: dict[str, Any], policy: dict[str, Any]
) -> tuple[str, list[str]]:
    """Derive lifecycle and exact findings from policy plus inventory metadata."""

    name = repository["full_name"]
    override = policy["lifecycle_overrides"].get(name)
    findings: list[str] = []
    if override is None:
        if repository["archived"]:
            findings.append("archived repository lacks an explicit lifecycle override")
            lifecycle = "archived"
        else:
            lifecycle = policy["default_lifecycle"]
    else:
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
    organization = policy["organization"]
    if repository["owner"] != organization:
        findings.append("owner identity differs from policy")
    if not name.startswith(f"{organization['login']}/"):
        findings.append("repository is outside the organization")
    if repository["disabled"]:
        findings.append("repository is disabled")
    return lifecycle, sorted(set(findings))
