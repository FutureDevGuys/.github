#!/usr/bin/env python3
"""Semantic validation for Renovate effective-config proof rows."""

from __future__ import annotations

from typing import Any

from security_scan_adoption_contract import digest


PROOF_FLAG_KEYS = {
    "shared_extends_allowlist_exact",
    "local_extends_closed",
    "local_candidate_label_forbidden",
    "reserved_label_removal_forbidden",
    "renovate_merge_execution_forbidden",
    "major_manual_review_invariant",
}


def validate_effective_proof(
    value: object,
    shared_preset_sha256: object,
    canonical_source: dict[str, Any],
    repository: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    required_keys = {
        "shared_preset_sha256",
        "local_config_sha256",
        *PROOF_FLAG_KEYS,
    }
    if not isinstance(value, dict) or set(value) != required_keys:
        return None, [f"{repository} effective-config proof is malformed"]
    errors: list[str] = []
    if value.get("shared_preset_sha256") != shared_preset_sha256:
        errors.append(f"{repository} effective-config proof does not bind shared preset")
    expected_local_digest = (
        canonical_source["sha256"]
        if canonical_source.get("state") == "present"
        else digest(b"{}\n")
    )
    if value.get("local_config_sha256") != expected_local_digest:
        errors.append(f"{repository} effective-config proof does not bind canonical config")
    for key in PROOF_FLAG_KEYS:
        if not isinstance(value.get(key), bool):
            errors.append(f"{repository} effective-config proof flag {key} is malformed")
    return value, errors


def validate_proof_findings(
    proof: dict[str, Any], findings: list[str], repository: str
) -> list[str]:
    """Require every proof boolean to match its exact finding category."""

    shared_failed = any(finding.startswith("shared") for finding in findings)
    local_extends_failed = any(
        control in finding
        for finding in findings
        for control in ("extends", "ignorePresets", "globalExtends", "preset resolution")
    )
    candidate_failed = any("automerge-candidate" in finding for finding in findings)
    reserved_failed = any("remove reserved" in finding for finding in findings)
    merge_failed = any(
        "Renovate merging" in finding or "merge execution" in finding
        for finding in findings
    )
    expected_flags = {
        "shared_extends_allowlist_exact": not shared_failed,
        "local_extends_closed": not local_extends_failed,
        "local_candidate_label_forbidden": not candidate_failed,
        "reserved_label_removal_forbidden": not reserved_failed,
        "renovate_merge_execution_forbidden": not merge_failed,
        "major_manual_review_invariant": not shared_failed and not reserved_failed,
    }
    return [
        f"{repository} effective-config proof flag {key} does not match findings"
        for key, expected in expected_flags.items()
        if proof.get(key) is not expected
    ]
