#!/usr/bin/env python3
"""Semantic validation for security-scan adoption reports and receipts."""

from __future__ import annotations

import json
import re
import stat
from pathlib import Path
from typing import Any

from renovate_config_authority import (
    PACKAGE_JSON_CONFIG,
    validate_config_sources,
)
from security_scan_adoption_contract import (
    COMMIT_RE,
    RECEIPT_SCHEMA_VERSION,
    REPORT_SCHEMA_VERSION,
    TOOL_NAME,
    TOOL_VERSION,
    canonical_findings,
    canonical_json,
    digest,
    render_canonical_caller,
)
from security_scan_adoption_lifecycle import (
    PolicyError,
    classify_repository,
    validate_policy,
)
from security_scan_adoption_proof import (
    validate_effective_proof,
    validate_proof_findings,
)


MAX_EVIDENCE_BYTES = 5 * 1024 * 1024
DEFAULT_POLICY_PATH = Path(__file__).resolve().parent.parent / "security-scan-adopters.json"
DEFAULT_CALLER_TEMPLATE_PATH = (
    Path(__file__).resolve().parent.parent / "tests/fixtures/security-scan-caller.yml"
)


def load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"cannot read {label}: {error}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size > MAX_EVIDENCE_BYTES
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ValueError(f"{label} must be a bounded non-writable regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot parse {label}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} root must be an object")
    return value


def evidence_findings(value: object, label: str) -> tuple[list[str], list[str]]:
    if not isinstance(value, list):
        return [], [f"{label} must be a list"]
    if any(not isinstance(finding, str) or not finding for finding in value):
        return [], [f"{label} must contain nonempty strings"]
    findings = list(value)
    if findings != canonical_findings(findings):
        return findings, [f"{label} must be in canonical unique order"]
    return findings, []


def validate_evidence(
    report_path: Path,
    receipt_path: Path,
    policy_path: Path = DEFAULT_POLICY_PATH,
    required_revision: str | None = None,
) -> list[str]:
    try:
        report = load_json_object(report_path, "adoption report")
        receipt = load_json_object(receipt_path, "adoption receipt")
        policy = validate_policy(load_json_object(policy_path, "adoption policy"))
    except (ValueError, PolicyError) as error:
        return [str(error)]
    errors: list[str] = []
    if (
        report.get("schema_version") != REPORT_SCHEMA_VERSION
        or report.get("executed") is not True
    ):
        errors.append("report does not prove execution")
    if report.get("tool") != {"name": TOOL_NAME, "version": TOOL_VERSION}:
        errors.append("report tool identity does not match validator")
    visibility = report.get("visibility")
    repositories = report.get("repositories")
    inputs = report.get("inputs")
    if not isinstance(inputs, dict):
        errors.append("report inputs are missing")
        inputs = {}
    credential_source = inputs.get("credential_source")
    if credential_source not in {"token", "gh-session", "fixture"}:
        errors.append("report credential source is invalid")
    observed_required_revision = inputs.get("required_revision")
    canonical_caller_digest: str | None = None
    if (
        not isinstance(observed_required_revision, str)
        or COMMIT_RE.fullmatch(observed_required_revision) is None
    ):
        errors.append("report required revision is not one exact commit SHA")
    else:
        try:
            caller_template = DEFAULT_CALLER_TEMPLATE_PATH.read_text(encoding="utf-8")
            canonical_caller_digest = digest(
                render_canonical_caller(
                    caller_template,
                    observed_required_revision,
                ).encode("utf-8")
            )
        except (OSError, UnicodeDecodeError, ValueError) as error:
            errors.append(f"cannot render canonical security caller: {error}")
    if required_revision is not None:
        if COMMIT_RE.fullmatch(required_revision) is None:
            errors.append("expected required revision is not one exact commit SHA")
        elif observed_required_revision != required_revision:
            errors.append("report required revision does not match workflow admission")
    if not isinstance(visibility, dict) or not isinstance(repositories, list):
        errors.append("report visibility or repositories are missing")
        visibility = {}
        repositories = []

    global_findings: list[str] = []
    flattened_row_findings: list[str] = []
    active_revisions: list[dict[str, Any]] = []
    config_source_inventory: list[dict[str, Any]] = []
    if visibility.get("paginated") is not True:
        errors.append("report does not prove paginated discovery")
    inventory_keys = (
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
    normalized = [
        {key: row[key] for key in inventory_keys}
        for row in repositories
        if isinstance(row, dict) and all(key in row for key in inventory_keys)
    ]
    if len(normalized) != len(repositories):
        errors.append("report repository inventory is malformed")
    elif visibility.get("inventory_sha256") != digest(canonical_json(normalized)):
        errors.append("report repository inventory digest does not match")
    repository_names: list[str] = []
    for row in repositories:
        if isinstance(row, dict):
            full_name = row.get("full_name")
            if isinstance(full_name, str):
                repository_names.append(full_name)
    if len(repository_names) != len(repositories):
        errors.append("report repository names are malformed")
    elif repository_names != sorted(set(repository_names)):
        errors.append("report repositories are not in canonical unique order")
    if visibility.get("discovered_repository_count") != len(repositories):
        errors.append("report repository count does not match inventory")
    observed_organization = visibility.get("organization")
    organization_exact = observed_organization == policy["organization"]
    if not isinstance(observed_organization, dict) or set(observed_organization) != {
        "login",
        "id",
        "node_id",
    }:
        errors.append("report organization identity evidence is malformed")
    if visibility.get("organization_identity_exact") is not organization_exact:
        errors.append("report organization identity dimension does not match evidence")
    if not organization_exact:
        global_findings.append("organization identity differs from policy")
    counts = visibility.get("organization_repository_counts")
    expected_count: int | None = None
    if isinstance(counts, dict) and set(counts) == {"public", "private"}:
        public_count = counts.get("public")
        private_count = counts.get("private")
        if (
            isinstance(public_count, int)
            and not isinstance(public_count, bool)
            and isinstance(private_count, int)
            and not isinstance(private_count, bool)
        ):
            expected_count = public_count + private_count
    if visibility.get("expected_repository_count") != expected_count:
        errors.append("report expected repository count does not match evidence")
    count_exact = expected_count == len(repositories)
    if visibility.get("repository_count_exact") is not count_exact:
        errors.append("report repository count dimension does not match")
    if not count_exact:
        global_findings.append(
            "paginated repository count does not match organization totals"
        )
    missing_overrides = sorted(
        set(policy["lifecycle_overrides"]) - set(repository_names)
    )
    if visibility.get("missing_lifecycle_overrides") != missing_overrides:
        errors.append("report missing lifecycle overrides do not match policy")
    global_findings.extend(
        f"{repository}: lifecycle override is absent from discovery"
        for repository in missing_overrides
    )
    global_findings = canonical_findings(global_findings)
    expected_complete = (
        organization_exact is True
        and count_exact is True
        and not missing_overrides
    )
    if visibility.get("complete") is not expected_complete:
        errors.append("report visibility completeness does not match dimensions")
    if not expected_complete:
        errors.append("report does not prove complete organization visibility")

    for row in repositories:
        if not isinstance(row, dict):
            continue
        name = row.get("full_name")
        if not isinstance(name, str):
            continue
        if not all(key in row for key in inventory_keys):
            continue
        lifecycle_findings, category_errors = evidence_findings(
            row.get("lifecycle_findings"), f"{name} lifecycle findings"
        )
        errors.extend(category_errors)
        expected_lifecycle, expected_lifecycle_findings = classify_repository(
            row, policy
        )
        if row.get("lifecycle") != expected_lifecycle:
            errors.append(f"{name} lifecycle does not match policy and inventory")
        if lifecycle_findings != expected_lifecycle_findings:
            errors.append(f"{name} lifecycle findings do not match policy and inventory")
        security_findings, category_errors = evidence_findings(
            row.get("security_scan_findings"), f"{name} security-scan findings"
        )
        errors.extend(category_errors)
        renovate_findings, category_errors = evidence_findings(
            row.get("renovate_config_findings"), f"{name} Renovate findings"
        )
        errors.extend(category_errors)
        expected_row_findings = canonical_findings(
            [
                *(f"{name}: {finding}" for finding in lifecycle_findings),
                *(f"{name}: {finding}" for finding in security_findings),
                *(f"{name}: {finding}" for finding in renovate_findings),
            ]
        )
        row_findings, category_errors = evidence_findings(
            row.get("findings"), f"{name} flattened findings"
        )
        errors.extend(category_errors)
        if row_findings != expected_row_findings:
            errors.append(f"{name} findings do not match row audit dimensions")
        flattened_row_findings.extend(expected_row_findings)

        lifecycle = row.get("lifecycle")
        revision = row.get("default_revision")
        if lifecycle not in {"active", "authority", "archived"}:
            errors.append(f"{name} lifecycle is invalid")
            continue
        if lifecycle != "active":
            if revision is not None:
                errors.append(f"{name} non-active lifecycle binds a revision")
            if row.get("security_scan") != "not_applicable":
                errors.append(f"{name} non-active security status is not_applicable")
            if row.get("security_scan_caller") is not None or security_findings:
                errors.append(f"{name} non-active row contains security evidence")
            if row.get("renovate_effective_config") != "not_applicable":
                errors.append(f"{name} non-active Renovate status is not_applicable")
            if (
                row.get("renovate_config_sources") is not None
                or row.get("effective_config_proof") is not None
                or renovate_findings
            ):
                errors.append(f"{name} non-active row contains Renovate evidence")
            continue

        active_revisions.append({"repository": name, "revision": revision})
        config_source_inventory.append(
            {
                "repository": name,
                "revision": revision,
                "sources": row.get("renovate_config_sources"),
            }
        )
        if not isinstance(revision, str) or COMMIT_RE.fullmatch(revision) is None:
            errors.append(f"{name} active repository does not bind one exact revision")
            if row.get("security_scan") != "unknown":
                errors.append(f"{name} unresolved revision must make security unknown")
            if row.get("renovate_effective_config") != "unknown":
                errors.append(f"{name} unresolved revision must make Renovate unknown")
            if (
                row.get("security_scan_caller") is not None
                or row.get("renovate_config_sources") is not None
                or row.get("effective_config_proof") is not None
                or security_findings
                or renovate_findings
            ):
                errors.append(f"{name} unresolved revision contains derived evidence")
            if not lifecycle_findings:
                errors.append(f"{name} unresolved revision has no finding")
            continue

        caller = row.get("security_scan_caller")
        expected_scan_status: str | None = None
        if not isinstance(caller, dict) or set(caller) != {"state", "sha256"}:
            errors.append(f"{name} security caller evidence is malformed")
        else:
            state = caller.get("state")
            caller_digest = caller.get("sha256")
            if state == "present":
                if (
                    not isinstance(caller_digest, str)
                    or re.fullmatch(r"[0-9a-f]{64}", caller_digest) is None
                ):
                    errors.append(f"{name} security caller digest is missing")
                elif canonical_caller_digest is not None:
                    canonical_finding = (
                        "caller bytes must exactly match the approved organization artifact"
                    )
                    if caller_digest == canonical_caller_digest:
                        if security_findings:
                            errors.append(
                                f"{name} canonical security caller has findings"
                            )
                    elif canonical_finding not in security_findings:
                        errors.append(
                            f"{name} noncanonical security caller lacks an exact finding"
                        )
                expected_scan_status = "fail" if security_findings else "pass"
            elif state == "absent":
                if caller_digest is not None:
                    errors.append(f"{name} absent security caller has a digest")
                if security_findings != ["security-scan caller is missing"]:
                    errors.append(f"{name} missing security caller finding is not exact")
                expected_scan_status = "missing"
            elif state == "unknown":
                if caller_digest is not None or not security_findings:
                    errors.append(f"{name} unknown security caller evidence is incomplete")
                expected_scan_status = "unknown"
            else:
                errors.append(f"{name} security caller state is invalid")
        if (
            expected_scan_status is not None
            and row.get("security_scan") != expected_scan_status
        ):
            errors.append(f"{name} security status does not match caller evidence")

        sources, source_errors = validate_config_sources(
            row.get("renovate_config_sources"), name
        )
        errors.extend(source_errors)
        if not sources:
            continue
        canonical_source = sources[0]
        unknown_sources = [
            source for source in sources if source.get("state") == "unknown"
        ]
        required_source_findings = [
            f"alternate Renovate config source is forbidden: {source['path']}"
            for source in sources[1:-1]
            if source.get("state") == "present"
        ]
        if sources[-1].get("state") == "renovate_present":
            required_source_findings.append(
                "alternate Renovate config source is forbidden: package.json#renovate"
            )
        for finding in required_source_findings:
            if finding not in renovate_findings:
                errors.append(f"{name} alternate config presence lacks an exact finding")
        if unknown_sources:
            if row.get("renovate_effective_config") != "unknown":
                errors.append(f"{name} unknown config source must make Renovate unknown")
            if row.get("effective_config_proof") is not None:
                errors.append(f"{name} unknown config source must not retain a proof")
            if not renovate_findings:
                errors.append(f"{name} unknown config source has no finding")
        else:
            proof, proof_errors = validate_effective_proof(
                row.get("effective_config_proof"),
                inputs.get("shared_preset_sha256"),
                canonical_source,
                name,
            )
            errors.extend(proof_errors)
            if proof is not None:
                errors.extend(
                    validate_proof_findings(proof, renovate_findings, name)
                )
            expected_renovate_status = (
                "fail"
                if renovate_findings
                else "pass"
                if canonical_source.get("state") == "present"
                else "absent_pass"
            )
            if row.get("renovate_effective_config") != expected_renovate_status:
                errors.append(
                    f"{name} Renovate status does not match source and proof evidence"
                )

    if inputs.get("active_revisions_sha256") != digest(
        canonical_json(active_revisions)
    ):
        errors.append("report active revision digest does not match")
    if inputs.get("renovate_config_sources_sha256") != digest(
        canonical_json(config_source_inventory)
    ):
        errors.append("report Renovate config-source digest does not match")
    expected_findings = canonical_findings(
        [*global_findings, *flattened_row_findings]
    )
    findings, finding_errors = evidence_findings(
        report.get("findings"), "report findings"
    )
    errors.extend(finding_errors)
    if findings != expected_findings:
        errors.append("report findings do not exactly match global and repository findings")
    expected_result = {
        "status": "pass" if not expected_findings else "fail",
        "finding_count": len(expected_findings),
    }
    if report.get("result") != expected_result:
        errors.append("report result does not match recomputed findings")

    try:
        raw = report_path.read_bytes()
    except OSError as error:
        errors.append(f"cannot reread adoption report: {error}")
        raw = b""
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
    report_policy = report.get("policy")
    policy_bytes = policy_path.read_bytes()
    if not isinstance(report_policy, dict) or report_policy != {
        "path": policy_path.name,
        "sha256": digest(policy_bytes),
    }:
        errors.append("report policy binding does not match lifecycle authority")
    expected_inputs = {
        "credential_source": credential_source,
        "policy_sha256": report_policy.get("sha256")
        if isinstance(report_policy, dict)
        else None,
        "required_revision": inputs.get("required_revision"),
        "shared_preset_sha256": inputs.get("shared_preset_sha256"),
        "inventory_sha256": visibility.get("inventory_sha256"),
        "active_revisions_sha256": inputs.get("active_revisions_sha256"),
        "renovate_config_sources_sha256": inputs.get(
            "renovate_config_sources_sha256"
        ),
        "repository_count": visibility.get("discovered_repository_count"),
    }
    if receipt.get("inputs") != expected_inputs:
        errors.append("receipt inputs do not bind report inputs")
    if receipt.get("schema_version") != RECEIPT_SCHEMA_VERSION:
        errors.append("receipt schema version does not match validator")
    if receipt.get("tool") != report.get("tool"):
        errors.append("receipt tool identity does not bind report")
    if (
        receipt.get("result") != report.get("result")
        or receipt.get("executed") is not True
    ):
        errors.append("receipt does not bind executed report result")
    if expected_result != {"status": "pass", "finding_count": 0}:
        errors.append("adoption audit result is not pass")
    return errors
