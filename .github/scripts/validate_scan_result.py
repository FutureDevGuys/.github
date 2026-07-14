#!/usr/bin/env python3
"""Fail closed unless a Trivy receipt proves a clean, completed scan."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
TRIVY_SCHEMA_VERSION = 2
RESULT_COLLECTIONS = (
    "Vulnerabilities",
    "Misconfigurations",
    "Secrets",
    "Licenses",
)
SEVERITIES = {"HIGH", "CRITICAL"}


def is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def report_finding_counts(payload: dict[str, Any]) -> tuple[dict[str, int], list[str]]:
    """Recompute gated findings from the uploaded report, independent of the receipt."""

    counts = {"high": 0, "critical": 0}
    errors: list[str] = []
    results = payload.get("Results")
    if not isinstance(results, list):
        return counts, ["report Results must be a list"]
    for result_index, result in enumerate(results):
        if not isinstance(result, dict):
            errors.append(f"report Results[{result_index}] must be an object")
            continue
        for collection in RESULT_COLLECTIONS:
            if collection not in result or result[collection] is None:
                continue
            findings = result[collection]
            if not isinstance(findings, list):
                errors.append(
                    f"report Results[{result_index}].{collection} must be a list"
                )
                continue
            for finding_index, finding in enumerate(findings):
                if not isinstance(finding, dict):
                    errors.append(
                        "report "
                        f"Results[{result_index}].{collection}[{finding_index}] "
                        "must be an object"
                    )
                    continue
                if (
                    collection == "Misconfigurations"
                    and str(finding.get("Status", "FAIL")).upper() != "FAIL"
                ):
                    continue
                severity = str(finding.get("Severity", "")).upper()
                if severity in SEVERITIES:
                    counts[severity.lower()] += 1
    return counts, errors


def validate_receipt(
    receipt: Any,
    report_path: Path,
    expected_input: Mapping[str, str] | None = None,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(receipt, dict):
        return ["receipt must be a JSON object"]
    if receipt.get("schema_version") != 2:
        errors.append("schema_version must be 2")
    if receipt.get("executed") is not True:
        errors.append("executed must be true")

    tool = receipt.get("tool")
    if not isinstance(tool, dict):
        errors.append("tool must be an object")
    else:
        if tool.get("name") != "trivy":
            errors.append("tool.name must be trivy")
        if not is_nonempty_string(tool.get("version")):
            errors.append("tool.version must be non-empty")

    scan_input = receipt.get("input")
    if not isinstance(scan_input, dict):
        errors.append("input must be an object")
    else:
        for key in ("repository", "ref", "event", "scan_path"):
            if not is_nonempty_string(scan_input.get(key)):
                errors.append(f"input.{key} must be non-empty")
        if not COMMIT_RE.fullmatch(str(scan_input.get("commit", ""))):
            errors.append("input.commit must be an exact 40-character lowercase commit SHA")
        if not COMMIT_RE.fullmatch(str(scan_input.get("workflow_revision", ""))):
            errors.append(
                "input.workflow_revision must be an exact 40-character lowercase commit SHA"
            )
        if expected_input is not None:
            for key in (
                "repository",
                "ref",
                "commit",
                "event",
                "workflow_revision",
            ):
                expected = expected_input.get(key)
                if not is_nonempty_string(expected):
                    errors.append(f"expected {key} must be non-empty")
                elif scan_input.get(key) != expected:
                    errors.append(f"input.{key} does not match the workflow context")
        for key in ("config", "ignore_file"):
            item = scan_input.get(key)
            if not isinstance(item, dict):
                errors.append(f"input.{key} must be an object")
                continue
            if not is_nonempty_string(item.get("path")):
                errors.append(f"input.{key}.path must be non-empty")
            if not SHA256_RE.fullmatch(str(item.get("sha256", ""))):
                errors.append(f"input.{key}.sha256 must be a SHA-256 digest")

    result = receipt.get("result")
    if not isinstance(result, dict):
        errors.append("result must be an object")
    else:
        status = result.get("status")
        action_outcome = result.get("action_outcome")
        high = result.get("high")
        critical = result.get("critical")
        if status not in {"clean", "findings", "error", "skipped"}:
            errors.append("result.status is invalid")
        if action_outcome not in {"success", "failure", "cancelled", "skipped", ""}:
            errors.append("result.action_outcome is invalid")
        if not isinstance(high, int) or isinstance(high, bool) or high < 0:
            errors.append("result.high must be a non-negative integer")
        if not isinstance(critical, int) or isinstance(critical, bool) or critical < 0:
            errors.append("result.critical must be a non-negative integer")
        if isinstance(high, int) and isinstance(critical, int):
            findings = high + critical
            if status == "clean" and (action_outcome != "success" or findings != 0):
                errors.append("clean result requires a successful action with no findings")
            if status == "findings" and (action_outcome != "failure" or findings == 0):
                errors.append("findings result requires a failed action with findings")

    report = receipt.get("report")
    if not isinstance(report, dict):
        errors.append("report evidence is missing")
    else:
        if not is_nonempty_string(report.get("path")):
            errors.append("report.path must be non-empty")
        digest = report.get("sha256")
        if not SHA256_RE.fullmatch(str(digest or "")):
            errors.append("report.sha256 must be a SHA-256 digest")
        if report.get("json_valid") is not True:
            errors.append("report.json_valid must be true")
        if report.get("schema_version") != TRIVY_SCHEMA_VERSION:
            errors.append(f"report.schema_version must be {TRIVY_SCHEMA_VERSION}")
        if not isinstance(report.get("results_count"), int) or isinstance(
            report.get("results_count"), bool
        ) or report.get("results_count", -1) < 0:
            errors.append("report.results_count must be a non-negative integer")
        if not isinstance(report.get("size_bytes"), int) or report.get("size_bytes", 0) <= 0:
            errors.append("report.size_bytes must be positive")
        if not report_path.is_file():
            errors.append(f"report file is missing: {report_path}")
        else:
            raw = report_path.read_bytes()
            actual_digest = hashlib.sha256(raw).hexdigest()
            if digest != actual_digest:
                errors.append("report digest does not match the uploaded report")
            if report.get("size_bytes") != len(raw):
                errors.append("report size does not match the uploaded report")
            try:
                payload = json.loads(raw)
                if not isinstance(payload, dict):
                    errors.append("report JSON must be an object")
                else:
                    if payload.get("SchemaVersion") != TRIVY_SCHEMA_VERSION:
                        errors.append(
                            f"report SchemaVersion must be {TRIVY_SCHEMA_VERSION}"
                        )
                    results = payload.get("Results")
                    if isinstance(results, list):
                        if report.get("results_count") != len(results):
                            errors.append("report results_count does not match Results")
                    counts, count_errors = report_finding_counts(payload)
                    errors.extend(count_errors)
                    if isinstance(result, dict):
                        if result.get("high") != counts["high"]:
                            errors.append(
                                "result.high does not match the uploaded report"
                            )
                        if result.get("critical") != counts["critical"]:
                            errors.append(
                                "result.critical does not match the uploaded report"
                            )
            except json.JSONDecodeError:
                errors.append("report file is not valid JSON")

    if isinstance(result, dict) and result.get("status") != "clean":
        errors.append(f"scan result is not clean: {result.get('status')}")
    return errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", type=Path)
    parser.add_argument("report", type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--event", required=True)
    parser.add_argument("--workflow-revision", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"ERROR: scan receipt is missing: {args.receipt}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as error:
        print(f"ERROR: scan receipt is invalid JSON: {error}", file=sys.stderr)
        return 1
    expected_input = {
        "repository": args.repository,
        "ref": args.ref,
        "commit": args.commit,
        "event": args.event,
        "workflow_revision": args.workflow_revision,
    }
    errors = validate_receipt(receipt, args.report, expected_input)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Trivy receipt proves a clean, completed scan.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
