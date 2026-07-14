#!/usr/bin/env python3
"""Build a deterministic Trivy execution receipt from a completed scan step."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 2
TRIVY_SCHEMA_VERSION = 2
SEVERITIES = {"HIGH", "CRITICAL"}
RESULT_COLLECTIONS = (
    "Vulnerabilities",
    "Misconfigurations",
    "Secrets",
    "Licenses",
)


def file_digest(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def input_file(path: Path) -> dict[str, Any]:
    return {
        "path": path.as_posix(),
        "sha256": file_digest(path),
    }


def report_evidence(path: Path) -> tuple[dict[str, Any] | None, dict[str, int]]:
    counts = {"high": 0, "critical": 0}
    if not path.is_file():
        return None, counts
    raw = path.read_bytes()
    json_valid = False
    report_schema_version: int | None = None
    results_count: int | None = None
    try:
        payload = json.loads(raw)
        if isinstance(payload, dict):
            report_schema_version = payload.get("SchemaVersion")
            results = payload.get("Results")
            json_valid = (
                report_schema_version == TRIVY_SCHEMA_VERSION
                and isinstance(results, list)
            )
            if json_valid:
                results_count = len(results)
                for result in results:
                    if not isinstance(result, dict):
                        continue
                    for collection in RESULT_COLLECTIONS:
                        findings = result.get(collection) or []
                        if not isinstance(findings, list):
                            continue
                        for finding in findings:
                            if not isinstance(finding, dict):
                                continue
                            severity = str(finding.get("Severity", "")).upper()
                            if severity in SEVERITIES:
                                counts[severity.lower()] += 1
    except json.JSONDecodeError:
        pass
    return (
        {
            "path": path.as_posix(),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
            "json_valid": json_valid,
            "schema_version": report_schema_version,
            "results_count": results_count,
        },
        counts,
    )


def build_receipt(args: argparse.Namespace) -> dict[str, Any]:
    report, counts = report_evidence(args.report)
    executed = args.scan_outcome in {"success", "failure"}
    tool_version = args.tool_version.strip()

    if not executed:
        status = "skipped"
    elif report is None or not report["json_valid"] or not tool_version:
        status = "error"
    elif counts["high"] + counts["critical"] > 0:
        status = "findings"
    elif args.scan_outcome == "success":
        status = "clean"
    else:
        status = "error"

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "executed": executed,
        "tool": {
            "name": "trivy",
            "version": tool_version,
        },
        "input": {
            "repository": args.repository,
            "ref": args.ref,
            "commit": args.commit,
            "event": args.event,
            "workflow_revision": args.workflow_revision,
            "scan_path": ".",
            "config": input_file(args.config),
            "ignore_file": input_file(args.ignore_file),
        },
        "result": {
            "status": status,
            "action_outcome": args.scan_outcome,
            "high": counts["high"],
            "critical": counts["critical"],
        },
        "report": report,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--scan-outcome", required=True)
    parser.add_argument("--tool-version", default="")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--event", required=True)
    parser.add_argument("--workflow-revision", required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--ignore-file", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    receipt = build_receipt(args)
    args.output.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
