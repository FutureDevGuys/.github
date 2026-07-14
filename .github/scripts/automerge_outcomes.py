#!/usr/bin/env python3
"""Record and summarize machine-readable automerge outcomes."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = 1
OUTCOMES = {"merged", "dry_run", "skipped"}


def parse_timestamp(value: str) -> datetime:
    normalized = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp must include a timezone: {value}")
    return parsed.astimezone(timezone.utc)


def format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def build_record(
    *,
    repository: str,
    pull_request: int,
    created_at: str,
    outcome: str,
    reason: str,
    detail: str,
    blocks_progress: bool,
    observed_at: str | None = None,
) -> dict[str, Any]:
    if not repository or "/" not in repository:
        raise ValueError("repository must be an owner/name string")
    if pull_request <= 0:
        raise ValueError("pull_request must be positive")
    if outcome not in OUTCOMES:
        raise ValueError(f"unsupported outcome: {outcome}")
    if not reason.strip():
        raise ValueError("reason must be non-empty")

    created = parse_timestamp(created_at)
    observed = (
        parse_timestamp(observed_at)
        if observed_at
        else datetime.now(timezone.utc)
    )
    age_hours = max(0.0, (observed - created).total_seconds() / 3600)
    return {
        "schema_version": SCHEMA_VERSION,
        "repository": repository,
        "pull_request": pull_request,
        "created_at": format_timestamp(created),
        "observed_at": format_timestamp(observed),
        "age_hours": round(age_hours, 3),
        "outcome": outcome,
        "reason": reason.strip(),
        "detail": detail.strip(),
        "blocks_progress": blocks_progress,
    }


def load_records(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid JSON on line {line_number}: {error}") from error
        if not isinstance(record, dict) or record.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(f"invalid outcome record on line {line_number}")
        records.append(record)
    return records


def summarize_records(
    records: Iterable[dict[str, Any]], *, degrade_after_hours: float
) -> dict[str, Any]:
    materialized = list(records)
    outcome_counts = Counter(str(record.get("outcome", "invalid")) for record in materialized)
    skip_reasons = Counter(
        str(record.get("reason", "unknown"))
        for record in materialized
        if record.get("outcome") == "skipped"
    )
    stale_blockers = [
        record
        for record in materialized
        if record.get("outcome") == "skipped"
        and record.get("blocks_progress") is True
        and isinstance(record.get("age_hours"), (int, float))
        and not isinstance(record.get("age_hours"), bool)
        and float(record["age_hours"]) >= degrade_after_hours
    ]
    progress = outcome_counts["merged"] + outcome_counts["dry_run"]
    return {
        "schema_version": SCHEMA_VERSION,
        "record_count": len(materialized),
        "outcomes": dict(sorted(outcome_counts.items())),
        "skip_reasons": dict(sorted(skip_reasons.items())),
        "oldest_skip_hours": max(
            (
                float(record["age_hours"])
                for record in materialized
                if record.get("outcome") == "skipped"
                and isinstance(record.get("age_hours"), (int, float))
                and not isinstance(record.get("age_hours"), bool)
            ),
            default=0.0,
        ),
        "degrade_after_hours": degrade_after_hours,
        "stale_progress_blockers": len(stale_blockers),
        "degraded": progress == 0 and bool(stale_blockers),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    record = subparsers.add_parser("record")
    record.add_argument("--output", type=Path, required=True)
    record.add_argument("--repository", required=True)
    record.add_argument("--pull-request", type=int, required=True)
    record.add_argument("--created-at", required=True)
    record.add_argument("--outcome", choices=sorted(OUTCOMES), required=True)
    record.add_argument("--reason", required=True)
    record.add_argument("--detail", default="")
    record.add_argument("--blocks-progress", action="store_true")
    record.add_argument("--observed-at")

    summarize = subparsers.add_parser("summarize")
    summarize.add_argument("--input", type=Path, required=True)
    summarize.add_argument("--output", type=Path, required=True)
    summarize.add_argument("--degrade-after-hours", type=float, default=24.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "record":
            record = build_record(
                repository=args.repository,
                pull_request=args.pull_request,
                created_at=args.created_at,
                outcome=args.outcome,
                reason=args.reason,
                detail=args.detail,
                blocks_progress=args.blocks_progress,
                observed_at=args.observed_at,
            )
            with args.output.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
            return 0

        summary = summarize_records(
            load_records(args.input),
            degrade_after_hours=args.degrade_after_hours,
        )
        args.output.write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(json.dumps(summary, sort_keys=True))
        return 0
    except (OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
