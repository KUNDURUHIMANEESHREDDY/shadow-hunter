"""Read-only comparison of DynamoDB audit event keys and S3 archive keys.

This command reads only event_id/created_at from the AUDIT GSI and object keys
from S3. It does not read archived object bodies or mutate either service.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Iterable

from .audit_exporter import _object_key


def compare_archive_keys(
    expected_keys: Iterable[str],
    actual_keys: Iterable[str],
    *,
    sample_limit: int = 25,
) -> dict[str, Any]:
    """Compare expected and actual key sets without including audit payloads."""
    if sample_limit < 0:
        raise ValueError("sample_limit cannot be negative")
    expected = set(expected_keys)
    actual = set(actual_keys)
    missing = sorted(expected - actual)
    orphaned = sorted(actual - expected)
    return {
        "expected_archive_objects": len(expected),
        "actual_archive_objects": len(actual),
        "missing_archive_objects": len(missing),
        "orphaned_archive_objects": len(orphaned),
        "missing_key_samples": missing[:sample_limit],
        "orphaned_key_samples": orphaned[:sample_limit],
    }


def collect_audit_keys(
    table: Any,
    s3_client: Any,
    *,
    bucket: str,
    prefix: str,
    page_size: int = 1000,
) -> dict[str, Any]:
    """Read audit identities from GSI1 and compare them with S3 object keys."""
    from boto3.dynamodb.conditions import Key

    if not isinstance(bucket, str) or not bucket.strip():
        raise ValueError("An S3 archive bucket is required")
    normalized_prefix = prefix.strip("/")
    if not normalized_prefix or any(
        part in {".", ".."} for part in normalized_prefix.split("/")
    ):
        raise ValueError("Invalid audit archive prefix")
    if not 1 <= page_size <= 1000:
        raise ValueError("page_size must be between 1 and 1000")

    expected_keys: set[str] = set()
    seen_event_ids: set[str] = set()
    duplicate_event_ids = 0
    invalid_records = 0
    rows_seen = 0
    invalid_samples: list[str] = []
    last_evaluated_key: dict[str, Any] | None = None

    while True:
        request: dict[str, Any] = {
            "IndexName": "GSI1",
            "KeyConditionExpression": Key("GSI1PK").eq("AUDIT"),
            "ProjectionExpression": "#event_id, #created_at",
            "ExpressionAttributeNames": {
                "#event_id": "event_id",
                "#created_at": "created_at",
            },
            "Limit": page_size,
        }
        if last_evaluated_key:
            request["ExclusiveStartKey"] = last_evaluated_key
        response = table.query(**request)
        for item in response.get("Items", []):
            rows_seen += 1
            event_id = item.get("event_id")
            created_at = item.get("created_at")
            try:
                if not isinstance(event_id, str) or not isinstance(created_at, str):
                    raise ValueError("Missing event identity")
                key = _object_key(created_at, event_id, normalized_prefix)
            except (TypeError, ValueError):
                invalid_records += 1
                if len(invalid_samples) < 25:
                    invalid_samples.append(
                        event_id[:128] if isinstance(event_id, str) else "[missing-event-id]"
                    )
                continue
            if event_id in seen_event_ids:
                duplicate_event_ids += 1
            seen_event_ids.add(event_id)
            expected_keys.add(key)

        last_evaluated_key = response.get("LastEvaluatedKey")
        if not last_evaluated_key:
            break

    actual_keys: set[str] = set()
    paginator = s3_client.get_paginator("list_objects_v2")
    s3_prefix = normalized_prefix + "/"
    for page in paginator.paginate(Bucket=bucket, Prefix=s3_prefix):
        for obj in page.get("Contents", []):
            key = obj.get("Key")
            if isinstance(key, str) and key.endswith(".json"):
                actual_keys.add(key)

    comparison = compare_archive_keys(expected_keys, actual_keys)
    return {
        "dynamodb_audit_rows_seen": rows_seen,
        "invalid_dynamodb_audit_rows": invalid_records,
        "duplicate_event_ids": duplicate_event_ids,
        "s3_json_objects_seen": len(actual_keys),
        **comparison,
        "invalid_event_id_samples": invalid_samples,
        "ok": (
            invalid_records == 0
            and duplicate_event_ids == 0
            and comparison["missing_archive_objects"] == 0
            and comparison["orphaned_archive_objects"] == 0
        ),
        "consistency_note": (
            "GSI1 is eventually consistent. Run after the stream exporter has "
            "caught up and repeat before treating a mismatch as permanent."
        ),
    }


def reconcile(
    *,
    table_name: str,
    bucket: str,
    prefix: str = "audit-events",
    region: str | None = None,
) -> dict[str, Any]:
    import boto3

    session = boto3.session.Session(region_name=region)
    table = session.resource("dynamodb").Table(table_name)
    s3_client = session.client("s3")
    return collect_audit_keys(
        table,
        s3_client,
        bucket=bucket,
        prefix=prefix,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare DynamoDB audit event identities with the S3 Object Lock archive."
    )
    parser.add_argument(
        "--table-name",
        default=os.environ.get("SHADOW_HUNTER_DYNAMODB_TABLE"),
    )
    parser.add_argument(
        "--bucket",
        default=os.environ.get("SHADOW_HUNTER_AUDIT_BUCKET"),
    )
    parser.add_argument(
        "--prefix",
        default=os.environ.get("SHADOW_HUNTER_AUDIT_PREFIX", "audit-events"),
    )
    parser.add_argument("--region", default=os.environ.get("AWS_REGION"))
    parser.add_argument("--report-file", type=Path)
    args = parser.parse_args(argv)
    if not args.table_name or not args.bucket:
        parser.error(
            "Provide --table-name and --bucket or set the corresponding SHADOW_HUNTER variables"
        )
    try:
        report = reconcile(
            table_name=args.table_name,
            bucket=args.bucket,
            prefix=args.prefix,
            region=args.region,
        )
    except Exception as exc:
        print(
            json.dumps(
                {"ok": False, "error_type": type(exc).__name__},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2

    rendered = json.dumps(report, indent=2, sort_keys=True)
    print(rendered)
    if args.report_file:
        args.report_file.write_text(rendered + "\n", encoding="utf-8")
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
