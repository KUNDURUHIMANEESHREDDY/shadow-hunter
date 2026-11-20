"""Read-only content verification for DynamoDB audit rows and S3 archive objects.

This verifier uses a separate auditor identity with only DynamoDB Query on
GSI1 and S3 GetObject on the audit-events prefix. It does not mutate AWS state
or print audit payloads. Key-only reconciliation remains a separate command.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .audit_exporter import _ALLOWED_FIELDS, _audit_document, _object_key


def _is_missing_object(exc: Exception) -> bool:
    response = getattr(exc, "response", None)
    if not isinstance(response, Mapping):
        return False
    metadata = response.get("ResponseMetadata", {})
    error = response.get("Error", {})
    status = metadata.get("HTTPStatusCode") if isinstance(metadata, Mapping) else None
    code = error.get("Code") if isinstance(error, Mapping) else None
    return status == 404 or code in {"NoSuchKey", "NotFound", "404"}


def _canonical_bytes(item: Mapping[str, Any]) -> bytes:
    """Recreate the exporter's documented canonical JSON representation."""
    document = _audit_document(item)
    return json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def verify_audit_archive(
    table: Any,
    s3_client: Any,
    *,
    bucket: str,
    prefix: str = "audit-events",
    trace_id: str | None = None,
    page_size: int = 1000,
    sample_limit: int = 25,
) -> dict[str, Any]:
    """Compare source audit rows with archived object bytes without writes."""
    if not isinstance(bucket, str) or not bucket.strip():
        raise ValueError("An S3 archive bucket is required")
    normalized_prefix = prefix.strip("/")
    if not normalized_prefix or any(
        part in {".", ".."} for part in normalized_prefix.split("/")
    ):
        raise ValueError("Invalid audit archive prefix")
    if not 1 <= page_size <= 1000:
        raise ValueError("page_size must be between 1 and 1000")
    if sample_limit < 0:
        raise ValueError("sample_limit cannot be negative")
    if trace_id is not None and (
        not isinstance(trace_id, str)
        or not 1 <= len(trace_id) <= 128
        or trace_id.strip() != trace_id
    ):
        raise ValueError("trace_id must contain 1–128 trimmed characters")

    fields = ("entity_type", *_ALLOWED_FIELDS)
    aliases = {"#gsi1pk": "GSI1PK"}
    aliases.update({f"#{field}": field for field in fields})
    projection = ", ".join(f"#{field}" for field in fields)
    query: dict[str, Any] = {
        "IndexName": "GSI1",
        "KeyConditionExpression": "#gsi1pk = :audit_partition",
        "ProjectionExpression": projection,
        "ExpressionAttributeNames": aliases,
        "ExpressionAttributeValues": {":audit_partition": "AUDIT"},
        "Limit": page_size,
    }

    checked = 0
    verified = 0
    missing = 0
    mismatched = 0
    read_errors = 0
    invalid_records = 0
    duplicate_event_ids = 0
    seen_event_ids: set[str] = set()
    hash_samples: list[dict[str, str]] = []
    error_samples: list[dict[str, str]] = []
    last_evaluated_key: dict[str, Any] | None = None

    while True:
        if last_evaluated_key:
            query["ExclusiveStartKey"] = last_evaluated_key
        response = table.query(**query)

        for item in response.get("Items", []):
            if (
                trace_id is not None
                and isinstance(item, Mapping)
                and item.get("trace_id") != trace_id
            ):
                continue
            if not isinstance(item, Mapping) or item.get("entity_type") != "AUDIT":
                invalid_records += 1
                continue

            event_id = item.get("event_id")
            actual_trace_id = item.get("trace_id")
            try:
                if not isinstance(event_id, str) or not event_id:
                    raise ValueError("Missing event ID")
                key = _object_key(
                    item["created_at"],
                    event_id,
                    normalized_prefix,
                )
                expected_body = _canonical_bytes(item)
            except (KeyError, TypeError, ValueError):
                invalid_records += 1
                if len(error_samples) < sample_limit:
                    error_samples.append({
                        "event_id": event_id[:128] if isinstance(event_id, str) else "[missing]",
                        "error_type": "InvalidAuditRecord",
                    })
                continue

            if event_id in seen_event_ids:
                duplicate_event_ids += 1
            seen_event_ids.add(event_id)
            checked += 1

            try:
                result = s3_client.get_object(Bucket=bucket, Key=key)
                body_stream = result.get("Body")
                if body_stream is None:
                    raise ValueError("S3 GetObject response has no body")
                try:
                    actual_body = body_stream.read()
                finally:
                    close = getattr(body_stream, "close", None)
                    if callable(close):
                        close()
                if not isinstance(actual_body, bytes):
                    raise TypeError("S3 object body is not bytes")
            except Exception as exc:
                if _is_missing_object(exc):
                    missing += 1
                    status = "MissingObject"
                else:
                    read_errors += 1
                    status = type(exc).__name__
                if len(error_samples) < sample_limit:
                    error_samples.append({
                        "event_id": event_id,
                        "trace_id": str(actual_trace_id or ""),
                        "key": key,
                        "error_type": status,
                    })
                continue

            expected_hash = hashlib.sha256(expected_body).hexdigest()
            actual_hash = hashlib.sha256(actual_body).hexdigest()
            if expected_body == actual_body:
                verified += 1
                status = "verified"
            else:
                mismatched += 1
                status = "mismatch"

            if len(hash_samples) < sample_limit:
                hash_samples.append({
                    "event_id": event_id,
                    "trace_id": str(actual_trace_id or ""),
                    "key": key,
                    "status": status,
                    "expected_sha256": expected_hash,
                    "actual_sha256": actual_hash,
                })

        last_evaluated_key = response.get("LastEvaluatedKey")
        if not last_evaluated_key:
            break

    no_trace_matches = trace_id is not None and checked == 0
    return {
        "source_audit_events_checked": checked,
        "verified_objects": verified,
        "missing_objects": missing,
        "content_mismatches": mismatched,
        "object_read_errors": read_errors,
        "invalid_audit_records": invalid_records,
        "duplicate_event_ids": duplicate_event_ids,
        "no_matching_trace": no_trace_matches,
        "hash_samples": hash_samples,
        "error_samples": error_samples,
        "ok": (
            not no_trace_matches
            and invalid_records == 0
            and duplicate_event_ids == 0
            and missing == 0
            and mismatched == 0
            and read_errors == 0
            and verified == checked
        ),
        "consistency_note": (
            "GSI1 is eventually consistent. Run after the stream exporter has "
            "caught up; repeat after a short delay if the requested trace is not visible."
        ),
        "verification_note": (
            "Object bytes are compared with the canonical allowlisted/redacted "
            "JSON projection from the source audit row. Hashes are evidence "
            "summaries; the report intentionally omits audit payloads."
        ),
    }


def verify(
    *,
    table_name: str,
    bucket: str,
    prefix: str = "audit-events",
    region: str | None = None,
    trace_id: str | None = None,
) -> dict[str, Any]:
    import boto3

    session = boto3.session.Session(region_name=region)
    table = session.resource("dynamodb").Table(table_name)
    s3_client = session.client("s3")
    return verify_audit_archive(
        table,
        s3_client,
        bucket=bucket,
        prefix=prefix,
        trace_id=trace_id,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only byte verification of DynamoDB audit events against the S3 archive."
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
    parser.add_argument("--trace-id")
    parser.add_argument("--report-file", type=Path)
    args = parser.parse_args(argv)
    if not args.table_name or not args.bucket:
        parser.error(
            "Provide --table-name and --bucket or set the corresponding SHADOW_HUNTER variables"
        )

    try:
        report = verify(
            table_name=args.table_name,
            bucket=args.bucket,
            prefix=args.prefix,
            region=args.region,
            trace_id=args.trace_id,
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
