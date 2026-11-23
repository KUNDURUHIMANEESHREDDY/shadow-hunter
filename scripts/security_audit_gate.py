"""Read-only full-scope audit gate: key reconciliation AND byte verification.

Both checks are necessary: a byte-only verifier cannot detect extra objects;
a key-only verifier cannot detect altered object contents. No AWS writes occur.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from shadow_hunter.audit_reconcile import collect_audit_keys
from shadow_hunter.audit_verify import verify_audit_archive


def assess_archive(
    table: Any,
    s3_client: Any,
    *,
    bucket: str,
    prefix: str = "audit-events",
    page_size: int = 1000,
) -> dict[str, Any]:
    keys = collect_audit_keys(
        table, s3_client, bucket=bucket, prefix=prefix, page_size=page_size,
    )
    content = verify_audit_archive(
        table, s3_client, bucket=bucket, prefix=prefix, page_size=page_size,
    )
    return {
        "ok": keys["ok"] and content["ok"],
        "scope": "all DynamoDB GSI1 AUDIT rows and matching S3 JSON objects",
        "key_reconciliation": keys,
        "byte_verification": content,
        "limitations": (
            "Both sources are compared at read time; DynamoDB GSI1 and stream "
            "export are eventually consistent. This cannot detect coordinated "
            "tampering of both sources, prove historical completeness of the "
            "source log, or certify S3 retention configuration."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only full audit archive key and byte-integrity gate."
    )
    parser.add_argument(
        "--table-name", default=os.environ.get("SHADOW_HUNTER_DYNAMODB_TABLE"),
    )
    parser.add_argument(
        "--bucket", default=os.environ.get("SHADOW_HUNTER_AUDIT_BUCKET"),
    )
    parser.add_argument(
        "--region", default=os.environ.get("AWS_REGION"),
    )
    parser.add_argument(
        "--prefix", default=os.environ.get("SHADOW_HUNTER_AUDIT_PREFIX", "audit-events"),
    )
    parser.add_argument("--page-size", type=int, default=1000)
    parser.add_argument("--report-file", type=Path)
    args = parser.parse_args(argv)
    if not args.table_name or not args.bucket:
        parser.error("--table-name and --bucket (or environment values) are required")
    try:
        import boto3

        session = boto3.session.Session(region_name=args.region)
        report = assess_archive(
            session.resource("dynamodb").Table(args.table_name),
            session.client("s3"),
            bucket=args.bucket,
            prefix=args.prefix,
            page_size=args.page_size,
        )
    except Exception as exc:
        print(
            json.dumps({"ok": False, "error_type": type(exc).__name__}),
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
