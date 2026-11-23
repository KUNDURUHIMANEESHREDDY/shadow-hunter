"""Integrity gate tests against synthetic DynamoDB and S3 (Moto only)."""
from __future__ import annotations

import json

import boto3
import pytest

moto = pytest.importorskip("moto")
from moto import mock_aws

from scripts.security_audit_gate import assess_archive
from shadow_hunter.audit_exporter import _audit_document, _object_key


@pytest.fixture
def archive():
    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="security-audit-fixture",
            BillingMode="PAY_PER_REQUEST",
            KeySchema=[
                {"AttributeName": "PK", "KeyType": "HASH"},
                {"AttributeName": "SK", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "PK", "AttributeType": "S"},
                {"AttributeName": "SK", "AttributeType": "S"},
                {"AttributeName": "GSI1PK", "AttributeType": "S"},
                {"AttributeName": "GSI1SK", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[{
                "IndexName": "GSI1",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }],
        )
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="shadow-hunter-audit-test")
        yield table, s3


def add_event(table, s3, *, event_id="event-001", sk="001", archive=True):
    item = {
        "PK": "TRACE#security-test",
        "SK": f"AUDIT#{sk}",
        "GSI1PK": "AUDIT",
        "GSI1SK": f"2026-11-23T12:00:00+00:00#{sk}",
        "entity_type": "AUDIT",
        "event_id": event_id,
        "trace_id": "security-test",
        "request_id": "synthetic-request",
        "created_at": "2026-11-23T12:00:00+00:00",
        "event_type": "POLICY_DECISION",
        "decision": "DENY",
        "reason_code": "RESOURCE_TENANT_MISMATCH",
        "actor_id": "synthetic-caller",
        "tenant_id": "tenant-one",
        "resource_id": "foreign-order",
        "details": {"test": "synthetic"},
    }
    table.put_item(Item=item)
    key = _object_key(item["created_at"], item["event_id"])
    if archive:
        body = json.dumps(
            _audit_document(item),
            ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
        s3.put_object(Bucket="shadow-hunter-audit-test", Key=key, Body=body)
    return key


def check(archive, *, page_size=1000):
    table, s3 = archive
    return assess_archive(
        table, s3, bucket="shadow-hunter-audit-test", page_size=page_size,
    )


def test_gate_accepts_exact_complete_archive_with_pagination(archive):
    table, s3 = archive
    add_event(table, s3, event_id="first", sk="001")
    add_event(table, s3, event_id="second", sk="002")
    report = check(archive, page_size=1)
    assert report["ok"] is True
    assert report["key_reconciliation"]["missing_archive_objects"] == 0
    assert report["key_reconciliation"]["orphaned_archive_objects"] == 0
    assert report["byte_verification"]["verified_objects"] == 2


def test_gate_detects_tampered_event_body_even_when_keys_match(archive):
    table, s3 = archive
    key = add_event(table, s3)
    s3.put_object(
        Bucket="shadow-hunter-audit-test",
        Key=key,
        Body=b'{"decision":"ALLOW"}',
    )
    report = check(archive)
    assert report["ok"] is False
    assert report["key_reconciliation"]["ok"] is True
    assert report["byte_verification"]["content_mismatches"] == 1


def test_gate_detects_missing_archive_object(archive):
    table, s3 = archive
    add_event(table, s3, archive=False)
    report = check(archive)
    assert report["ok"] is False
    assert report["key_reconciliation"]["missing_archive_objects"] == 1
    assert report["byte_verification"]["missing_objects"] == 1


def test_gate_detects_orphaned_archive_object(archive):
    table, s3 = archive
    add_event(table, s3)
    s3.put_object(
        Bucket="shadow-hunter-audit-test",
        Key="audit-events/2026/11/23/extra.json",
        Body=b"{}",
    )
    report = check(archive)
    assert report["ok"] is False
    assert report["key_reconciliation"]["orphaned_archive_objects"] == 1
    assert report["byte_verification"]["ok"] is True


def test_gate_rejects_duplicate_event_ids(archive):
    table, s3 = archive
    add_event(table, s3, event_id="duplicate", sk="001")
    add_event(table, s3, event_id="duplicate", sk="002")
    report = check(archive, page_size=1)
    assert report["ok"] is False
    assert report["key_reconciliation"]["duplicate_event_ids"] == 1
    assert report["byte_verification"]["duplicate_event_ids"] == 1
