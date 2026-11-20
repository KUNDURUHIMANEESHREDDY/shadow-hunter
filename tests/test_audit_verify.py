from __future__ import annotations

import io
import json

from shadow_hunter.audit_exporter import _audit_document, _object_key
from shadow_hunter.audit_verify import verify_audit_archive


class FakeTable:
    def __init__(self, items):
        self.items = items
        self.calls = 0
        self.last_query = None

    def query(self, **kwargs):
        self.calls += 1
        self.last_query = kwargs
        return {"Items": self.items}


class MissingObject(Exception):
    def __init__(self):
        self.response = {
            "ResponseMetadata": {"HTTPStatusCode": 404},
            "Error": {"Code": "NoSuchKey"},
        }


class FakeS3:
    def __init__(self, objects):
        self.objects = objects

    def get_object(self, *, Bucket, Key):
        if Key not in self.objects:
            raise MissingObject()
        return {"Body": io.BytesIO(self.objects[Key])}


def audit_item(event_id="event-1", trace_id="trace-1"):
    return {
        "entity_type": "AUDIT",
        "event_id": event_id,
        "trace_id": trace_id,
        "request_id": "request-1",
        "event_type": "POLICY_DECISION",
        "decision": "DENY",
        "reason_code": "RESOURCE_OWNER_MISMATCH",
        "actor_id": "customer-1",
        "tenant_id": "tenant-1",
        "resource_id": "order-other",
        "action_digest": "a" * 64,
        "policy_id": "support-refund-baseline",
        "policy_version": "0.1.0",
        "details": {"tool_name": "get_order"},
        "created_at": "2026-11-20T12:30:00+00:00",
    }


def canonical_body(item):
    return json.dumps(
        _audit_document(item),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def test_verifier_checks_exact_archive_bytes_and_emits_hashes():
    item = audit_item()
    key = _object_key(item["created_at"], item["event_id"])
    report = verify_audit_archive(
        FakeTable([item]),
        FakeS3({key: canonical_body(item)}),
        bucket="audit-bucket",
    )
    assert report["ok"] is True
    assert report["source_audit_events_checked"] == 1
    assert report["verified_objects"] == 1
    assert report["hash_samples"][0]["status"] == "verified"
    assert report["hash_samples"][0]["expected_sha256"] == report["hash_samples"][0]["actual_sha256"]


def test_verifier_detects_archive_content_mismatch():
    item = audit_item()
    key = _object_key(item["created_at"], item["event_id"])
    report = verify_audit_archive(
        FakeTable([item]),
        FakeS3({key: b'{"decision":"ALLOW"}'}),
        bucket="audit-bucket",
    )
    assert report["ok"] is False
    assert report["content_mismatches"] == 1
    assert report["hash_samples"][0]["expected_sha256"] != report["hash_samples"][0]["actual_sha256"]


def test_verifier_reports_missing_archive_object():
    report = verify_audit_archive(
        FakeTable([audit_item()]),
        FakeS3({}),
        bucket="audit-bucket",
    )
    assert report["ok"] is False
    assert report["missing_objects"] == 1


def test_verifier_can_limit_check_to_a_single_trace():
    selected = audit_item(trace_id="trace-selected")
    key = _object_key(selected["created_at"], selected["event_id"])
    table = FakeTable([selected])
    report = verify_audit_archive(
        table,
        FakeS3({key: canonical_body(selected)}),
        bucket="audit-bucket",
        trace_id="trace-selected",
    )
    assert report["ok"] is True
    assert report["source_audit_events_checked"] == 1
    assert report["no_matching_trace"] is False
    assert "IndexName" not in table.last_query
    assert table.last_query["ExpressionAttributeNames"]["#pk"] == "PK"
    assert table.last_query["ExpressionAttributeValues"][":trace_partition"] == "TRACE#trace-selected"


def test_verifier_fails_when_trace_has_no_matching_rows():
    report = verify_audit_archive(
        FakeTable([]),
        FakeS3({}),
        bucket="audit-bucket",
        trace_id="trace-missing",
    )
    assert report["ok"] is False
    assert report["no_matching_trace"] is True


def test_verifier_rejects_invalid_records_without_exposing_payload():
    report = verify_audit_archive(
        FakeTable([{"entity_type": "AUDIT", "event_id": "event-invalid"}]),
        FakeS3({}),
        bucket="audit-bucket",
    )
    assert report["ok"] is False
    assert report["invalid_audit_records"] == 1
