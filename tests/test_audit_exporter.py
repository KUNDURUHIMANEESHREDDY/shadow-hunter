from __future__ import annotations

from decimal import Decimal

import pytest

from shadow_hunter.audit_exporter import (
    _audit_document,
    _is_existing_object,
    _json_safe,
    _object_key,
)


def test_object_key_is_deterministic_and_uses_utc_date():
    assert _object_key(
        "2026-11-20T23:30:00-02:00",
        "event-123",
    ) == "audit-events/2026/11/21/event-123.json"


def test_object_key_rejects_unsafe_event_id_and_path_prefix():
    with pytest.raises(ValueError):
        _object_key("2026-11-20T10:00:00+00:00", "../escape")
    with pytest.raises(ValueError):
        _object_key("2026-11-20T10:00:00+00:00", "event-1", "../escape")


def test_json_safe_redacts_nested_token_and_secret_fields():
    value = {
        "amount_minor": Decimal("1250"),
        "details": {
            "approval_id": "approval-1",
            "approval_token": "must-not-escape",
            "nested": [{"client_secret": "hidden", "status": "APPROVED"}],
        },
    }

    assert _json_safe(value) == {
        "amount_minor": 1250,
        "details": {
            "approval_id": "approval-1",
            "approval_token": "[REDACTED]",
            "nested": [{"client_secret": "[REDACTED]", "status": "APPROVED"}],
        },
    }


def test_audit_document_projects_only_allowlisted_fields():
    document = _audit_document(
        {
            "PK": "TRACE#trace-1",
            "SK": "EVENT#...",
            "entity_type": "AUDIT",
            "event_id": "event-1",
            "trace_id": "trace-1",
            "request_id": "request-1",
            "event_type": "REFUND_EXECUTED",
            "created_at": "2026-11-20T10:00:00+00:00",
            "details": {"approval_token": "hidden"},
            "token_hash": "must-not-export",
        }
    )

    assert "PK" not in document
    assert "token_hash" not in document
    assert document["details"]["approval_token"] == "[REDACTED]"


def test_existing_object_status_is_treated_as_successful_replay():
    duplicate = Exception("already exists")
    duplicate.response = {
        "ResponseMetadata": {"HTTPStatusCode": 412},
        "Error": {"Code": "PreconditionFailed"},
    }
    conflict = Exception("conditional write conflict")
    conflict.response = {
        "ResponseMetadata": {"HTTPStatusCode": 409},
        "Error": {"Code": "ConditionalRequestConflict"},
    }

    assert _is_existing_object(duplicate) is True
    assert _is_existing_object(conflict) is False
