"""Export DynamoDB audit INSERT records to an S3 Object Lock archive.

This function is separate from the application Lambda. Its role can read
DynamoDB Streams and PutObject under one archive prefix, but cannot read, list,
delete, or change retention on archived objects.
"""
from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

import boto3
from boto3.dynamodb.types import TypeDeserializer


_LOG = logging.getLogger(__name__)
_LOG.setLevel(logging.INFO)
_DESERIALIZER = TypeDeserializer()

_ALLOWED_FIELDS = (
    "event_id",
    "trace_id",
    "request_id",
    "event_type",
    "decision",
    "reason_code",
    "actor_id",
    "tenant_id",
    "resource_id",
    "action_digest",
    "policy_id",
    "policy_version",
    "details",
    "created_at",
)
_SENSITIVE_KEY_PARTS = (
    "token",
    "secret",
    "password",
    "authorization",
    "credential",
    "api_key",
)
_SAFE_EVENT_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def _json_safe(value: Any) -> Any:
    """Convert DynamoDB values to JSON and redact nested secret-like fields."""
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, Mapping):
        safe: dict[str, Any] = {}
        for key, child in value.items():
            key_text = str(key)
            normalized = key_text.lower().replace("-", "_")
            if any(part in normalized for part in _SENSITIVE_KEY_PARTS):
                safe[key_text] = "[REDACTED]"
            else:
                safe[key_text] = _json_safe(child)
        return safe
    if isinstance(value, (list, tuple)):
        return [_json_safe(child) for child in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"Unsupported audit value type: {type(value).__name__}")


def _deserialize_image(image: Mapping[str, Any]) -> dict[str, Any]:
    return {
        name: _DESERIALIZER.deserialize(attribute_value)
        for name, attribute_value in image.items()
    }


def _audit_document(item: Mapping[str, Any]) -> dict[str, Any]:
    """Project only the approved audit schema into the long-term archive."""
    for required in ("event_id", "trace_id", "request_id", "event_type", "created_at"):
        value = item.get(required)
        if not isinstance(value, str) or not value:
            raise ValueError(f"Audit record is missing required field: {required}")

    projected = {
        field: _json_safe(item[field])
        for field in _ALLOWED_FIELDS
        if field in item
    }
    if not isinstance(projected.get("details", {}), (dict, list)):
        raise ValueError("Audit details must be a structured object or array")
    return projected


def _object_key(
    created_at: str,
    event_id: str,
    prefix: str = "audit-events",
) -> str:
    if not isinstance(event_id, str) or _SAFE_EVENT_ID.fullmatch(event_id) is None:
        raise ValueError("Invalid audit event ID")
    if not isinstance(prefix, str) or not prefix or prefix.startswith("/"):
        raise ValueError("Invalid audit archive prefix")
    if any(part in {".", ".."} for part in prefix.split("/")):
        raise ValueError("Invalid audit archive prefix")

    timestamp = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        raise ValueError("Audit timestamp must include a timezone")
    timestamp = timestamp.astimezone(timezone.utc)
    return f"{prefix.rstrip('/')}/{timestamp:%Y/%m/%d}/{event_id}.json"


def _is_existing_object(exc: Exception) -> bool:
    response = getattr(exc, "response", None)
    if not isinstance(response, Mapping):
        return False
    metadata = response.get("ResponseMetadata", {})
    error = response.get("Error", {})
    status = metadata.get("HTTPStatusCode") if isinstance(metadata, Mapping) else None
    code = error.get("Code") if isinstance(error, Mapping) else None
    return status == 412 or code == "PreconditionFailed"


def _export_record(
    record: Mapping[str, Any],
    *,
    s3_client: Any,
    bucket: str,
    prefix: str,
) -> bool:
    """Return True for exported, duplicate, or irrelevant records."""
    if record.get("eventName") != "INSERT":
        return True

    dynamodb = record.get("dynamodb")
    image = dynamodb.get("NewImage") if isinstance(dynamodb, Mapping) else None
    if not isinstance(image, Mapping):
        raise ValueError("DynamoDB INSERT record has no NewImage")

    item = _deserialize_image(image)
    if item.get("entity_type") != "AUDIT":
        return True

    document = _audit_document(item)
    key = _object_key(document["created_at"], document["event_id"], prefix)
    body = json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")

    try:
        s3_client.put_object(
            Bucket=bucket,
            Key=key,
            Body=body,
            ContentType="application/json",
            ServerSideEncryption="AES256",
            IfNoneMatch="*",
        )
    except Exception as exc:
        if _is_existing_object(exc):
            # A previous attempt wrote this event. The conditional write
            # prevents a retry from creating a replacement object version.
            return True
        raise
    return True


def handler(event: dict[str, Any], context: Any) -> dict[str, list[dict[str, str]]]:
    """Process a DynamoDB Streams batch with partial-failure reporting."""
    if not isinstance(event, Mapping):
        raise ValueError("DynamoDB stream event must be an object")
    records = event.get("Records", [])
    if not isinstance(records, list):
        raise ValueError("DynamoDB stream Records must be a list")
    if not records:
        return {"batchItemFailures": []}

    bucket = os.environ.get("SHADOW_HUNTER_AUDIT_BUCKET", "").strip()
    if not bucket:
        raise RuntimeError("SHADOW_HUNTER_AUDIT_BUCKET is required")
    prefix = os.environ.get("SHADOW_HUNTER_AUDIT_PREFIX", "audit-events").strip("/")
    if not prefix:
        raise RuntimeError("SHADOW_HUNTER_AUDIT_PREFIX must not be empty")

    s3_client = boto3.client("s3")
    failures: list[dict[str, str]] = []

    for record in records:
        dynamodb = record.get("dynamodb", {})
        sequence = (
            dynamodb.get("SequenceNumber")
            if isinstance(dynamodb, Mapping)
            else None
        )
        if not isinstance(sequence, str) or not sequence:
            raise ValueError("DynamoDB stream record has no sequence number")
        try:
            _export_record(
                record,
                s3_client=s3_client,
                bucket=bucket,
                prefix=prefix,
            )
        except Exception as exc:
            # Never log the record payload; it contains customer and audit data.
            _LOG.error(
                "Audit export failed for stream sequence %s (%s)",
                sequence,
                type(exc).__name__,
            )
            failures.append({"itemIdentifier": sequence})

    return {"batchItemFailures": failures}
