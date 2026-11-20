from __future__ import annotations

import json

import pytest

from shadow_hunter.audit_reconcile import compare_archive_keys
from shadow_hunter.audit_replay import (
    parse_failure_envelope,
    select_sequence_range,
)


def test_reconciliation_reports_missing_and_orphaned_keys():
    result = compare_archive_keys(
        ["audit-events/2026/11/20/a.json", "audit-events/2026/11/20/b.json"],
        ["audit-events/2026/11/20/a.json", "audit-events/2026/11/20/orphan.json"],
        sample_limit=5,
    )
    assert result["expected_archive_objects"] == 2
    assert result["actual_archive_objects"] == 2
    assert result["missing_archive_objects"] == 1
    assert result["orphaned_archive_objects"] == 1
    assert result["missing_key_samples"] == ["audit-events/2026/11/20/b.json"]


def test_failure_envelope_extracts_only_stream_range_metadata():
    envelope = {
        "version": "1.0",
        "DDBStreamBatchInfo": {
            "streamArn": "arn:aws:dynamodb:us-east-1:123456789012:table/t/stream/x",
            "shardId": "shardId-001",
            "startSequenceNumber": "100",
            "endSequenceNumber": "105",
        },
        "payload": "not present on an SQS destination",
    }
    parsed = parse_failure_envelope(json.dumps(envelope))
    assert parsed == {
        "stream_arn": envelope["DDBStreamBatchInfo"]["streamArn"],
        "shard_id": "shardId-001",
        "start_sequence": "100",
        "end_sequence": "105",
    }


@pytest.mark.parametrize(
    "body",
    [
        "{}",
        "not-json",
        json.dumps({"DDBStreamBatchInfo": {"streamArn": "x"}}),
        json.dumps({
            "DDBStreamBatchInfo": {
                "streamArn": "x",
                "shardId": "y",
                "startSequenceNumber": "8",
                "endSequenceNumber": "4",
            }
        }),
    ],
)
def test_failure_envelope_rejects_incomplete_or_invalid_metadata(body):
    with pytest.raises(ValueError):
        parse_failure_envelope(body)


def stream_record(sequence: str) -> dict:
    return {"dynamodb": {"SequenceNumber": sequence}}


def test_select_sequence_range_is_inclusive_and_requires_both_boundaries():
    selected = select_sequence_range(
        [stream_record("99"), stream_record("100"), stream_record("104"), stream_record("105"), stream_record("106")],
        start_sequence="100",
        end_sequence="105",
    )
    assert [item["dynamodb"]["SequenceNumber"] for item in selected] == [
        "100", "104", "105"
    ]


def test_select_sequence_range_rejects_expired_or_incomplete_ranges():
    with pytest.raises(LookupError):
        select_sequence_range(
            [stream_record("101"), stream_record("105")],
            start_sequence="100",
            end_sequence="105",
        )
