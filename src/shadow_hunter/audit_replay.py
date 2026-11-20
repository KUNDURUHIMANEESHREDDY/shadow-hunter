"""Dry-run-first replay of DynamoDB Stream audit-export DLQ messages.

Lambda's SQS on-failure destination contains failed-batch metadata rather than
the original stream records. This tool fetches the recorded sequence range
from the stream, reuses the same conditional S3 exporter, and deletes a DLQ
message only after the entire range is exported successfully.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Mapping
from typing import Any


def parse_failure_envelope(body: str) -> dict[str, str]:
    try:
        envelope = json.loads(body)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("DLQ message body is not valid JSON") from exc
    if not isinstance(envelope, Mapping):
        raise ValueError("DLQ envelope must be an object")
    batch = envelope.get("DDBStreamBatchInfo")
    if not isinstance(batch, Mapping):
        raise ValueError("DLQ envelope has no DDBStreamBatchInfo")
    values = {
        "stream_arn": batch.get("streamArn"),
        "shard_id": batch.get("shardId"),
        "start_sequence": batch.get("startSequenceNumber"),
        "end_sequence": batch.get("endSequenceNumber"),
    }
    if any(not isinstance(value, str) or not value for value in values.values()):
        raise ValueError("DLQ envelope is missing stream range metadata")
    try:
        start = int(values["start_sequence"])
        end = int(values["end_sequence"])
    except ValueError as exc:
        raise ValueError("DLQ sequence numbers must be numeric strings") from exc
    if start > end:
        raise ValueError("DLQ sequence range is reversed")
    return values


def select_sequence_range(
    records: list[dict[str, Any]],
    *,
    start_sequence: str,
    end_sequence: str,
) -> list[dict[str, Any]]:
    """Select an inclusive sequence range and require both boundary records."""
    start = int(start_sequence)
    end = int(end_sequence)
    selected: list[dict[str, Any]] = []
    for record in records:
        dynamodb = record.get("dynamodb")
        sequence = dynamodb.get("SequenceNumber") if isinstance(dynamodb, Mapping) else None
        if not isinstance(sequence, str):
            continue
        number = int(sequence)
        if start <= number <= end:
            selected.append(record)
    if not selected:
        raise LookupError("No stream records remain for the failed sequence range")
    sequences = [
        int(record["dynamodb"]["SequenceNumber"])
        for record in selected
    ]
    if sequences[0] != start or sequences[-1] != end:
        raise LookupError(
            "The failed stream sequence range is no longer fully available"
        )
    return selected


def fetch_failed_range(
    streams_client: Any,
    *,
    stream_arn: str,
    shard_id: str,
    start_sequence: str,
    end_sequence: str,
    max_pages: int = 60,
) -> list[dict[str, Any]]:
    response = streams_client.get_shard_iterator(
        StreamArn=stream_arn,
        ShardId=shard_id,
        ShardIteratorType="AT_SEQUENCE_NUMBER",
        SequenceNumber=start_sequence,
    )
    iterator = response.get("ShardIterator")
    if not iterator:
        raise LookupError("DynamoDB Streams did not return a shard iterator")

    collected: list[dict[str, Any]] = []
    found_end = False
    end_number = int(end_sequence)

    for _ in range(max_pages):
        page = streams_client.get_records(
            ShardIterator=iterator,
            Limit=1000,
        )
        records = page.get("Records", [])
        for record in records:
            dynamodb = record.get("dynamodb")
            sequence = dynamodb.get("SequenceNumber") if isinstance(dynamodb, Mapping) else None
            if not isinstance(sequence, str):
                continue
            number = int(sequence)
            if number < int(start_sequence):
                continue
            if number > end_number:
                found_end = False
                break
            collected.append(record)
            if number == end_number:
                found_end = True
                break
        if found_end:
            break
        iterator = page.get("NextShardIterator")
        if not iterator:
            break
        if not records:
            time.sleep(0.5)

    if not found_end:
        raise LookupError(
            "Could not retrieve the complete failed range; stream retention may have expired"
        )
    return select_sequence_range(
        collected,
        start_sequence=start_sequence,
        end_sequence=end_sequence,
    )


def replay_messages(
    *,
    sqs_client: Any,
    streams_client: Any,
    s3_client: Any,
    queue_url: str,
    bucket: str,
    prefix: str,
    max_messages: int = 10,
    visibility_timeout: int = 120,
    apply: bool = False,
) -> dict[str, Any]:
    from .audit_exporter import _export_record

    if not 1 <= max_messages <= 10:
        raise ValueError("max_messages must be between 1 and 10")
    response = sqs_client.receive_message(
        QueueUrl=queue_url,
        MaxNumberOfMessages=max_messages,
        VisibilityTimeout=visibility_timeout,
        WaitTimeSeconds=2,
    )
    messages = response.get("Messages", [])
    outcomes: list[dict[str, Any]] = []

    for message in messages:
        receipt = message.get("ReceiptHandle")
        message_id = message.get("MessageId")
        try:
            failure = parse_failure_envelope(message.get("Body", ""))
            records = fetch_failed_range(
                streams_client,
                stream_arn=failure["stream_arn"],
                shard_id=failure["shard_id"],
                start_sequence=failure["start_sequence"],
                end_sequence=failure["end_sequence"],
            )
            if apply:
                for record in records:
                    _export_record(
                        record,
                        s3_client=s3_client,
                        bucket=bucket,
                        prefix=prefix,
                    )
                sqs_client.delete_message(
                    QueueUrl=queue_url,
                    ReceiptHandle=receipt,
                )
                status = "replayed_and_deleted"
            else:
                sqs_client.change_message_visibility(
                    QueueUrl=queue_url,
                    ReceiptHandle=receipt,
                    VisibilityTimeout=0,
                )
                status = "dry_run_available"
            outcomes.append(
                {
                    "message_id": message_id,
                    "status": status,
                    "records_retrieved": len(records),
                    "start_sequence": failure["start_sequence"],
                    "end_sequence": failure["end_sequence"],
                }
            )
        except Exception as exc:
            # Keep the failed message in the DLQ. Do not log its body or stream
            # records because they can contain customer and audit data.
            if receipt:
                try:
                    sqs_client.change_message_visibility(
                        QueueUrl=queue_url,
                        ReceiptHandle=receipt,
                        VisibilityTimeout=visibility_timeout,
                    )
                except Exception:
                    pass
            outcomes.append(
                {
                    "message_id": message_id,
                    "status": "failed_message_retained",
                    "error_type": type(exc).__name__,
                }
            )

    return {
        "dry_run": not apply,
        "messages_received": len(messages),
        "messages_replayed": sum(
            item["status"] == "replayed_and_deleted" for item in outcomes
        ),
        "messages_failed": sum(
            item["status"] == "failed_message_retained" for item in outcomes
        ),
        "outcomes": outcomes,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Inspect or replay failed audit-export batches from the SQS DLQ."
    )
    parser.add_argument(
        "--queue-url",
        default=os.environ.get("SHADOW_HUNTER_AUDIT_DLQ_URL"),
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
    parser.add_argument("--max-messages", type=int, default=10)
    parser.add_argument("--visibility-timeout", type=int, default=120)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write missing audit objects and delete DLQ messages only after success.",
    )
    args = parser.parse_args(argv)
    if not args.queue_url or not args.bucket:
        parser.error(
            "Provide --queue-url and --bucket or set the corresponding SHADOW_HUNTER variables"
        )

    try:
        import boto3

        session = boto3.session.Session(region_name=args.region)
        result = replay_messages(
            sqs_client=session.client("sqs"),
            streams_client=session.client("dynamodbstreams"),
            s3_client=session.client("s3"),
            queue_url=args.queue_url,
            bucket=args.bucket,
            prefix=args.prefix,
            max_messages=args.max_messages,
            visibility_timeout=args.visibility_timeout,
            apply=args.apply,
        )
    except Exception as exc:
        print(
            json.dumps(
                {"dry_run": not args.apply, "error_type": type(exc).__name__},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["messages_failed"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
