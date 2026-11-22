"""Bounded smoke test for a live *staging* Shadow Hunter AWS data stack.

Never runs automatically. Uses only synthetic identifiers and the demo ledger.
Does not create CloudFormation resources, real refunds, or identities.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from shadow_hunter.dynamodb_store import DynamoDBStore
from shadow_hunter.policy import Principal


def run(region: str, stack_name: str) -> None:
    if stack_name != "shadow-hunter-data-staging":
        raise ValueError("Smoke test is restricted to shadow-hunter-data-staging")
    cf = boto3.client("cloudformation", region_name=region)
    stack = cf.describe_stacks(StackName=stack_name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise RuntimeError("Staging stack must be CREATE_COMPLETE")
    outputs = {x["OutputKey"]: x["OutputValue"] for x in stack["Outputs"]}
    table_name = outputs["TableName"]
    archive = outputs["AuditArchiveBucketName"]
    if table_name != "shadow-hunter-staging" or not archive.endswith("-staging"):
        raise RuntimeError("Refusing a non-staging table or archive")

    ddb = boto3.client("dynamodb", region_name=region)
    definition = ddb.describe_table(TableName=table_name)["Table"]
    assert definition["TableStatus"] == "ACTIVE"
    assert definition["StreamSpecification"]["StreamEnabled"]
    assert definition["StreamSpecification"]["StreamViewType"] == "NEW_IMAGE"
    assert {g["IndexName"] for g in definition["GlobalSecondaryIndexes"]} == {"GSI1"}
    assert definition["DeletionProtectionEnabled"]

    s3 = boto3.client("s3", region_name=region)
    lock = s3.get_object_lock_configuration(Bucket=archive)["ObjectLockConfiguration"]
    assert lock["Rule"]["DefaultRetention"]["Mode"] == "GOVERNANCE"
    assert lock["Rule"]["DefaultRetention"]["Days"] == 1

    store = DynamoDBStore(table_name, region=region)
    run_id = "staging-smoke-" + uuid.uuid4().hex
    order_id = run_id + "-order"
    trace_id = run_id + "-trace"
    store.add_order(
        order_id=order_id,
        tenant_id="staging-synthetic-tenant",
        customer_id="staging-synthetic-customer",
        currency="USD",
        refundable_minor=4000,
    )
    customer = Principal(
        "staging-synthetic-requester",
        "staging-synthetic-tenant",
        "staging-synthetic-customer",
        True,
    )
    refund = store.create_refund_request(
        principal=customer,
        order=store.get_order(order_id),
        amount_minor=1200,
        currency="USD",
        reason="Synthetic staging smoke test",
        idempotency_key=run_id,
        action_digest=run_id + "-digest",
        policy_id="support-refund-baseline",
        policy_version="0.1.0",
        policy_decision="ESCALATE",
        policy_reason_code="HUMAN_APPROVAL_REQUIRED",
    )
    refund_id = refund["refund_request_id"]
    approval_id = store.create_approval(
        refund_id, ttl_seconds=600, trace_id=trace_id, request_id=run_id,
    )
    capability = store.approve(approval_id, "staging-synthetic-approver")
    result = store.execute_refund(
        refund_request_id=refund_id,
        approval_token=capability,
        operator_id="staging-synthetic-executor",
        policy_id="support-refund-baseline",
        policy_version="0.1.0",
    )
    assert result["status"] == "EXECUTED"
    assert result["idempotent_replay"] is False
    assert store.get_order(order_id).refundable_minor == 2800
    assert store.execute_refund(
        refund_request_id=refund_id,
        approval_token=capability,
        operator_id="staging-synthetic-executor",
        policy_id="support-refund-baseline",
        policy_version="0.1.0",
    )["idempotent_replay"] is True

    events = store.get_trace_events(trace_id)
    assert {e["event_type"] for e in events} >= {
        "APPROVAL_REQUESTED", "APPROVAL_GRANTED", "REFUND_EXECUTED"
    }
    date = datetime.now(timezone.utc).strftime("%Y/%m/%d")
    archived = set()
    # DynamoDB Streams + Lambda delivery is eventually consistent.
    for _ in range(15):
        for event in events:
            key = f"audit-events/{date}/{event['event_id']}.json"
            try:
                s3.head_object(Bucket=archive, Key=key)
                archived.add(event["event_id"])
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") not in ("404", "NotFound"):
                    raise
        if len(archived) == len(events):
            break
        time.sleep(2)

    summary = {
        "stack_status": stack["StackStatus"],
        "table": table_name,
        "audit_archive": archive,
        "refund_state": result["status"],
        "idempotent_replay_verified": True,
        "remaining_minor": store.get_order(order_id).refundable_minor,
        "trace_events": len(events),
        "archived_events": len(archived),
        "audit_export_complete": len(archived) == len(events),
        "synthetic_only": True,
    }
    print(json.dumps(summary, indent=2))
    if len(archived) != len(events):
        raise RuntimeError("Audit events are not all visible in S3; inspect stream mapping/DLQ")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", default="ap-southeast-2")
    parser.add_argument("--stack-name", default="shadow-hunter-data-staging")
    parser.add_argument("--apply", action="store_true", help="Write synthetic staging records")
    args = parser.parse_args()
    if not args.apply:
        print("Dry run: add --apply to create synthetic staging test records.")
        sys.exit(0)
    run(args.region, args.stack_name)
