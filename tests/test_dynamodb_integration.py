"""End-to-end DynamoDB adapter tests with an isolated AWS-compatible emulator.

Moto intercepts AWS calls; these tests never contact an AWS account.
Run: python -m pytest -q tests/test_dynamodb_integration.py
"""
from __future__ import annotations

import boto3
import pytest

moto = pytest.importorskip("moto")
from moto import mock_aws

from shadow_hunter.dynamodb_store import DynamoDBStore
from shadow_hunter.policy import Principal
from shadow_hunter.store import IdempotencyConflict, StoreError


@pytest.fixture
def dynamodb_store():
    with mock_aws():
        resource = boto3.resource("dynamodb", region_name="us-east-1")
        resource.create_table(
            TableName="shadow-hunter-integration",
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
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI1",
                    "KeySchema": [
                        {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
        )
        yield DynamoDBStore("shadow-hunter-integration", region="us-east-1")


def _seed_refund(store, *, order_id="order-001", key="idempotency-001", amount=1500):
    store.add_order(
        order_id=order_id,
        tenant_id="tenant-001",
        customer_id="customer-001",
        currency="USD",
        refundable_minor=5000,
    )
    principal = Principal("requester-001", "tenant-001", "customer-001", True)
    order = store.get_order(order_id)
    refund = store.create_refund_request(
        principal=principal,
        order=order,
        amount_minor=amount,
        currency="USD",
        reason="Damaged item",
        idempotency_key=key,
        action_digest="digest-" + order_id,
        policy_id="support-refund-baseline",
        policy_version="0.1.0",
        policy_decision="ESCALATE",
        policy_reason_code="HUMAN_APPROVAL_REQUIRED",
    )
    return principal, refund


def test_real_transaction_lifecycle_audit_balance_and_replay(dynamodb_store):
    store = dynamodb_store
    _, refund = _seed_refund(store)
    same_request = store.create_refund_request(
        principal=Principal("requester-001", "tenant-001", "customer-001", True),
        order=store.get_order("order-001"),
        amount_minor=1500,
        currency="USD",
        reason="Damaged item",
        idempotency_key="idempotency-001",
        action_digest="digest-order-001",
        policy_id="support-refund-baseline",
        policy_version="0.1.0",
        policy_decision="ESCALATE",
        policy_reason_code="HUMAN_APPROVAL_REQUIRED",
    )
    assert same_request["refund_request_id"] == refund["refund_request_id"]

    approval_id = store.create_approval(
        refund["refund_request_id"], 600,
        trace_id="trace-lifecycle", request_id="request-lifecycle",
    )
    assert store.create_approval(refund["refund_request_id"], 600) == approval_id
    with pytest.raises(StoreError, match="cannot approve"):
        store.approve(approval_id, "requester-001")

    token = store.approve(approval_id, "operator-001")
    assert token
    with pytest.raises(StoreError, match="token is invalid"):
        store.execute_refund(
            refund_request_id=refund["refund_request_id"],
            approval_token="wrong-token",
            operator_id="operator-002",
            policy_id="support-refund-baseline",
            policy_version="0.1.0",
        )
    params = {
        "refund_request_id": refund["refund_request_id"],
        "approval_token": token,
        "operator_id": "operator-002",
        "policy_id": "support-refund-baseline",
        "policy_version": "0.1.0",
    }
    result = store.execute_refund(**params)
    assert result["status"] == "EXECUTED"
    assert result["idempotent_replay"] is False
    assert store.execute_refund(**params)["idempotent_replay"] is True
    assert store.get_order("order-001").refundable_minor == 3500

    events = store.get_trace_events("trace-lifecycle")
    assert [e["event_type"] for e in events] == [
        "APPROVAL_REQUESTED", "APPROVAL_SELF_APPROVAL_BLOCKED",
        "APPROVAL_GRANTED", "REFUND_EXECUTED",
    ]
    assert all(event["request_id"] == "request-lifecycle" for event in events)
    stats = store.overview()
    assert stats["refund_requests"] == 1
    assert stats["executed_refunds"] == 1
    assert stats["audit_events"] == 4
    assert stats["pending_approvals"] == 0
    assert stats["approved_approvals"] == 0


def test_idempotency_conflict_denied_without_writing_second_refund(dynamodb_store):
    store = dynamodb_store
    principal, _ = _seed_refund(store)
    with pytest.raises(IdempotencyConflict):
        store.create_refund_request(
            principal=principal,
            order=store.get_order("order-001"),
            amount_minor=2000,
            currency="USD",
            reason="Different amount",
            idempotency_key="idempotency-001",
            action_digest="different-digest",
            policy_id="support-refund-baseline",
            policy_version="0.1.0",
            policy_decision="ESCALATE",
            policy_reason_code="HUMAN_APPROVAL_REQUIRED",
        )
    assert store.overview()["refund_requests"] == 1


def test_rejected_approval_never_executes_and_persists_denial(dynamodb_store):
    store = dynamodb_store
    _, refund = _seed_refund(store)
    approval_id = store.create_approval(refund["refund_request_id"], 600)
    store.reject(approval_id, "operator-001", "Not eligible")
    with pytest.raises(StoreError, match="not pending"):
        store.approve(approval_id, "operator-002")
    with pytest.raises(StoreError, match="unused approved capability"):
        store.execute_refund(
            refund_request_id=refund["refund_request_id"],
            approval_token="fake",
            operator_id="operator-002",
            policy_id="support-refund-baseline",
            policy_version="0.1.0",
        )
    assert store.get_order("order-001").refundable_minor == 5000
    assert store.get_refund_request(refund["refund_request_id"])["status"] == "REJECTED"
    assert store.overview()["pending_approvals"] == 0


def test_approval_token_rotation_invalidates_old_token(dynamodb_store):
    store = dynamodb_store
    _, refund = _seed_refund(store)
    approval_id = store.create_approval(refund["refund_request_id"], 600)
    old_token = store.approve(approval_id, "operator-001")
    new_token = store.rotate_approval_token(approval_id, "operator-002")
    assert old_token != new_token
    with pytest.raises(StoreError, match="invalid"):
        store.execute_refund(
            refund_request_id=refund["refund_request_id"],
            approval_token=old_token,
            operator_id="operator-003",
            policy_id="support-refund-baseline",
            policy_version="0.1.0",
        )
    result = store.execute_refund(
        refund_request_id=refund["refund_request_id"],
        approval_token=new_token,
        operator_id="operator-003",
        policy_id="support-refund-baseline",
        policy_version="0.1.0",
    )
    assert result["status"] == "EXECUTED"


def test_nonce_and_operator_evaluation_quota_persist(dynamodb_store):
    store = dynamodb_store
    assert store.claim_a2a_nonce(
        nonce="nonce-001", agent_id="red", message_id="m-001",
        expires_at_epoch=4_000_000_000,
    )
    assert not store.claim_a2a_nonce(
        nonce="nonce-001", agent_id="red", message_id="m-002",
        expires_at_epoch=4_000_000_000,
    )
    store.reserve_agent_evaluation("operator-001", daily_limit=1, cooldown_seconds=0)
    with pytest.raises(StoreError, match="budget"):
        store.reserve_agent_evaluation("operator-001", daily_limit=1, cooldown_seconds=0)
    store.reserve_agent_evaluation("operator-002", daily_limit=1, cooldown_seconds=0)
