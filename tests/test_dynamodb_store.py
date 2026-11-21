from __future__ import annotations

from datetime import timedelta

import pytest

from shadow_hunter.dynamodb_store import DynamoDBStore
from shadow_hunter.store import StoreError, utc_now


def test_dynamodb_backend_requires_explicit_table_name(monkeypatch):
    monkeypatch.delenv("SHADOW_HUNTER_DYNAMODB_TABLE", raising=False)

    with pytest.raises(StoreError, match="SHADOW_HUNTER_DYNAMODB_TABLE"):
        DynamoDBStore.from_environment()


def test_public_projection_never_exposes_capability_hashes():
    item = {
        "PK": "APPROVAL#approval-1",
        "SK": "META",
        "approval_id": "approval-1",
        "status": "APPROVED",
        "token_hash": "private-hash",
        "consumed_token_hash": "private-consumed-hash",
        "amount_minor": 2500,
    }

    public = DynamoDBStore._public(item)

    assert public == {
        "approval_id": "approval-1",
        "status": "APPROVED",
        "amount_minor": 2500,
    }



class _ConditionalCheckFailed(Exception):
    response = {"Error": {"Code": "ConditionalCheckFailedException"}}


class _FakeNonceTable:
    def __init__(self, *, fail_condition=False):
        self.calls = []
        self.fail_condition = fail_condition

    def put_item(self, **kwargs):
        self.calls.append(kwargs)
        if self.fail_condition:
            raise _ConditionalCheckFailed()


def test_dynamodb_a2a_nonce_claim_uses_expiring_conditional_write():
    store = object.__new__(DynamoDBStore)
    table = _FakeNonceTable()
    store._table = table

    accepted = store.claim_a2a_nonce(
        nonce="nonce-unique-01",
        agent_id="red-agent",
        message_id="message-01",
        expires_at_epoch=4_000_000_000,
    )

    assert accepted is True
    call = table.calls[0]
    assert call["Item"]["PK"] == "A2A_NONCE#nonce-unique-01"
    assert call["Item"]["ttl_epoch"] == 4_000_000_000
    assert "attribute_not_exists(PK)" in call["ConditionExpression"]


def test_dynamodb_a2a_nonce_claim_rejects_existing_unexpired_nonce():
    store = object.__new__(DynamoDBStore)
    store._table = _FakeNonceTable(fail_condition=True)

    accepted = store.claim_a2a_nonce(
        nonce="nonce-replayed-01",
        agent_id="red-agent",
        message_id="message-02",
        expires_at_epoch=4_000_000_000,
    )

    assert accepted is False


class _FakeTransactClient:
    def __init__(self):
        self.calls = []

    def transact_write_items(self, **kwargs):
        self.calls.append(kwargs)


def _fake_pending_approval_store(principal_id: str):
    store = object.__new__(DynamoDBStore)
    store.table_name = "shadow-hunter-tests"
    store._client = _FakeTransactClient()
    approval = {
        "PK": "APPROVAL#approval-1",
        "SK": "META",
        "approval_id": "approval-1",
        "refund_request_id": "refund-1",
        "trace_id": "trace-1",
        "request_id": "request-1",
        "tenant_id": "tenant-1",
        "principal_id": principal_id,
        "action_digest": "action-digest",
        "policy_id": "support-refund-baseline",
        "policy_version": "0.1.0",
        "expires_at": (utc_now() + timedelta(minutes=10)).isoformat(
            timespec="microseconds"
        ),
        "status": "PENDING",
    }
    audit_attempts = []
    store._get_item = lambda *_args, **_kwargs: dict(approval)
    store._audit_item = lambda **kwargs: dict(kwargs)
    store._tx_update = lambda key, **kwargs: {
        "Update": {"Key": dict(key), **kwargs}
    }
    store._tx_put = lambda item: {"Put": dict(item)}
    store._stats_tx = lambda deltas: {"Stats": dict(deltas)}
    store.audit_attempts = audit_attempts
    store.append_audit = lambda **kwargs: audit_attempts.append(dict(kwargs))
    return store, approval


def test_dynamodb_rejects_self_approval_and_records_denial():
    store, _ = _fake_pending_approval_store("requesting-operator")

    with pytest.raises(StoreError, match="cannot approve their own"):
        store.approve("approval-1", "requesting-operator")

    assert store._client.calls == []
    assert len(store.audit_attempts) == 1
    assert store.audit_attempts[0]["event_type"] == "APPROVAL_SELF_APPROVAL_BLOCKED"
    assert store.audit_attempts[0]["decision"] == "DENY"
    assert store.audit_attempts[0]["reason_code"] == "MAKER_CHECKER_VIOLATION"


def test_dynamodb_approval_condition_requires_a_different_principal():
    store, _ = _fake_pending_approval_store("requesting-customer")

    token = store.approve("approval-1", "independent-operator")

    assert token
    assert len(store._client.calls) == 1
    update = store._client.calls[0]["TransactItems"][0]["Update"]
    assert "principal_id <> :approver" in update["condition_expression"]
    assert update["values"][":approver"] == "independent-operator"
    assert store.audit_attempts == []



class _ApprovalItemTable:
    def __init__(self, item=None):
        self.item = item

    def get_item(self, **kwargs):
        return {"Item": self.item} if self.item is not None else {}


def _dynamo_stateful_store(item=None):
    from boto3.dynamodb.types import TypeSerializer

    store = object.__new__(DynamoDBStore)
    store.table_name = "shadow-hunter-tests"
    store._serializer = TypeSerializer()
    store._client = _FakeTransactClient()
    store._table = _ApprovalItemTable(item)
    return store


def test_dynamodb_approval_token_rotation_is_conditional_and_audited():
    approval = {
        "PK": "APPROVAL#approval-1",
        "SK": "META",
        "approval_id": "approval-1",
        "refund_request_id": "refund-1",
        "principal_id": "customer-1",
        "tenant_id": "tenant-1",
        "trace_id": "trace-1",
        "request_id": "request-1",
        "action_digest": "digest",
        "policy_id": "policy",
        "policy_version": "1",
        "status": "APPROVED",
        "token_hash": "hash-from-read",
        "expires_at": "9999-12-31T23:59:59.000000+00:00",
    }
    store = _dynamo_stateful_store(approval)

    replacement = store.rotate_approval_token("approval-1", "operator-2")

    assert replacement
    actions = store._client.calls[0]["TransactItems"]
    update = next(item["Update"] for item in actions if "Update" in item)
    assert update["ConditionExpression"] == (
        "#status = :approved AND expires_at > :now "
        "AND token_hash = :previous_token_hash"
    )
    assert update["ExpressionAttributeValues"][":previous_token_hash"]["S"] == "hash-from-read"
    event = next(item["Put"]["Item"] for item in actions if "Put" in item)
    assert event["event_type"]["S"] == "APPROVAL_TOKEN_ROTATED"
    assert event["actor_id"]["S"] == "operator-2"
    assert replacement not in str(event)


def test_dynamodb_evaluation_budget_reserves_atomically_per_operator():
    store = _dynamo_stateful_store()

    store.reserve_agent_evaluation(
        "operator-1",
        daily_limit=5,
        cooldown_seconds=60,
    )

    actions = store._client.calls[0]["TransactItems"]
    update = next(item["Update"] for item in actions if "Update" in item)
    condition = update["ConditionExpression"]
    assert "run_count < :limit" in condition
    assert "last_run_at <= :cutoff" in condition
    key = update["Key"]
    assert key["PK"]["S"].startswith("OPERATOR_EVAL_USAGE#")
    assert key["SK"]["S"].startswith("DAY#")
    event = next(item["Put"]["Item"] for item in actions if "Put" in item)
    assert event["event_type"]["S"] == "AGENT_EVALUATION_BUDGET_RESERVED"
    assert event["actor_id"]["S"] == "operator-1"



class _ApprovalItemTable:
    def __init__(self, item=None):
        self.item = item

    def get_item(self, **kwargs):
        return {"Item": self.item} if self.item is not None else {}


def _dynamo_stateful_store(item=None):
    from boto3.dynamodb.types import TypeSerializer

    store = object.__new__(DynamoDBStore)
    store.table_name = "shadow-hunter-tests"
    store._serializer = TypeSerializer()
    store._client = _FakeTransactClient()
    store._table = _ApprovalItemTable(item)
    return store


def test_dynamodb_approval_token_rotation_is_conditional_and_audited():
    approval = {
        "PK": "APPROVAL#approval-1",
        "SK": "META",
        "approval_id": "approval-1",
        "refund_request_id": "refund-1",
        "principal_id": "customer-1",
        "tenant_id": "tenant-1",
        "trace_id": "trace-1",
        "request_id": "request-1",
        "action_digest": "digest",
        "policy_id": "policy",
        "policy_version": "1",
        "status": "APPROVED",
        "token_hash": "hash-from-read",
        "expires_at": "9999-12-31T23:59:59.000000+00:00",
    }
    store = _dynamo_stateful_store(approval)

    replacement = store.rotate_approval_token("approval-1", "operator-2")

    assert replacement
    actions = store._client.calls[0]["TransactItems"]
    update = next(item["Update"] for item in actions if "Update" in item)
    assert update["ConditionExpression"] == (
        "#status = :approved AND expires_at > :now "
        "AND token_hash = :previous_token_hash"
    )
    assert update["ExpressionAttributeValues"][":previous_token_hash"]["S"] == "hash-from-read"
    event = next(item["Put"]["Item"] for item in actions if "Put" in item)
    assert event["event_type"]["S"] == "APPROVAL_TOKEN_ROTATED"
    assert event["actor_id"]["S"] == "operator-2"
    assert replacement not in str(event)


def test_dynamodb_evaluation_budget_reserves_atomically_per_operator():
    store = _dynamo_stateful_store()

    store.reserve_agent_evaluation(
        "operator-1",
        daily_limit=5,
        cooldown_seconds=60,
    )

    actions = store._client.calls[0]["TransactItems"]
    update = next(item["Update"] for item in actions if "Update" in item)
    condition = update["ConditionExpression"]
    assert "run_count < :limit" in condition
    assert "last_run_at <= :cutoff" in condition
    key = update["Key"]
    assert key["PK"]["S"].startswith("OPERATOR_EVAL_USAGE#")
    assert key["SK"]["S"].startswith("DAY#")
    event = next(item["Put"]["Item"] for item in actions if "Put" in item)
    assert event["event_type"]["S"] == "AGENT_EVALUATION_BUDGET_RESERVED"
    assert event["actor_id"]["S"] == "operator-1"
