from __future__ import annotations

import pytest

from shadow_hunter.dynamodb_store import DynamoDBStore
from shadow_hunter.store import StoreError


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
