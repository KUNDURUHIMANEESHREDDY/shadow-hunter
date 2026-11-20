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
