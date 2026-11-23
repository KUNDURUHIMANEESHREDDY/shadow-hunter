"""Bounded local tenant-isolation and API-abuse regression suite.

Uses only synthetic fixtures. Moto intercepts DynamoDB; no live AWS or
third-party endpoint is contacted.
"""
from __future__ import annotations

from contextlib import nullcontext
from types import SimpleNamespace
from uuid import uuid4

import boto3
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shadow_hunter.approvals import ApprovalService
from shadow_hunter.auth import TokenAuthenticator
from shadow_hunter.gateway import ToolGateway, public_tool_result
from shadow_hunter.policy import PolicyEngine, Principal
from shadow_hunter.store import SQLiteStore


def _mcp_stub(_gateway, _authenticator):
    class SessionManager:
        def run(self):
            return nullcontext()

    return SimpleNamespace(session_manager=SessionManager()), FastAPI()


# The API initializes its module-level app at import time.
from shadow_hunter import mcp_server
mcp_server.build_mcp_runtime = _mcp_stub
from shadow_hunter import api as api_module


@pytest.fixture(params=["sqlite", "dynamodb"])
def isolated_store(request, tmp_path):
    if request.param == "sqlite":
        yield SQLiteStore(tmp_path / "security-isolation.sqlite3")
        return

    pytest.importorskip("moto")
    from moto import mock_aws
    from shadow_hunter.dynamodb_store import DynamoDBStore

    with mock_aws():
        resource = boto3.resource("dynamodb", region_name="us-east-1")
        resource.create_table(
            TableName="shadow-hunter-security-local",
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
            GlobalSecondaryIndexes=[{
                "IndexName": "GSI1",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }],
        )
        yield DynamoDBStore("shadow-hunter-security-local", region="us-east-1")


ALPHA = Principal("subject-alpha", "tenant-alpha", "customer-alpha", True)
BETA = Principal("subject-beta", "tenant-beta", "customer-beta", True)


def seed_orders(store):
    for order_id, tenant_id, customer_id in [
        ("alpha-order", "tenant-alpha", "customer-alpha"),
        ("beta-order", "tenant-beta", "customer-beta"),
        ("alpha-neighbor-order", "tenant-alpha", "customer-other"),
    ]:
        store.add_order(
            order_id=order_id,
            tenant_id=tenant_id,
            customer_id=customer_id,
            currency="USD",
            refundable_minor=5000,
        )


def args_for(tool_name, order_id, *, key="isolated-key-001"):
    if tool_name == "create_refund_request":
        return {
            "order_id": order_id,
            "amount_minor": 100,
            "currency": "USD",
            "reason": "Synthetic security test",
            "idempotency_key": key,
        }
    return {"order_id": order_id}


@pytest.mark.parametrize("tool", [
    "get_order", "check_refund_eligibility", "create_refund_request",
])
def test_cross_tenant_and_cross_customer_are_non_enumerating_and_side_effect_free(
    isolated_store, tool
):
    store = isolated_store
    seed_orders(store)
    gateway = ToolGateway(store, PolicyEngine(), ApprovalService(store))
    cases = [
        (ALPHA, "beta-order", "RESOURCE_TENANT_MISMATCH"),
        (BETA, "alpha-order", "RESOURCE_TENANT_MISMATCH"),
        (ALPHA, "alpha-neighbor-order", "RESOURCE_OWNER_MISMATCH"),
    ]

    for principal, foreign_order, internal_reason in cases:
        trace = str(uuid4())
        request_id = "security-isolation-request"
        public = []
        for order_id in ("does-not-exist", foreign_order):
            result = gateway.invoke(
                principal=principal,
                tool_name=tool,
                arguments=args_for(tool, order_id),
                request_id=request_id,
                trace_id=trace,
            )
            public.append(public_tool_result(result))
        assert public[0] == public[1]
        assert public[0]["decision"] == "DENY"
        assert public[0]["reason_code"] == "RESOURCE_NOT_AVAILABLE"
        assert "order" not in public[0]
        assert "refund_request" not in public[0]
        reasons = {
            e["reason_code"] for e in store.get_trace_events(trace)
            if e["event_type"] == "POLICY_DECISION"
        }
        assert reasons == {"ORDER_CONTEXT_MISSING", internal_reason}

    assert store.overview()["refund_requests"] == 0


def test_tenant_scoped_idempotency_and_spoofed_identity_arguments(isolated_store):
    store = isolated_store
    seed_orders(store)
    gateway = ToolGateway(store, PolicyEngine(), ApprovalService(store))
    for principal, own_order in [(ALPHA, "alpha-order"), (BETA, "beta-order")]:
        own = gateway.invoke(
            principal=principal,
            tool_name="get_order",
            arguments={"order_id": own_order},
        )
        assert own["decision"] == "ALLOW"
        assert own["order"]["order_id"] == own_order

    created = []
    for principal, own_order in [(ALPHA, "alpha-order"), (BETA, "beta-order")]:
        result = gateway.invoke(
            principal=principal,
            tool_name="create_refund_request",
            arguments=args_for("create_refund_request", own_order, key="shared-key-001"),
        )
        assert result["decision"] != "DENY"
        created.append(result["refund_request"]["refund_request_id"])
    assert created[0] != created[1]
    assert store.overview()["refund_requests"] == 2

    spoofed = args_for("create_refund_request", "beta-order", key="shared-key-002")
    spoofed.update({"tenant_id": "tenant-beta", "customer_id": "customer-beta"})
    denied = gateway.invoke(
        principal=ALPHA,
        tool_name="create_refund_request",
        arguments=spoofed,
    )
    assert denied["decision"] == "DENY"
    assert denied["reason_code"] == "INVALID_ARGUMENTS"
    assert store.overview()["refund_requests"] == 2


def test_http_boundary_rejects_token_confusion_spoofing_and_operator_access(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(api_module, "build_mcp_runtime", _mcp_stub)
    store = SQLiteStore(tmp_path / "http-security.sqlite3")
    seed_orders(store)
    auth = TokenAuthenticator(
        customer_tokens={
            "alpha-token": {
                "subject_id": ALPHA.subject_id,
                "tenant_id": ALPHA.tenant_id,
                "customer_id": ALPHA.customer_id,
            },
            "beta-token": {
                "subject_id": BETA.subject_id,
                "tenant_id": BETA.tenant_id,
                "customer_id": BETA.customer_id,
            },
        },
        operator_tokens={"operator-token": {"subject_id": "operator-subject"}},
    )
    app = api_module.create_app(
        store=store, authenticator=auth, harness_client=object()
    )
    with TestClient(app) as client:
        route = "/v1/agent/tools/get_order"
        arguments = {"order_id": "alpha-order"}
        body = {"arguments": arguments}
        for header in ({}, {"Authorization": "Bearer invalid"},
                       {"Authorization": "Bearer operator-token"},
                       {"Authorization": "Basic alpha-token"}):
            assert client.post(route, json=body, headers=header).status_code == 401

        for order_id in ("beta-order", "alpha-neighbor-order", "missing"):
            result = client.post(
                route,
                headers={"Authorization": "Bearer alpha-token"},
                json={"arguments": {"order_id": order_id}},
            )
            assert result.status_code == 200
            assert result.json()["reason_code"] == "RESOURCE_NOT_AVAILABLE"
            assert "order" not in result.json()

        assert client.post(
            route,
            headers={"Authorization": "Bearer alpha-token"},
            json={"arguments": arguments, "tenant_id": "tenant-beta"},
        ).status_code == 422
        assert client.post(
            route,
            headers={"Authorization": "Bearer alpha-token"},
            json={"arguments": {**arguments, "tenant_id": "tenant-beta"}},
        ).json()["decision"] == "DENY"

        # Only operators can read evidence, issue approvals, or execute refunds.
        operator_paths = [
            "/v1/operator/audit",
            "/v1/operator/approvals",
            "/v1/operator/overview",
            "/v1/operator/audit/trace/synthetic",
        ]
        for path in operator_paths:
            assert client.get(
                path, headers={"Authorization": "Bearer alpha-token"}
            ).status_code == 401
        assert client.post(
            "/v1/operator/refunds/unowned/execute",
            json={"approval_token": "forged"},
            headers={"Authorization": "Bearer alpha-token"},
        ).status_code in (401, 404)

        for suspicious_id in (
            "' OR '1'='1", "../alpha-order", "alpha-order\u0000", "unknown-" + "x" * 500
        ):
            response = client.post(
                route,
                json={"arguments": {"order_id": suspicious_id}},
                headers={"Authorization": "Bearer alpha-token"},
            )
            assert response.status_code in (200, 422)
            if response.status_code == 200:
                assert response.json()["decision"] == "DENY"
    assert store.overview()["refund_requests"] == 0
