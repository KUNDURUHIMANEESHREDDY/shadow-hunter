from __future__ import annotations

from contextlib import nullcontext
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from shadow_hunter import mcp_server
from shadow_hunter.approvals import ApprovalService
from shadow_hunter.auth import TokenAuthenticator
from shadow_hunter.gateway import ToolGateway
from shadow_hunter.mcp_server import MCPCaller, invoke_current_tool
from shadow_hunter.policy import PolicyEngine, Principal
from shadow_hunter.store import SQLiteStore


class _SessionManager:
    def run(self):
        return nullcontext()


def _build_mcp_stub(_gateway, _authenticator):
    return SimpleNamespace(session_manager=_SessionManager()), FastAPI()


# api.py constructs its module-level app during import, so stub MCP before
# importing the factory. This matches the existing operator API test setup.
mcp_server.build_mcp_runtime = _build_mcp_stub
import shadow_hunter.api as api_module


def _add_foreign_orders(store):
    store.add_order(
        order_id="foreign-tenant-order",
        tenant_id="tenant-2",
        customer_id="customer-2",
        currency="USD",
        refundable_minor=1000,
    )
    store.add_order(
        order_id="foreign-customer-order",
        tenant_id="tenant-1",
        customer_id="customer-2",
        currency="USD",
        refundable_minor=1000,
    )


def test_customer_tool_api_does_not_disclose_order_existence(tmp_path, monkeypatch):
    monkeypatch.setattr(api_module, "build_mcp_runtime", _build_mcp_stub)
    store = SQLiteStore(tmp_path / "resource-disclosure-api.sqlite3")
    _add_foreign_orders(store)
    authenticator = TokenAuthenticator(
        customer_tokens={
            "customer-token": {
                "subject_id": "customer-subject",
                "tenant_id": "tenant-1",
                "customer_id": "customer-1",
            }
        },
        operator_tokens={"operator-token": {"subject_id": "operator-subject"}},
    )
    app = api_module.create_app(
        store=store,
        authenticator=authenticator,
        harness_client=object(),
    )
    order_ids = (
        "missing-order",
        "foreign-tenant-order",
        "foreign-customer-order",
    )
    with TestClient(app) as client:
        responses = [
            client.post(
                "/v1/agent/tools/get_order",
                headers={"Authorization": "Bearer customer-token"},
                json={
                    "request_id": "shared-request",
                    "trace_id": "shared-trace",
                    "arguments": {"order_id": order_id},
                },
            )
            for order_id in order_ids
        ]
        assert all(response.status_code == 200 for response in responses)
        payloads = [response.json() for response in responses]
        assert payloads[0] == payloads[1] == payloads[2]
        assert payloads[0]["decision"] == "DENY"
        assert payloads[0]["reason_code"] == "RESOURCE_NOT_AVAILABLE"

        # Detailed distinctions remain available only through operator auth.
        assert client.get(
            "/v1/operator/audit/trace/shared-trace",
            headers={"Authorization": "Bearer customer-token"},
        ).status_code == 401
        audit_response = client.get(
            "/v1/operator/audit/trace/shared-trace",
            headers={"Authorization": "Bearer operator-token"},
        )
        assert audit_response.status_code == 200
        policy_reasons = {
            event["reason_code"]
            for event in audit_response.json()
            if event["event_type"] == "POLICY_DECISION"
        }
        assert policy_reasons == {
            "ORDER_CONTEXT_MISSING",
            "RESOURCE_TENANT_MISMATCH",
            "RESOURCE_OWNER_MISMATCH",
        }


def test_mcp_customer_tool_does_not_disclose_order_existence(tmp_path):
    store = SQLiteStore(tmp_path / "resource-disclosure-mcp.sqlite3")
    _add_foreign_orders(store)
    gateway = ToolGateway(
        store,
        PolicyEngine(),
        ApprovalService(store, ttl_seconds=600),
    )
    caller = MCPCaller(
        principal=Principal("customer-subject", "tenant-1", "customer-1", True),
        agent_id="trusted-agent",
        demo_run_id="shared-mcp-trace",
    )
    marker = mcp_server._current_caller.set(caller)
    try:
        payloads = [
            invoke_current_tool(gateway, "get_order", {"order_id": order_id})
            for order_id in (
                "missing-order",
                "foreign-tenant-order",
                "foreign-customer-order",
            )
        ]
    finally:
        mcp_server._current_caller.reset(marker)

    assert {payload["reason_code"] for payload in payloads} == {
        "RESOURCE_NOT_AVAILABLE"
    }
    assert {payload["decision"] for payload in payloads} == {"DENY"}
    policy_reasons = {
        event["reason_code"]
        for event in store.get_trace_events("shared-mcp-trace")
        if event["event_type"] == "POLICY_DECISION"
    }
    assert policy_reasons == {
        "ORDER_CONTEXT_MISSING",
        "RESOURCE_TENANT_MISMATCH",
        "RESOURCE_OWNER_MISMATCH",
    }
