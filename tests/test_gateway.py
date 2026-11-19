from __future__ import annotations

import pytest

from shadow_hunter.approvals import ApprovalService
from shadow_hunter.gateway import ToolGateway
from shadow_hunter.policy import PolicyConfig, PolicyEngine, Principal
from shadow_hunter.store import SQLiteStore


@pytest.fixture
def system(tmp_path):
    store = SQLiteStore(tmp_path / "shadow-hunter-test.sqlite3")
    store.add_order(
        order_id="order-1",
        tenant_id="tenant-1",
        customer_id="customer-1",
        currency="USD",
        refundable_minor=25_000,
    )
    approvals = ApprovalService(store, ttl_seconds=600)
    gateway = ToolGateway(
        store,
        PolicyEngine(PolicyConfig(self_service_refund_limit_minor=10_000)),
        approvals,
    )
    customer = Principal("subject-1", "tenant-1", "customer-1", True)
    return store, approvals, gateway, customer


def test_tool_gateway_allows_owned_order_read(system):
    store, _, gateway, customer = system
    result = gateway.invoke(
        principal=customer, tool_name="get_order", arguments={"order_id": "order-1"}
    )
    assert result["decision"] == "ALLOW"
    assert result["order"]["refundable_minor"] == 25_000
    assert store.overview()["audit_events"] == 1


def test_tool_gateway_denies_unknown_tool(system):
    _, _, gateway, customer = system
    result = gateway.invoke(
        principal=customer,
        tool_name="delete_customer",
        arguments={"customer_id": "customer-1"},
    )
    assert result["decision"] == "DENY"


def test_refund_request_is_created_with_pending_approval(system):
    store, _, gateway, customer = system
    result = gateway.invoke(
        principal=customer,
        tool_name="create_refund_request",
        arguments={
            "order_id": "order-1",
            "amount_minor": 5_000,
            "currency": "USD",
            "reason": "Damaged item",
            "idempotency_key": "idempotency-0001",
        },
    )
    assert result["decision"] == "ALLOW"
    assert result["approval"]["status"] == "PENDING"
    assert result["refund_request"]["status"] == "PENDING_APPROVAL"
    assert store.overview()["pending_approvals"] == 1


def test_large_refund_is_escalated_not_executed(system):
    _, _, gateway, customer = system
    result = gateway.invoke(
        principal=customer,
        tool_name="create_refund_request",
        arguments={
            "order_id": "order-1",
            "amount_minor": 12_000,
            "currency": "USD",
            "reason": "High value return",
            "idempotency_key": "idempotency-0002",
        },
    )
    assert result["decision"] == "ESCALATE"
    assert result["refund_request"]["status"] == "PENDING_APPROVAL"


def test_agent_cannot_call_refund_execution(system):
    _, _, gateway, customer = system
    result = gateway.invoke(
        principal=customer,
        tool_name="execute_refund",
        arguments={"refund_request_id": "anything", "approval_token": "anything"},
    )
    assert result["decision"] == "DENY"


def test_duplicate_request_key_returns_the_same_refund_request(system):
    _, _, gateway, customer = system
    arguments = {
        "order_id": "order-1",
        "amount_minor": 5_000,
        "currency": "USD",
        "reason": "Damaged item",
        "idempotency_key": "idempotency-repeat",
    }
    first = gateway.invoke(principal=customer, tool_name="create_refund_request", arguments=arguments)
    second = gateway.invoke(principal=customer, tool_name="create_refund_request", arguments=arguments)
    assert first["refund_request"]["refund_request_id"] == second["refund_request"]["refund_request_id"]
    assert first["approval"]["approval_id"] == second["approval"]["approval_id"]


def test_same_idempotency_key_with_changed_parameters_is_denied(system):
    _, _, gateway, customer = system
    base = {
        "order_id": "order-1",
        "amount_minor": 5_000,
        "currency": "USD",
        "reason": "Damaged item",
        "idempotency_key": "idempotency-conflict",
    }
    gateway.invoke(principal=customer, tool_name="create_refund_request", arguments=base)
    changed = {**base, "amount_minor": 6_000}
    result = gateway.invoke(principal=customer, tool_name="create_refund_request", arguments=changed)
    assert result["decision"] == "DENY"
    assert result["reason_code"] == "IDEMPOTENCY_KEY_CONFLICT"


def test_approval_and_refund_execution_are_single_use_and_idempotent(system):
    store, approvals, gateway, customer = system
    created = gateway.invoke(
        principal=customer,
        tool_name="create_refund_request",
        arguments={
            "order_id": "order-1",
            "amount_minor": 5_000,
            "currency": "USD",
            "reason": "Damaged item",
            "idempotency_key": "idempotency-execute",
        },
    )
    approval_id = created["approval"]["approval_id"]
    token = approvals.approve(approval_id, "support-agent-1")
    refund_id = created["refund_request"]["refund_request_id"]

    first = gateway.execute_approved_refund(
        refund_request_id=refund_id,
        approval_token=token,
        operator_id="support-agent-1",
    )
    replay = gateway.execute_approved_refund(
        refund_request_id=refund_id,
        approval_token=token,
        operator_id="support-agent-1",
    )
    assert first["status"] == "EXECUTED"
    assert replay["idempotent_replay"] is True
    assert store.get_order("order-1").refundable_minor == 20_000
    assert store.overview()["executed_refunds"] == 1


def test_invalid_approval_token_does_not_execute(system):
    store, approvals, gateway, customer = system
    created = gateway.invoke(
        principal=customer,
        tool_name="create_refund_request",
        arguments={
            "order_id": "order-1",
            "amount_minor": 5_000,
            "currency": "USD",
            "reason": "Damaged item",
            "idempotency_key": "idempotency-invalid-token",
        },
    )
    approvals.approve(created["approval"]["approval_id"], "support-agent-1")
    with pytest.raises(Exception):
        gateway.execute_approved_refund(
            refund_request_id=created["refund_request"]["refund_request_id"],
            approval_token="wrong-token",
            operator_id="support-agent-1",
        )
    assert store.get_order("order-1").refundable_minor == 25_000


def test_approval_audit_events_keep_original_request_and_trace_ids(system):
    store, approvals, gateway, customer = system
    created = gateway.invoke(
        principal=customer,
        tool_name="create_refund_request",
        request_id="request-correlated-1",
        trace_id="trace-correlated-1",
        arguments={
            "order_id": "order-1",
            "amount_minor": 5_000,
            "currency": "USD",
            "reason": "Damaged item",
            "idempotency_key": "idempotency-trace-001",
        },
    )
    token = approvals.approve(created["approval"]["approval_id"], "support-agent-1")
    gateway.execute_approved_refund(
        refund_request_id=created["refund_request"]["refund_request_id"],
        approval_token=token,
        operator_id="support-agent-1",
    )
    events = store.get_trace_events("trace-correlated-1")
    assert events
    assert {event["request_id"] for event in events} == {"request-correlated-1"}
    assert "REFUND_EXECUTED" in {event["event_type"] for event in events}
