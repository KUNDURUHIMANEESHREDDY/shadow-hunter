from __future__ import annotations

import pytest

from shadow_hunter.approvals import ApprovalService
from shadow_hunter.gateway import GatewayError, ToolGateway
from shadow_hunter.policy import PolicyConfig, PolicyEngine, Principal
from shadow_hunter.store import SQLiteStore


@pytest.fixture
def flow(tmp_path):
    store = SQLiteStore(tmp_path / "approval-flow.sqlite3")
    store.add_order(
        order_id="order-approval",
        tenant_id="tenant-a",
        customer_id="customer-a",
        currency="USD",
        refundable_minor=30_000,
    )
    service = ApprovalService(store, ttl_seconds=600)
    gateway = ToolGateway(
        store, PolicyEngine(PolicyConfig(self_service_refund_limit_minor=10_000)), service
    )
    principal = Principal("customer-user", "tenant-a", "customer-a", True)
    created = gateway.invoke(
        principal=principal,
        tool_name="create_refund_request",
        arguments={
            "order_id": "order-approval",
            "amount_minor": 7_500,
            "currency": "USD",
            "reason": "Product damaged",
            "idempotency_key": "approval-flow-0001",
        },
    )
    return store, service, gateway, created


def test_approval_is_bound_to_action_digest_and_policy_version(flow):
    store, service, gateway, created = flow
    refund_id = created["refund_request"]["refund_request_id"]
    approval_id = created["approval"]["approval_id"]
    token = service.approve(approval_id, "support-user")
    with store._transaction() as conn:
        conn.execute(
            "UPDATE approvals SET action_digest = ? WHERE approval_id = ?",
            ("tampered-digest", approval_id),
        )
    with pytest.raises(GatewayError):
        gateway.execute_approved_refund(
            refund_request_id=refund_id,
            approval_token=token,
            operator_id="support-user",
        )
    assert store.get_order("order-approval").refundable_minor == 30_000


def test_order_balance_is_rechecked_at_execution(flow):
    store, service, gateway, created = flow
    refund_id = created["refund_request"]["refund_request_id"]
    token = service.approve(created["approval"]["approval_id"], "support-user")
    store.add_order(
        order_id="order-approval",
        tenant_id="tenant-a",
        customer_id="customer-a",
        currency="USD",
        refundable_minor=2_000,
    )
    with pytest.raises(GatewayError):
        gateway.execute_approved_refund(
            refund_request_id=refund_id,
            approval_token=token,
            operator_id="support-user",
        )
    assert store.get_order("order-approval").refundable_minor == 2_000


def test_rejected_approval_cannot_execute(flow):
    _, service, gateway, created = flow
    refund_id = created["refund_request"]["refund_request_id"]
    approval_id = created["approval"]["approval_id"]
    service.reject(approval_id, "support-user", "Insufficient evidence")
    with pytest.raises(GatewayError):
        gateway.execute_approved_refund(
            refund_request_id=refund_id,
            approval_token="not-issued",
            operator_id="support-user",
        )


def test_approval_is_invalidated_when_policy_version_changes(flow):
    store, service, gateway, created = flow
    refund_id = created["refund_request"]["refund_request_id"]
    token = service.approve(created["approval"]["approval_id"], "support-user")
    gateway.policy.config = PolicyConfig(
        policy_id="support-refund-baseline", version="0.2.0", self_service_refund_limit_minor=10_000
    )
    with pytest.raises(GatewayError):
        gateway.execute_approved_refund(
            refund_request_id=refund_id,
            approval_token=token,
            operator_id="support-user",
        )
    assert store.get_order("order-approval").refundable_minor == 30_000
