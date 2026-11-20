from __future__ import annotations

import pytest

from shadow_hunter.agents import (
    A2AProtocolError,
    AgentMessage,
    AttackScenario,
    BlueAgent,
    RedAgent,
    RedBlueSimulation,
    default_refund_attack_scenarios,
)
from shadow_hunter.approvals import ApprovalService
from shadow_hunter.gateway import ToolGateway
from shadow_hunter.policy import Decision, PolicyConfig, PolicyEngine, Principal
from shadow_hunter.store import SQLiteStore


@pytest.fixture
def system(tmp_path):
    store = SQLiteStore(tmp_path / "red-blue-test.sqlite3")
    store.add_order(
        order_id="order-own",
        tenant_id="tenant-1",
        customer_id="customer-1",
        currency="USD",
        refundable_minor=25_000,
    )
    store.add_order(
        order_id="order-foreign",
        tenant_id="tenant-1",
        customer_id="customer-2",
        currency="USD",
        refundable_minor=10_000,
    )
    gateway = ToolGateway(
        store,
        PolicyEngine(PolicyConfig(self_service_refund_limit_minor=10_000)),
        ApprovalService(store, ttl_seconds=600),
    )
    principal = Principal("subject-1", "tenant-1", "customer-1", True)
    simulation = RedBlueSimulation(store=store, gateway=gateway)
    return store, gateway, principal, simulation


def test_red_blue_suite_blocks_boundary_attacks_and_records_trace(system):
    store, _, principal, simulation = system
    scenarios = default_refund_attack_scenarios(
        own_order_id="order-own",
        foreign_order_id="order-foreign",
        currency="USD",
        refundable_minor=25_000,
    )

    observations = simulation.run_suite(scenarios, principal=principal)

    assert len(observations) == 4
    assert all(result.passed for result in observations)
    assert all(result.attack_prevented for result in observations)
    assert {result.reason_code for result in observations} == {
        "RESOURCE_OWNER_MISMATCH",
        "UNKNOWN_OR_FORBIDDEN_TOOL",
        "REFUND_EXCEEDS_REMAINING_AMOUNT",
        "INVALID_ARGUMENTS",
    }
    assert store.overview()["refund_requests"] == 0

    for observation in observations:
        events = store.get_trace_events(observation.trace_id)
        event_types = {event["event_type"] for event in events}
        assert {
            "A2A_MESSAGE_SENT",
            "A2A_MESSAGE_RECEIVED",
            "POLICY_DECISION",
            "A2A_EVALUATION",
        }.issubset(event_types)
        policy_event = next(
            event for event in events if event["event_type"] == "POLICY_DECISION"
        )
        assert policy_event["details"]["agent_id"] == "blue-agent"


def test_blue_agent_rejects_forged_sender_before_gateway_invocation(system):
    _, gateway, principal, _ = system
    blue = BlueAgent(gateway)
    forged = AgentMessage(
        message_id="forged-message",
        trace_id="forged-trace",
        sender_id="rogue-agent",
        recipient_id="blue-agent",
        message_type="attack.proposal",
        payload={
            "scenario_id": "forged",
            "description": "Attempt to impersonate the Red Agent.",
            "tool_name": "get_order",
            "arguments": {"order_id": "order-own"},
        },
    )

    with pytest.raises(A2AProtocolError, match="authorized Red-to-Blue"):
        blue.receive(forged, principal=principal)


def test_blue_agent_does_not_return_tool_data_to_red_agent(system):
    _, gateway, principal, _ = system
    scenario = AttackScenario(
        scenario_id="owned_read_control",
        description="Control case: request an order owned by the authenticated customer.",
        tool_name="get_order",
        arguments={"order_id": "order-own"},
        expected_decision=Decision.ALLOW,
        expected_reason_code="OWNED_ORDER_READ_ALLOWED",
    )
    red = RedAgent()
    blue = BlueAgent(gateway)
    proposal = red.propose(scenario)

    response = blue.receive(proposal, principal=principal)

    assert response.payload["decision"] == "ALLOW"
    assert response.payload["reason_code"] == "OWNED_ORDER_READ_ALLOWED"
    assert set(response.payload) == {
        "scenario_id",
        "decision",
        "reason_code",
        "action_digest",
    }
    assert "order" not in response.payload
    assert "refundable_minor" not in response.payload


def test_red_agent_checks_trace_and_expected_decision(system):
    _, gateway, principal, _ = system
    scenario = AttackScenario(
        scenario_id="own_order_read",
        description="A proposal whose expected policy outcome is ALLOW.",
        tool_name="get_order",
        arguments={"order_id": "order-own"},
        expected_decision=Decision.ALLOW,
        expected_reason_code="OWNED_ORDER_READ_ALLOWED",
    )
    red = RedAgent()
    blue = BlueAgent(gateway)
    proposal = red.propose(scenario, trace_id="trace-red-blue-0001")
    response = blue.receive(proposal, principal=principal)

    observation = red.assess(proposal, response, scenario)

    assert observation.trace_id == "trace-red-blue-0001"
    assert observation.passed is True
    assert observation.attack_prevented is False
