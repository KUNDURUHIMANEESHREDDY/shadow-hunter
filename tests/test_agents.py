from __future__ import annotations

from dataclasses import replace

import pytest

from shadow_hunter.agents import (
    A2AAuthenticationError,
    A2AConfigurationError,
    A2AProtocolError,
    AgentAuthenticator,
    AgentCredential,
    AgentMessage,
    AttackScenario,
    BlueAgent,
    Decision,
    EvaluationMetrics,
    RedAgent,
    RedBlueSimulation,
    AdversarialStrategyEngine,
    default_refund_attack_scenarios,
)
from shadow_hunter.approvals import ApprovalService
from shadow_hunter.gateway import ToolGateway
from shadow_hunter.policy import PolicyConfig, PolicyEngine, Principal
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
    policy = PolicyEngine(PolicyConfig(self_service_refund_limit_minor=10_000))
    gateway = ToolGateway(store, policy, ApprovalService(store, ttl_seconds=600))
    principal = Principal("subject-1", "tenant-1", "customer-1", True)
    authenticator = AgentAuthenticator(
        {
            "red-test": AgentCredential("red-agent", "r" * 48),
            "blue-test": AgentCredential("blue-agent", "b" * 48),
        }
    )
    simulation = RedBlueSimulation(
        store=store,
        gateway=gateway,
        authenticator=authenticator,
        red_key_id="red-test",
        blue_key_id="blue-test",
        nonce_store=store,
    )
    scenarios = default_refund_attack_scenarios(
        own_order_id="order-own",
        foreign_order_id="order-foreign",
        currency="USD",
        refundable_minor=25_000,
        self_service_limit_minor=10_000,
    )
    return store, gateway, principal, authenticator, simulation, scenarios


def test_authenticated_red_blue_suite_blocks_attacks_and_records_evidence(system):
    store, _, principal, _, simulation, scenarios = system

    observations = simulation.run_suite(scenarios, principal=principal)
    metrics = EvaluationMetrics.from_observations(observations)

    assert len(observations) == 8
    assert all(result.passed for result in observations)
    assert all(result.attack_prevented for result in observations if result.is_attack)
    assert all(not result.attack_success for result in observations)
    assert {row.scenario_id for row in observations} == {
        scenario.scenario_id for scenario in scenarios
    }
    assert metrics.attack_attempts == 7
    assert metrics.attack_successes == 0
    assert metrics.attacks_prevented == 7
    assert metrics.control_cases == 1
    assert metrics.false_denials == 0
    assert metrics.attack_success_rate == 0.0
    assert metrics.defensive_effectiveness == 1.0
    assert metrics.false_denial_rate == 0.0
    assert metrics.policy_decision_accuracy == 1.0
    # The high-value request is isolated in the evaluation workload and remains
    # pending approval; no evaluation round executes a refund.
    assert store.overview()["executed_refunds"] == 0

    for observation in observations:
        events = store.get_trace_events(observation.trace_id)
        event_types = {event["event_type"] for event in events}
        assert {
            "A2A_MESSAGE_SENT",
            "A2A_MESSAGE_RECEIVED",
            "POLICY_DECISION",
            "A2A_EVALUATION",
        }.issubset(event_types)
        assert any(
            event["details"].get("authenticated") is True
            for event in events
            if event["event_type"] == "A2A_MESSAGE_SENT"
        )


def test_blue_agent_rejects_forged_sender_before_gateway_invocation(system):
    _, gateway, principal, _, _, _ = system
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


def test_a2a_authenticator_rejects_replayed_message(system):
    store, gateway, principal, authenticator, _, scenarios = system
    red = RedAgent()
    blue = BlueAgent(gateway)
    proposal = red.propose(scenarios[0], trace_id="trace-replay-check")
    signed = authenticator.sign(
        proposal, key_id="red-test", issued_at=1_900_000_000, nonce="replay-nonce-001"
    )

    # Use an explicit test clock within the signed-message window.
    verified = authenticator.verify(
        signed,
        expected_sender="red-agent",
        expected_recipient="blue-agent",
        nonce_store=store,
        now_epoch=1_900_000_000,
    )
    assert verified == proposal

    with pytest.raises(A2AAuthenticationError, match="replay"):
        authenticator.verify(
            signed,
            expected_sender="red-agent",
            expected_recipient="blue-agent",
            nonce_store=store,
            now_epoch=1_900_000_000,
        )


def test_a2a_authenticator_rejects_tampered_payload(system):
    store, _, _, authenticator, _, scenarios = system
    signed = authenticator.sign(
        RedAgent().propose(scenarios[0]),
        key_id="red-test",
        issued_at=1_900_000_000,
        nonce="tamper-nonce-001",
    )
    tampered_message = AgentMessage(
        message_id=signed.message.message_id,
        trace_id=signed.message.trace_id,
        sender_id=signed.message.sender_id,
        recipient_id=signed.message.recipient_id,
        message_type=signed.message.message_type,
        payload={
            **signed.message.payload,
            "tool_name": "execute_refund",
        },
    )
    tampered = replace(signed, message=tampered_message)

    with pytest.raises(A2AAuthenticationError, match="signature"):
        authenticator.verify(
            tampered,
            expected_sender="red-agent",
            expected_recipient="blue-agent",
            nonce_store=store,
            now_epoch=1_900_000_000,
        )


def test_blue_agent_returns_only_redacted_reasoning_and_decision(system):
    _, gateway, principal, authenticator, simulation, scenarios = system
    observation = simulation.run(scenarios[0], principal=principal)

    response_events = [
        event for event in simulation.store.get_trace_events(observation.trace_id)
        if event["event_type"] == "A2A_EVALUATION"
    ]
    assert response_events
    assert "unauthorized_resource_access" in response_events[0]["details"]["threat_categories"]
    assert response_events[0]["details"]["risk_score"] == 100
    assert "customer_id" not in response_events[0]["details"]


def test_adversarial_strategy_engine_runs_bounded_adaptive_iterations(system):
    store, gateway, principal, authenticator, _, scenarios = system
    engine = AdversarialStrategyEngine(scenarios)
    simulation = RedBlueSimulation(
        store=store,
        gateway=gateway,
        authenticator=authenticator,
        red_key_id="red-test",
        blue_key_id="blue-test",
        nonce_store=store,
    )

    observations = simulation.run_autonomous_loop(
        engine, principal=principal, rounds=10
    )

    assert len(observations) == 10
    assert engine.observation_count == 10
    assert [row.round_number for row in observations] == list(range(1, 11))
    assert len({row.trace_id for row in observations}) == 10
    assert all(row.passed for row in observations)


def test_strategy_engine_rejects_unbounded_round_count(system):
    _, _, principal, authenticator, simulation, scenarios = system
    engine = AdversarialStrategyEngine(scenarios)
    with pytest.raises(ValueError, match="between 1 and"):
        simulation.run_autonomous_loop(engine, principal=principal, rounds=10_000)


def test_control_case_is_not_counted_as_an_attack(system):
    _, _, principal, _, simulation, scenarios = system
    control = next(row for row in scenarios if row.scenario_id == "legitimate_owned_order_read")

    observation = simulation.run(control, principal=principal)
    metrics = EvaluationMetrics.from_observations([observation])

    assert observation.decision is Decision.ALLOW
    assert observation.is_attack is False
    assert observation.attack_success is False
    assert observation.attack_prevented is False
    assert metrics.attack_attempts == 0
    assert metrics.control_cases == 1
    assert metrics.false_denials == 0
    assert metrics.policy_decision_accuracy == 1.0


def test_agent_authenticator_rejects_shared_hmac_secret():
    with pytest.raises(A2AConfigurationError, match="unique HMAC secret"):
        AgentAuthenticator(
            {
                "red-key": AgentCredential("red-agent", "shared-secret-value-" * 3),
                "blue-key": AgentCredential("blue-agent", "shared-secret-value-" * 3),
            }
        )
