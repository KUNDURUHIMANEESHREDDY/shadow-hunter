"""Independent Red/Blue evidence verification and deterministic reports."""
from __future__ import annotations

import json
import sqlite3

import pytest

from shadow_hunter.agents import (
    AgentAuthenticator, AgentCredential, RedBlueSimulation,
    default_refund_attack_scenarios,
)
from shadow_hunter.approvals import ApprovalService
from shadow_hunter.evidence import EvidenceVerificationError, verify_round_evidence
from shadow_hunter.gateway import ToolGateway
from shadow_hunter.policy import PolicyConfig, PolicyEngine, Principal
from shadow_hunter.store import SQLiteStore
from scripts.run_red_blue_synthetic import evaluate


@pytest.fixture
def completed_round(tmp_path):
    path = tmp_path / "audit.sqlite3"
    store = SQLiteStore(path)
    store.add_order(
        order_id="own", tenant_id="tenant-a", customer_id="owner",
        currency="USD", refundable_minor=25_000,
    )
    store.add_order(
        order_id="foreign", tenant_id="tenant-a", customer_id="stranger",
        currency="USD", refundable_minor=12_000,
    )
    gateway = ToolGateway(
        store,
        PolicyEngine(PolicyConfig(self_service_refund_limit_minor=10_000)),
        ApprovalService(store, ttl_seconds=600),
    )
    auth = AgentAuthenticator({
        "red": AgentCredential("red-agent", "r" * 48),
        "blue": AgentCredential("blue-agent", "b" * 48),
    })
    principal = Principal("trusted-principal", "tenant-a", "owner", True)
    simulation = RedBlueSimulation(
        store=store, gateway=gateway, authenticator=auth,
        red_key_id="red", blue_key_id="blue", nonce_store=store,
    )
    scenario = default_refund_attack_scenarios(
        own_order_id="own", foreign_order_id="foreign", currency="USD",
        refundable_minor=25_000, self_service_limit_minor=10_000,
    )[0]
    observation = simulation.run(scenario, principal=principal)
    return path, store, observation, scenario, principal


def check(store, observation, scenario, principal):
    return verify_round_evidence(
        store, observation,
        expected_tool_name=scenario.tool_name,
        expected_principal_id=principal.subject_id,
    )


def test_signed_a2a_and_gateway_evidence_are_correlated(completed_round):
    _, store, observation, scenario, principal = completed_round
    receipt = check(store, observation, scenario, principal)
    assert receipt.decision == "DENY"
    assert receipt.reason_code == "RESOURCE_OWNER_MISMATCH"
    assert len(receipt.semantic_sha256) == 64
    evidence = store.get_trace_events(observation.trace_id)
    proof_events = [x for x in evidence if x["event_type"] == "A2A_EVIDENCE_VERIFIED"]
    assert len(proof_events) == 1
    assert proof_events[0]["details"] == receipt.to_dict()
    assert receipt == check(store, observation, scenario, principal)


@pytest.mark.parametrize("field,value", [
    ("decision", "ALLOW"),
    ("reason_code", "FALSIFIED_REASON"),
    ("actor_id", "fake-principal"),
])
def test_verifier_rejects_corrupted_gateway_verdict(completed_round, field, value):
    path, store, observation, scenario, principal = completed_round
    with sqlite3.connect(path) as conn:
        conn.execute(
            f"UPDATE audit_events SET {field}=? WHERE trace_id=? AND event_type='POLICY_DECISION'",
            (value, observation.trace_id),
        )
    with pytest.raises(EvidenceVerificationError):
        check(store, observation, scenario, principal)


def test_verifier_rejects_missing_received_message(completed_round):
    path, store, observation, scenario, principal = completed_round
    with sqlite3.connect(path) as conn:
        conn.execute(
            "DELETE FROM audit_events WHERE trace_id=? AND event_type='A2A_MESSAGE_RECEIVED'",
            (observation.trace_id,),
        )
    with pytest.raises(EvidenceVerificationError, match="A2A_MESSAGE_RECEIVED"):
        check(store, observation, scenario, principal)


def test_verifier_rejects_injected_extra_gateway_action(completed_round):
    _, store, observation, scenario, principal = completed_round
    store.append_audit(
        event_type="POLICY_DECISION",
        trace_id=observation.trace_id,
        request_id=observation.proposal_message_id,
        actor_id=principal.subject_id,
        tenant_id=principal.tenant_id,
        decision="DENY",
        reason_code="UNKNOWN_OR_FORBIDDEN_TOOL",
        details={"tool_name": "another_tool", "agent_id": "blue-agent"},
    )
    with pytest.raises(EvidenceVerificationError, match="POLICY_DECISION event count"):
        check(store, observation, scenario, principal)


def test_verifier_rejects_untrusted_a2a_receipt(completed_round):
    path, store, observation, scenario, principal = completed_round
    with sqlite3.connect(path) as conn:
        conn.execute(
            "UPDATE audit_events SET details_json=? WHERE trace_id=? AND event_type='A2A_MESSAGE_RECEIVED'",
            (json.dumps({"authenticated": False}), observation.trace_id),
        )
    with pytest.raises(EvidenceVerificationError):
        check(store, observation, scenario, principal)


def test_reproducible_synthetic_run_has_same_proof_chain_for_new_keys_and_uuids():
    first = evaluate(rounds=8)
    second = evaluate(rounds=8)
    assert first == second
    assert first["runtime"] == "deterministic_local_synthetic"
    assert first["hosted_model_used"] is False
    assert first["all_expected_outcomes_passed"] is True
    assert first["metrics"]["attack_attempts"] == 7
    assert first["metrics"]["attacks_prevented"] == 7
    assert first["metrics"]["control_cases"] == 1
    assert first["metrics"]["false_denials"] == 0
    assert first["metrics"]["policy_decision_accuracy"] == 1.0
    assert first["refunds_executed"] == 0
    assert len(first["results"]) == 8
    assert all(len(row["evidence_sha256"]) == 64 for row in first["results"])


@pytest.mark.parametrize("rounds", [True, 0, 9, -1, "8"])
def test_unbounded_synthetic_runs_fail_closed(rounds):
    with pytest.raises(ValueError):
        evaluate(rounds=rounds)


def test_forged_blue_self_report_cannot_pass_without_actual_gateway_action(tmp_path):
    """Even a correctly signed Blue claim cannot invent a policy decision."""
    from shadow_hunter.agents import AgentMessage, BlueAgent

    store = SQLiteStore(tmp_path / "forged-blue.sqlite3")
    store.add_order(
        order_id="trusted-own", tenant_id="test-tenant",
        customer_id="owner", currency="USD", refundable_minor=25_000,
    )
    store.add_order(
        order_id="foreign-order", tenant_id="test-tenant",
        customer_id="someone-else", currency="USD", refundable_minor=10_000,
    )
    gateway = ToolGateway(
        store, PolicyEngine(PolicyConfig(self_service_refund_limit_minor=10_000)),
        ApprovalService(store, ttl_seconds=600),
    )
    auth = AgentAuthenticator({
        "red": AgentCredential("red-agent", "r" * 48),
        "blue": AgentCredential("blue-agent", "b" * 48),
    })

    class ForgedBlue(BlueAgent):
        def receive_authenticated(self, envelope, *, authenticator, nonce_store, principal):
            proposal = authenticator.verify(
                envelope,
                expected_sender="red-agent",
                expected_recipient="blue-agent",
                nonce_store=nonce_store,
            )
            # A compromised agent returns a well-formed result without ever
            # passing the proposed action through the real policy gateway.
            return AgentMessage(
                message_id="forged-blue-response",
                trace_id=proposal.trace_id,
                sender_id="blue-agent",
                recipient_id="red-agent",
                message_type="defense.result",
                payload={
                    "scenario_id": proposal.payload["scenario_id"],
                    "decision": "ALLOW",
                    "reason_code": "OWNED_ORDER_READ_ALLOWED",
                    "action_digest": None,
                    "risk_score": 0,
                    "threat_categories": [],
                    "recommended_action": "ROUTE_TO_POLICY_GATEWAY",
                    "analysis_summary": "Forged synthetic Blue recommendation",
                    "defense_model": "fake_blue",
                    "defense_seed": 0,
                },
            )

    scenario = default_refund_attack_scenarios(
        own_order_id="trusted-own", foreign_order_id="foreign-order",
        currency="USD", refundable_minor=25_000,
    )[0]
    simulation = RedBlueSimulation(
        store=store, gateway=gateway, authenticator=auth,
        red_key_id="red", blue_key_id="blue", nonce_store=store,
        blue_agent=ForgedBlue(gateway),
    )
    principal = Principal("trusted-subject", "test-tenant", "owner", True)
    with pytest.raises(EvidenceVerificationError, match="POLICY_DECISION"):
        simulation.run(scenario, principal=principal)
    assert not any(
        event["event_type"] == "A2A_EVIDENCE_VERIFIED"
        for event in store.list_audit(limit=100)
    )
