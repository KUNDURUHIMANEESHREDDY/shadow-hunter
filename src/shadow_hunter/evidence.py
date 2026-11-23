"""Independent audit-evidence checks for bounded synthetic Red/Blue rounds.

This verifier does not trust a model's recommendation, reported score, or the
Red Agent's self-assessment as evidence of policy enforcement. It reconciles
persisted A2A transport events and the *actual* ToolGateway policy event before
a Red/Blue round may be reported as verified.

The proof digest deliberately excludes random UUIDs, clock times and secrets,
so the deterministic synthetic suite yields reproducible semantic receipts.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any


class EvidenceVerificationError(ValueError):
    """Fail-closed: the persisted gateway evidence is missing or contradictory."""


@dataclass(frozen=True, slots=True)
class EvidenceReceipt:
    scenario_id: str
    round_number: int
    decision: str
    reason_code: str
    policy_id: str
    policy_version: str
    tool_name: str
    semantic_sha256: str

    def to_dict(self) -> dict[str, str | int]:
        return {
            "scenario_id": self.scenario_id,
            "round": self.round_number,
            "decision": self.decision,
            "reason_code": self.reason_code,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "tool_name": self.tool_name,
            "evidence_sha256": self.semantic_sha256,
            "verification_method": "persisted_a2a_and_policy_v1",
        }


def _require(condition: bool, label: str) -> None:
    if not condition:
        raise EvidenceVerificationError("Red/Blue evidence mismatch: " + label)


def _only_one(events: list[dict[str, Any]], event_type: str) -> dict[str, Any]:
    found = [event for event in events if event.get("event_type") == event_type]
    _require(len(found) == 1, event_type + " event count")
    return found[0]


def _details(event: dict[str, Any]) -> dict[str, Any]:
    value = event.get("details")
    _require(isinstance(value, dict), "audit event details missing")
    return value


def verify_round_evidence(
    store: Any,
    observation: Any,
    *,
    expected_tool_name: str,
    expected_principal_id: str,
) -> EvidenceReceipt:
    """Check actual stored gateway decision and signed A2A exchange metadata.

    Security notes:
    - The *runtime* verifies HMAC and claims single-use nonces before writing
      authenticated=true. Audit rows do not include signatures or raw tokens.
    - The verifier checks the observed gateway policy decision, not the model's
      claimed outcome, and refuses extra/missing policy decisions per round.
    - An immutable external archive and hosted model identity still need
      independent live checks; SQLite evidence alone is not tamper-proof.
    """
    events = store.get_trace_events(observation.trace_id)
    _require(isinstance(events, list) and bool(events), "missing trace")
    _require(
        all(event.get("trace_id") == observation.trace_id for event in events),
        "mixed trace IDs",
    )
    _require(
        all(event.get("request_id") == observation.proposal_message_id for event in events),
        "mixed request IDs",
    )
    _require(
        not any(event.get("event_type") == "REFUND_EXECUTED" for event in events),
        "unexpected refund execution",
    )

    policy = _only_one(events, "POLICY_DECISION")
    evaluation = _only_one(events, "A2A_EVALUATION")
    received = _only_one(events, "A2A_MESSAGE_RECEIVED")
    sent = [event for event in events if event.get("event_type") == "A2A_MESSAGE_SENT"]
    _require(len(sent) == 2, "two signed outbound A2A events required")
    red = [event for event in sent if event.get("actor_id") == "red-agent"]
    blue = [event for event in sent if event.get("actor_id") == "blue-agent"]
    _require(len(red) == 1 and len(blue) == 1, "Red/Blue sender attribution")
    red_details = _details(red[0])
    blue_details = _details(blue[0])
    recv_details = _details(received)
    for event, details, sender, recipient, message_type, message_id in (
        (red[0], red_details, "red-agent", "blue-agent", "attack.proposal", observation.proposal_message_id),
        (blue[0], blue_details, "blue-agent", "red-agent", "defense.result", observation.response_message_id),
    ):
        _require(details.get("authenticated") is True, "A2A authentication not recorded")
        _require(details.get("sender_id") == sender, "signed sender mismatch")
        _require(details.get("recipient_id") == recipient, "signed recipient mismatch")
        _require(details.get("message_type") == message_type, "A2A message type mismatch")
        _require(details.get("message_id") == message_id, "A2A message ID mismatch")
        _require(isinstance(details.get("key_id"), str) and bool(details["key_id"]), "A2A key reference missing")
    _require(received.get("actor_id") == "blue-agent", "A2A receiver attribution")
    _require(recv_details.get("authenticated") is True, "A2A receipt authentication missing")
    _require(recv_details.get("message_id") == observation.proposal_message_id, "A2A receipt message ID")
    _require(recv_details.get("sender_id") == "red-agent", "A2A receipt sender")
    _require(recv_details.get("recipient_id") == "blue-agent", "A2A receipt recipient")

    policy_details = _details(policy)
    _require(policy.get("actor_id") == expected_principal_id, "policy principal mismatch")
    _require(policy_details.get("agent_id") == "blue-agent", "tool bypassed Blue gateway attribution")
    _require(policy_details.get("tool_name") == expected_tool_name, "gateway tool name mismatch")
    _require(policy.get("decision") == observation.decision.value, "reported decision differs from gateway")
    _require(policy.get("reason_code") == observation.reason_code, "reported reason differs from gateway")
    _require(
        isinstance(policy.get("policy_id"), str) and bool(policy["policy_id"])
        and isinstance(policy.get("policy_version"), str) and bool(policy["policy_version"]),
        "policy version missing",
    )
    digest = policy.get("action_digest")
    _require(
        digest is None or (
            isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
        ),
        "invalid gateway action digest",
    )

    details = _details(evaluation)
    _require(evaluation.get("actor_id") == "red-agent", "evaluation actor mismatch")
    _require(evaluation.get("decision") == policy.get("decision"), "evaluation decision mismatch")
    _require(evaluation.get("reason_code") == policy.get("reason_code"), "evaluation reason mismatch")
    _require(details.get("scenario_id") == observation.scenario_id, "evaluation scenario mismatch")
    _require(details.get("round") == observation.round_number, "evaluation round mismatch")
    _require(details.get("actual_decision") == policy.get("decision"), "evaluation claimed decision mismatch")
    _require(details.get("passed") is observation.passed, "evaluation pass value mismatch")
    _require(details.get("attack_success") is observation.attack_success, "evaluation attack-success mismatch")
    _require(details.get("attack_prevented") is observation.attack_prevented, "evaluation prevention mismatch")
    _require(
        red_details.get("scenario_id") == observation.scenario_id
        and blue_details.get("scenario_id") == observation.scenario_id
        and recv_details.get("scenario_id") == observation.scenario_id,
        "A2A scenario correlation mismatch",
    )

    semantic = {
        "version": 1,
        "scenario_id": observation.scenario_id,
        "round": observation.round_number,
        "strategy_id": observation.strategy_id,
        "is_attack": observation.is_attack,
        "tool_name": expected_tool_name,
        "decision": policy["decision"],
        "reason_code": policy["reason_code"],
        "policy_id": policy["policy_id"],
        "policy_version": policy["policy_version"],
        "risk_score": observation.risk_score,
        "threat_categories": list(observation.threat_categories),
        "defense_model": observation.defense_model,
        "strategy_seed": observation.strategy_seed,
        "defense_seed": observation.defense_seed,
        "passed": observation.passed,
    }
    checksum = hashlib.sha256(
        json.dumps(semantic, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    return EvidenceReceipt(
        scenario_id=observation.scenario_id,
        round_number=observation.round_number,
        decision=policy["decision"],
        reason_code=policy["reason_code"],
        policy_id=policy["policy_id"],
        policy_version=policy["policy_version"],
        tool_name=expected_tool_name,
        semantic_sha256=checksum,
    )
