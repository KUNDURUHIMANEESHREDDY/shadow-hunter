"""Opt-in hosted NVIDIA Red/Blue evaluation over *synthetic local* orders.

Unlike run_red_blue_synthetic.py, this script executes actual model inference
when explicitly invoked with --allow-provider-calls and NVIDIA_API_KEY.

The models can only select a fixed, audited scenario catalogue and give bounded
advisory analysis. Actual tool actions still go through the deterministic
ToolGateway with independently verified A2A/policy evidence.

No AWS, payments, external customer data, or real customer orders are used.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import tempfile
from pathlib import Path
from typing import Any

from shadow_hunter.agents import (
    AdversarialStrategyEngine, AgentAuthenticator, AgentCredential,
    BlueAgent, EvaluationMetrics, RedBlueSimulation,
    default_refund_attack_scenarios,
)
from shadow_hunter.approvals import ApprovalService
from shadow_hunter.evidence import verify_round_evidence
from shadow_hunter.gateway import ToolGateway
from shadow_hunter.nim import (
    NIMBlueDefenseReasoner, NIMChatClient, NIMConfigurationError,
    NIMInferenceError, NIMRedStrategyPlanner,
)
from shadow_hunter.policy import PolicyConfig, PolicyEngine, Principal
from shadow_hunter.store import SQLiteStore
from scripts.run_red_blue_synthetic import canonical_hash


def evaluate_hosted(client: Any, *, rounds: int = 1) -> dict:
    """Execute bounded, model-assisted Red/Blue reasoning.

    The client is injectable for OFFLINE tests; only the CLI constructs an
    actual NVIDIA HTTPS client. Tests must not claim live provider success.
    """
    if isinstance(rounds, bool) or not isinstance(rounds, int) or not 1 <= rounds <= 3:
        raise ValueError("hosted evaluation permits only 1–3 rounds")
    with tempfile.TemporaryDirectory(prefix="shadow-hunter-hosted-eval-") as directory:
        store = SQLiteStore(Path(directory) / "hosted-sandbox.sqlite3")
        store.add_order(
            order_id="synthetic-owned-order", tenant_id="synthetic-tenant",
            customer_id="synthetic-customer", currency="USD",
            refundable_minor=25_000,
        )
        store.add_order(
            order_id="synthetic-foreign-order", tenant_id="synthetic-tenant",
            customer_id="synthetic-other-customer", currency="USD",
            refundable_minor=15_000,
        )
        principal = Principal(
            "synthetic-caller", "synthetic-tenant", "synthetic-customer", True
        )
        policy = PolicyEngine(PolicyConfig(self_service_refund_limit_minor=10_000))
        gateway = ToolGateway(store, policy, ApprovalService(store, ttl_seconds=600))
        authentication = AgentAuthenticator({
            "red-local": AgentCredential("red-agent", secrets.token_urlsafe(48)),
            "blue-local": AgentCredential("blue-agent", secrets.token_urlsafe(48)),
        })
        red = NIMRedStrategyPlanner.from_environment(client)
        blue = NIMBlueDefenseReasoner.from_environment(client, policy)
        if red.model == blue.model:
            raise NIMConfigurationError("Red and Blue model identifiers must be distinct")
        scenarios = default_refund_attack_scenarios(
            own_order_id="synthetic-owned-order",
            foreign_order_id="synthetic-foreign-order", currency="USD",
            refundable_minor=25_000, self_service_limit_minor=10_000,
        )
        simulation = RedBlueSimulation(
            store=store, gateway=gateway, authenticator=authentication,
            red_key_id="red-local", blue_key_id="blue-local", nonce_store=store,
            blue_agent=BlueAgent(gateway, reasoner=blue),
            red_strategy_planner=red,
        )
        observations = simulation.run_autonomous_loop(
            AdversarialStrategyEngine(scenarios),
            principal=principal,
            rounds=rounds,
        )
        catalogued = {item.scenario_id: item for item in scenarios}
        results = []
        receipts = []
        for row in observations:
            receipt = verify_round_evidence(
                store, row,
                expected_tool_name=catalogued[row.scenario_id].tool_name,
                expected_principal_id=principal.subject_id,
            )
            events = store.get_trace_events(row.trace_id)
            saved = [event for event in events if event["event_type"] == "A2A_EVIDENCE_VERIFIED"]
            if len(saved) != 1 or saved[0]["details"] != receipt.to_dict():
                raise ValueError("hosted evaluation evidence is not independently verified")
            receipts.append(receipt.semantic_sha256)
            results.append({
                "scenario_id": row.scenario_id,
                "round": row.round_number,
                "is_attack": row.is_attack,
                "decision": receipt.decision,
                "reason_code": receipt.reason_code,
                "expected_outcome_passed": row.passed,
                "attack_success": row.attack_success,
                "risk_score": row.risk_score,
                "threat_categories": list(row.threat_categories),
                "red_seed": row.strategy_seed,
                "blue_seed": row.defense_seed,
                "evidence_sha256": receipt.semantic_sha256,
                "evidence_verified": True,
            })
        if store.overview()["executed_refunds"] != 0:
            raise ValueError("hosted evaluation sandbox must not execute refunds")
        metrics = EvaluationMetrics.from_observations(observations).to_dict()
        return {
            "schema_version": "red-blue-hosted-evaluation-v1",
            "provider": "nvidia_nim",
            "red_model": red.model,
            "blue_model": blue.model,
            "configured_model_calls": 2 * rounds,
            "scenario_catalogue_sha256": canonical_hash({
                scenario.scenario_id: {
                    "tool_name": scenario.tool_name,
                    "expected_decision": scenario.expected_decision.value,
                }
                for scenario in scenarios
            }),
            "evidence_chain_sha256": canonical_hash(receipts),
            "verified_rounds": len(receipts),
            "metrics": metrics,
            "results": results,
            "refunds_executed": 0,
            "notes": (
                "Model outputs are untrusted; ToolGateway policy is authoritative. "
                "NVIDIA seed determinism is best-effort. Evidence verification "
                "checks local gateway and A2A audit consistency; it is not "
                "external immutable-log or model identity attestation."
            ),
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-provider-calls", action="store_true",
                        help="Explicitly authorize bounded NVIDIA HTTPS inference requests")
    parser.add_argument("--rounds", type=int, choices=(1, 2, 3), default=1)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if not args.allow_provider_calls:
        parser.error("Hosted calls are disabled; specify --allow-provider-calls")
    # Require an explicit NVIDIA key. Do not silently load AWS Secrets Manager
    # or pick up unrelated cloud credentials from a developer workstation.
    key = os.environ.get("NVIDIA_API_KEY", "")
    if not isinstance(key, str) or not key.strip():
        parser.error("Set NVIDIA_API_KEY in the process environment (never in Git)")
    try:
        client = NIMChatClient(api_key=key, timeout_seconds=8, max_tokens=512)
        report = evaluate_hosted(client, rounds=args.rounds)
    except (NIMConfigurationError, NIMInferenceError, ValueError, RuntimeError):
        # Provider error bodies and credentials must never be mirrored in logs.
        print("Hosted Red/Blue evaluation failed closed; inspect permitted synthetic audit settings.")
        return 2
    encoded = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 0 if metrics_acceptable(report["metrics"]) else 1


def metrics_acceptable(metrics: dict) -> bool:
    return metrics["expected_outcome_passes"] == metrics["rounds"]


if __name__ == "__main__":
    raise SystemExit(main())
