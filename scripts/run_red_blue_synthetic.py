"""Run a reproducible, fully local synthetic Red/Blue security evaluation.

This is a deterministic engine, NOT a hosted LLM evaluation. It exercises
real signed A2A messages, single-use nonces, policy gateway calls and an
independent audit reconciler inside a temporary SQLite database. No network,
cloud, accounts, live orders or provider credentials are needed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import tempfile
from pathlib import Path

from shadow_hunter.agents import (
    AdversarialStrategyEngine,
    AgentAuthenticator,
    AgentCredential,
    EvaluationMetrics,
    RedBlueSimulation,
    default_refund_attack_scenarios,
)
from shadow_hunter.approvals import ApprovalService
from shadow_hunter.evidence import verify_round_evidence
from shadow_hunter.gateway import ToolGateway
from shadow_hunter.policy import PolicyConfig, PolicyEngine, Principal
from shadow_hunter.store import SQLiteStore


def canonical_hash(data: object) -> str:
    return hashlib.sha256(
        json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def evaluate(*, rounds: int = 8) -> dict:
    if isinstance(rounds, bool) or not isinstance(rounds, int) or not 1 <= rounds <= 8:
        raise ValueError("synthetic evaluation supports 1–8 bounded rounds")
    with tempfile.TemporaryDirectory(prefix="shadow-hunter-red-blue-") as directory:
        store = SQLiteStore(Path(directory) / "synthetic.sqlite3")
        store.add_order(
            order_id="synthetic-owned-order",
            tenant_id="synthetic-tenant",
            customer_id="synthetic-customer",
            currency="USD",
            refundable_minor=25_000,
        )
        store.add_order(
            order_id="synthetic-foreign-order",
            tenant_id="synthetic-tenant",
            customer_id="synthetic-other-customer",
            currency="USD",
            refundable_minor=15_000,
        )
        principal = Principal(
            subject_id="synthetic-principal",
            tenant_id="synthetic-tenant",
            customer_id="synthetic-customer",
            authenticated=True,
        )
        policy = PolicyEngine(PolicyConfig(self_service_refund_limit_minor=10_000))
        gateway = ToolGateway(store, policy, ApprovalService(store, ttl_seconds=600))
        # Cryptographically random ephemeral keys prevent replay across runs.
        # Signature metadata and private keys never appear in the report.
        auth = AgentAuthenticator({
            "red-ephemeral": AgentCredential("red-agent", secrets.token_urlsafe(48)),
            "blue-ephemeral": AgentCredential("blue-agent", secrets.token_urlsafe(48)),
        })
        scenarios = default_refund_attack_scenarios(
            own_order_id="synthetic-owned-order",
            foreign_order_id="synthetic-foreign-order",
            currency="USD",
            refundable_minor=25_000,
            self_service_limit_minor=10_000,
        )
        catalogue = {
            scenario.scenario_id: {
                "tool_name": scenario.tool_name,
                "expected_decision": scenario.expected_decision.value,
                "expected_reason_code": scenario.expected_reason_code,
                "is_attack": scenario.is_attack,
                "strategy_id": scenario.strategy_id,
            }
            for scenario in scenarios
        }
        runner = RedBlueSimulation(
            store=store,
            gateway=gateway,
            authenticator=auth,
            red_key_id="red-ephemeral",
            blue_key_id="blue-ephemeral",
            nonce_store=store,
        )
        observations = runner.run_autonomous_loop(
            AdversarialStrategyEngine(scenarios),
            principal=principal,
            rounds=rounds,
        )
        receipts = []
        rows = []
        for observation in observations:
            scenario = next(item for item in scenarios if item.scenario_id == observation.scenario_id)
            evidence = store.get_trace_events(observation.trace_id)
            proofs = [event for event in evidence if event.get("event_type") == "A2A_EVIDENCE_VERIFIED"]
            if len(proofs) != 1:
                raise RuntimeError("missing or duplicate independent verification events")
            receipt = verify_round_evidence(
                store, observation,
                expected_tool_name=scenario.tool_name,
                expected_principal_id=principal.subject_id,
            )
            if proofs[0].get("details") != receipt.to_dict():
                raise RuntimeError("stored evidence receipt does not match gateway evidence")
            receipts.append(receipt.semantic_sha256)
            rows.append({
                "round": observation.round_number,
                "scenario_id": observation.scenario_id,
                "strategy_id": observation.strategy_id,
                "expected_decision": scenario.expected_decision.value,
                "actual_decision": observation.decision.value,
                "reason_code": observation.reason_code,
                "is_attack": observation.is_attack,
                "passed": observation.passed,
                "threat_categories": list(observation.threat_categories),
                "risk_score": observation.risk_score,
                "evidence_sha256": receipt.semantic_sha256,
            })
        if store.overview()["executed_refunds"] != 0:
            raise RuntimeError("security evaluation must never execute refunds")
        metrics = EvaluationMetrics.from_observations(observations).to_dict()
        return {
            "schema_version": "red-blue-evaluation-v1",
            "runtime": "deterministic_local_synthetic",
            "hosted_model_used": False,
            "hosted_model_verified": False,
            "policy_authoritative": True,
            "a2a_authentication": "hmac_sha256_ephemeral",
            "verification_method": "persisted_a2a_and_policy_v1",
            "policy_id": policy.config.policy_id,
            "policy_version": policy.config.version,
            "catalogue_sha256": canonical_hash(catalogue),
            "evidence_chain_sha256": canonical_hash(receipts),
            "metrics": metrics,
            "results": rows,
            "all_expected_outcomes_passed": all(row["passed"] for row in rows),
            "refunds_executed": 0,
            "limitations": (
                "Synthetic in-process A2A and SQLite audit proof only. "
                "Not a hosted Red/Blue model test, remote-agent identity "
                "attestation, AWS audit integrity proof, or production safety claim."
            ),
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, choices=range(1, 9), default=8)
    parser.add_argument("--output", type=Path, help="Write stable redacted JSON evidence")
    args = parser.parse_args(argv)
    report = evaluate(rounds=args.rounds)
    encoded = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 0 if report["all_expected_outcomes_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
