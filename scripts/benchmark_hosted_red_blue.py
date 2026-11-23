"""Authenticated hosted Red/Blue benchmark with audit-backed comparison.

Only the pinned Shadow Hunter staging operator API can be called. No customer
tokens, user data, NIM keys or provider response bodies are printed or written.
It is not a production penetration test or an ungoverned attack harness.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from time import monotonic, sleep
from typing import Any
from urllib import error, request
from uuid import UUID

from scripts.smoke_agentcore_staging import STAGING_BASE, Response, _NoRedirect

METRIC_KEYS = (
    "rounds", "attack_attempts", "attack_successes", "attacks_prevented",
    "control_cases", "false_denials", "expected_outcome_passes",
    "attack_success_rate", "defensive_effectiveness", "false_denial_rate",
    "policy_decision_accuracy",
)
ATTACK_DENIALS = frozenset(("DENY", "ESCALATE"))
RESULT_LIMIT = 256 * 1024


def send_benchmark(
    path: str, token: str, *, method: str = "GET", payload: dict | None = None,
) -> Response:
    if not path.startswith("/v1/operator/") or ".." in path or "?" in path:
        raise ValueError("Only fixed, approved staging operator routes are permitted")
    if not token or any(ch.isspace() for ch in token):
        raise ValueError("Missing operator access token")
    body = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else None
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = request.Request(STAGING_BASE + path, headers=headers, data=body, method=method)
    try:
        with request.build_opener(_NoRedirect()).open(req, timeout=45) as response:
            return Response(response.status, response.read(RESULT_LIMIT + 1))
    except error.HTTPError as exc:
        # Never expose provider errors or authenticated response body.
        return Response(exc.code)


def _decode(response: Response) -> dict[str, Any]:
    if response.status != 200 or len(response.body) > RESULT_LIMIT:
        raise ValueError("Hosted benchmark API did not return an acceptable result")
    try:
        value = json.loads(response.body)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Hosted benchmark response is not JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("Hosted benchmark response must be an object")
    return value


def _metrics(payload: Mapping[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows or len(rows) > 3:
        raise ValueError("Hosted benchmark row count is invalid")
    for row in rows:
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("is_attack"), bool)
            or row.get("decision") not in {"ALLOW", "DENY", "ESCALATE"}
            or not isinstance(row.get("passed"), bool)
            or not isinstance(row.get("attack_success"), bool)
        ):
            raise ValueError("Hosted benchmark cases are invalid")
    attack_rows = [r for r in rows if r["is_attack"]]
    control_rows = [r for r in rows if not r["is_attack"]]
    attack_successes = sum(r["attack_success"] for r in attack_rows)
    true_positive = sum(r["decision"] in ATTACK_DENIALS for r in attack_rows)
    false_negative = len(attack_rows) - true_positive
    false_positive = sum(r["decision"] in ATTACK_DENIALS for r in control_rows)
    true_negative = len(control_rows) - false_positive
    observed = {
        "rounds": len(rows),
        "attack_attempts": len(attack_rows),
        "attack_successes": attack_successes,
        "attacks_prevented": len(attack_rows) - attack_successes,
        "control_cases": len(control_rows),
        "false_denials": false_positive,
        "expected_outcome_passes": sum(r["passed"] for r in rows),
        "attack_success_rate": round(attack_successes / len(attack_rows), 4) if attack_rows else 0.0,
        "defensive_effectiveness": round((len(attack_rows) - attack_successes) / len(attack_rows), 4) if attack_rows else 0.0,
        "false_denial_rate": round(false_positive / len(control_rows), 4) if control_rows else 0.0,
        "policy_decision_accuracy": round(sum(r["passed"] for r in rows) / len(rows), 4),
    }
    for key in METRIC_KEYS:
        value = payload.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("Hosted benchmark metric is missing or invalid")
        if abs(value - observed[key]) > 0.00011:
            raise ValueError("Hosted benchmark counters disagree with case outcomes")
    return {
        "metrics": observed,
        "decision_matrix": {
            "attack_blocked": true_positive,
            "attack_allowed": false_negative,
            "legitimate_blocked": false_positive,
            "legitimate_allowed": true_negative,
        },
    }


def analyze_hosted_result(payload: dict, audit: list, *, expected_rounds: int) -> dict:
    if not isinstance(payload, dict) or not isinstance(audit, list):
        raise ValueError("Benchmark evidence is invalid")
    rows = payload.get("results")
    run_id = payload.get("run_id")
    try:
        valid_id = isinstance(run_id, str) and str(UUID(run_id)) == run_id.lower()
    except (ValueError, AttributeError):
        valid_id = False
    if not valid_id or not isinstance(rows, list) or len(rows) != expected_rounds:
        raise ValueError("Benchmark run identity or requested round count is invalid")
    analysis = _metrics(payload, rows)
    if (
        isinstance(payload.get("verified_rounds"), bool)
        or payload.get("verified_rounds") != expected_rounds
    ):
        raise ValueError("Hosted benchmark has incomplete independently verified rounds")
    scenario_ids = [row.get("scenario_id") for row in rows]
    if any(not isinstance(value, str) or not value for value in scenario_ids):
        raise ValueError("Hosted benchmark scenario identity is missing")
    if len(set(scenario_ids)) != len(rows):
        raise ValueError("Hosted benchmark scenario identities must be unique")
    for row in rows:
        if (
            row.get("evidence_verified") is not True
            or not isinstance(row.get("evidence_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", row["evidence_sha256"]) is None
        ):
            raise ValueError("Hosted benchmark result lacks independently verified gateway evidence")
    runs = [
        x for x in audit
        if isinstance(x, dict) and x.get("event_type") == "AGENT_EVALUATION_RUN"
        and x.get("trace_id") == run_id
        and isinstance(x.get("details"), dict)
        and x["details"].get("runtime") == "hosted_nvidia_nim"
    ]
    if len(runs) != 1:
        raise ValueError("Hosted model invocation is not supported by an audit run event")
    details = runs[0]["details"]
    if (
        details.get("verified_rounds") != expected_rounds
        or details.get("evidence_verification") != "persisted_a2a_and_policy_v1"
    ):
        raise ValueError("Hosted benchmark audit does not attest verified rounds")
    for key in METRIC_KEYS:
        if details.get(key) != analysis["metrics"][key]:
            raise ValueError("Hosted benchmark audit metrics disagree")
    outcomes = [
        x for x in audit if isinstance(x, dict)
        and x.get("event_type") == "AGENT_EVALUATION_RESULT"
        and x.get("trace_id") == run_id
    ]
    if len(outcomes) != len(rows):
        raise ValueError("Hosted evaluation cases are not all present in audit evidence")
    # Independently reconcile the response against persisted case results and
    # each A2A_EVIDENCE_VERIFIED event copied from the synthetic sandbox.
    proofs = [
        event for event in audit if isinstance(event, dict)
        and event.get("event_type") == "AGENT_EVALUATION_TRACE_EVENT"
        and event.get("trace_id") == run_id
        and isinstance(event.get("details"), dict)
        and event["details"].get("source_event_type") == "A2A_EVIDENCE_VERIFIED"
    ]
    if len(proofs) != expected_rounds:
        raise ValueError("Hosted benchmark is missing independent gateway proof events")
    for row in rows:
        matches = [
            event for event in outcomes
            if isinstance(event.get("details"), dict)
            and event["details"].get("scenario_id") == row["scenario_id"]
            and event["details"].get("evidence_verified") is True
            and event["details"].get("evidence_sha256") == row["evidence_sha256"]
            and event.get("decision") == row["decision"]
        ]
        proof_matches = [
            event for event in proofs
            if event["details"].get("scenario_id") == row["scenario_id"]
            and event["details"].get("evidence_sha256") == row["evidence_sha256"]
            and event["details"].get("verification_method") == "persisted_a2a_and_policy_v1"
        ]
        if len(matches) != 1 or len(proof_matches) != 1:
            raise ValueError("Hosted benchmark case is not supported by matching gateway evidence")
    return {
        "report_type": "shadow_hunter_hosted_evaluation_v1",
        "provenance": "authenticated_staging_hosted_nim_and_audit",
        "run_id": run_id,
        "model": {
            "red": str(details.get("red_model", ""))[:160],
            "blue": str(details.get("blue_model", ""))[:160],
        },
        "rounds": expected_rounds,
        "verified_rounds": expected_rounds,
        "verification_method": "persisted_a2a_and_policy_v1",
        **analysis,
        "comparison": (
            "Attack vs legitimate control outcomes within the same hosted run; "
            "NOT a controlled experiment against an unprotected model."
        ),
        "limitations": (
            "Synthetic workload and short run; cannot establish statistical "
            "robustness, real-world adversarial resistance or production security."
        ),
    }


def run_benchmark(
    sender: Callable, operator_token: str, *, rounds: int = 3,
    pause: Callable = sleep, clock: Callable = monotonic,
) -> dict:
    if not operator_token or not 1 <= rounds <= 3:
        raise ValueError("Real operator token and 1-3 rounds are required")
    start = clock()
    result = _decode(sender(
        "/v1/operator/agent-evaluations/run", operator_token,
        method="POST", payload={"rounds": rounds},
    ))
    run_id = result.get("run_id")
    if not isinstance(run_id, str) or not 1 <= len(run_id) <= 64:
        raise ValueError("Invalid run ID")
    evidence = []
    # Three bounded retries for DynamoDB GSI eventual consistency.
    for attempt in range(3):
        response = sender("/v1/operator/audit/trace/" + run_id, operator_token)
        evidence = _read_trace(response)
        if evidence:
            break
        if attempt < 2:
            pause(0.4 * (attempt + 1))
    report = analyze_hosted_result(result, evidence, expected_rounds=rounds)
    report["client_elapsed_seconds"] = round(clock() - start, 3)
    return report


def _read_trace(response: Response) -> list:
    if response.status != 200 or len(response.body) > RESULT_LIMIT:
        raise ValueError("Could not read restricted audit trace")
    try:
        data = json.loads(response.body)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Audit trace is invalid JSON") from exc
    if not isinstance(data, list):
        raise ValueError("Audit trace is not an array")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--invoke-hosted-model", action="store_true")
    parser.add_argument("--acknowledge-charges", action="store_true")
    parser.add_argument("--rounds", type=int, default=3, choices=(1, 2, 3))
    parser.add_argument("--report-file", help="Local sanitized JSON report path")
    args = parser.parse_args(argv)
    if not (args.invoke_hosted_model and args.acknowledge_charges):
        print("NOT RUN: hosted evaluation requires --invoke-hosted-model and --acknowledge-charges")
        return 2
    token = os.environ.get("SHADOW_HUNTER_E2E_OPERATOR_JWT", "")
    if not token:
        print("BLOCKED genuine operator JWT is not configured")
        return 2
    try:
        report = run_benchmark(send_benchmark, token, rounds=args.rounds)
    except (ValueError, OSError, TimeoutError):
        print("BLOCKED hosted benchmark or audit verification did not complete")
        return 1
    output = json.dumps(report, sort_keys=True, indent=2)
    if args.report_file:
        file = Path(args.report_file)
        if file.exists():
            print("BLOCKED report path already exists; refusing overwrite")
            return 2
        file.write_text(output + "\n", encoding="utf-8")
        print("PASS audited hosted benchmark report written to selected local path")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
