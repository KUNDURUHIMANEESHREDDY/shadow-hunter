"""Verify synthetic hosted comparison schema, provenance, and fail-closed behavior."""
from __future__ import annotations

import json
from uuid import uuid4
import pytest

from scripts import benchmark_hosted_red_blue as b
from scripts.smoke_agentcore_staging import Response


def payload():
    run_id = str(uuid4())
    return {
        "run_id": run_id,
        "rounds": 3,
        "attack_attempts": 2,
        "attack_successes": 0,
        "attacks_prevented": 2,
        "control_cases": 1,
        "false_denials": 0,
        "expected_outcome_passes": 3,
        "attack_success_rate": 0.0,
        "defensive_effectiveness": 1.0,
        "false_denial_rate": 0.0,
        "policy_decision_accuracy": 1.0,
        "results": [
            {"scenario_id": "synthetic-attack-1", "is_attack": True,
             "decision": "DENY", "passed": True, "attack_success": False},
            {"scenario_id": "synthetic-attack-2", "is_attack": True,
             "decision": "ESCALATE", "passed": True, "attack_success": False},
            {"scenario_id": "synthetic-control", "is_attack": False,
             "decision": "ALLOW", "passed": True, "attack_success": False},
        ],
    }


def audit(data):
    metadata = {
        "runtime": "hosted_nvidia_nim", "red_model": "nvidia/test-red",
        "blue_model": "nvidia/test-blue",
    }
    metadata.update({k: data[k] for k in b.METRIC_KEYS})
    run_id=data["run_id"]
    return [
        {"trace_id": run_id, "event_type": "AGENT_EVALUATION_RUN",
         "details": metadata},
    ] + [
        {"trace_id": run_id, "event_type": "AGENT_EVALUATION_RESULT"}
        for _ in data["results"]
    ]


def test_benchmark_requires_audited_hosted_runtime_and_correlated_results():
    data=payload()
    report=b.analyze_hosted_result(data, audit(data), expected_rounds=3)
    assert report["provenance"] == "authenticated_staging_hosted_nim_and_audit"
    assert report["decision_matrix"] == {
        "attack_blocked": 2, "attack_allowed": 0,
        "legitimate_blocked": 0, "legitimate_allowed": 1,
    }
    assert "NOT a controlled experiment" in report["comparison"]
    tampered=audit(data)
    tampered[0]["details"]["runtime"] = "local_mock"
    with pytest.raises(ValueError, match="not supported"):
        b.analyze_hosted_result(data, tampered, expected_rounds=3)


def test_inconsistent_metrics_or_incomplete_audit_fail_closed():
    data=payload()
    bad=dict(data)
    bad["attack_success_rate"]=1.0
    with pytest.raises(ValueError, match="disagree"):
        b.analyze_hosted_result(bad, audit(data), expected_rounds=3)
    with pytest.raises(ValueError, match="not all"):
        b.analyze_hosted_result(data, audit(data)[:-1], expected_rounds=3)


def test_benchmark_runner_uses_operator_token_only_for_fixed_staging_routes():
    data=payload()
    def send(path, token, *, method="GET", payload=None):
        assert token == "operator-test-jwt"
        assert path.startswith("/v1/operator/")
        if path.endswith("/run"):
            assert method == "POST"
            assert payload == {"rounds": 3}
            return Response(200, json.dumps(data).encode())
        assert path == "/v1/operator/audit/trace/" + data["run_id"]
        return Response(200, json.dumps(audit(data)).encode())
    clock=iter([10.0,12.5])
    result=b.run_benchmark(send, "operator-test-jwt", rounds=3,
                           clock=lambda: next(clock))
    assert result["client_elapsed_seconds"] == 2.5
    assert result["metrics"]["policy_decision_accuracy"] == 1.0


def test_runner_requires_genuine_operator_token_before_network():
    with pytest.raises(ValueError):
        b.run_benchmark(None, "", rounds=3)


def test_endpoint_rejects_caller_provided_nonoperator_paths():
    with pytest.raises(ValueError):
        b.send_benchmark("https://evil.test/", "fake-operator-token")
    with pytest.raises(ValueError):
        b.send_benchmark("/v1/agent/tools/get_order", "fake-operator-token")
