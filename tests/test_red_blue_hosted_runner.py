"""Offline contract tests for the opt-in hosted Red/Blue runner.

The fake client is used ONLY inside tests: no credentials or vendor calls.
"""
from __future__ import annotations

import json

import pytest

from scripts.run_red_blue_hosted import evaluate_hosted, main, metrics_acceptable
from shadow_hunter.nim import NIMConfigurationError


class FakeHostedClient:
    def __init__(self):
        self.calls = []

    def complete_json(
        self, *, model, seed, max_tokens, system_prompt, user_prompt,
        response_schema,
    ):
        self.calls.append((model, seed))
        assert isinstance(seed, int)
        assert max_tokens == 384
        if "Red adversarial test strategist" in system_prompt:
            candidates = json.loads(user_prompt)["candidate_scenarios"]
            return {
                "scenario_id": candidates[0]["scenario_id"],
                "attack_hypothesis": "Test synthetic ownership boundary.",
                "injection_text": "",
            }
        assert "Blue defensive analyst" in system_prompt
        return {
            "risk_score": 0,
            "threat_categories": [],
            "indicators": [],
            "recommended_action": "ROUTE_TO_POLICY_GATEWAY",
            "analysis_summary": "The model is advisory only.",
        }


def test_model_assisted_runner_still_requires_real_gateway_authority(monkeypatch):
    monkeypatch.delenv("SHADOW_HUNTER_NIM_RED_MODEL", raising=False)
    monkeypatch.delenv("SHADOW_HUNTER_NIM_BLUE_MODEL", raising=False)
    fake = FakeHostedClient()
    report = evaluate_hosted(fake, rounds=1)
    assert len(fake.calls) == 2
    assert fake.calls[0][0] != fake.calls[1][0]
    assert report["verified_rounds"] == 1
    assert report["configured_model_calls"] == 2
    assert report["metrics"]["rounds"] == 1
    assert report["results"][0]["decision"] == "DENY"
    assert report["results"][0]["reason_code"] == "RESOURCE_OWNER_MISMATCH"
    assert report["results"][0]["evidence_verified"] is True
    assert len(report["results"][0]["evidence_sha256"]) == 64
    assert report["refunds_executed"] == 0
    assert metrics_acceptable(report["metrics"]) is True
    assert "private" not in json.dumps(report).lower()


def test_hosted_runner_rejects_using_one_model_for_red_and_blue(monkeypatch):
    monkeypatch.setenv("SHADOW_HUNTER_NIM_RED_MODEL", "nvidia/synthetic-test")
    monkeypatch.setenv("SHADOW_HUNTER_NIM_BLUE_MODEL", "nvidia/synthetic-test")
    fake = FakeHostedClient()
    with pytest.raises(NIMConfigurationError, match="distinct"):
        evaluate_hosted(fake)
    assert fake.calls == []


@pytest.mark.parametrize("rounds", [0, 4, True, -2, "2"])
def test_hosted_round_budget_is_bounded(rounds):
    with pytest.raises(ValueError, match="1–3 rounds"):
        evaluate_hosted(FakeHostedClient(), rounds=rounds)


def test_hosted_cli_never_calls_provider_without_explicit_optin():
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2


def test_hosted_cli_requires_separate_provider_key(monkeypatch):
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    with pytest.raises(SystemExit) as exc:
        main(["--allow-provider-calls"])
    assert exc.value.code == 2
