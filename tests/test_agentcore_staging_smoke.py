from __future__ import annotations

import json

import pytest

from scripts import smoke_agentcore_staging as smoke


def fake_sender(base_url, method, path, *, token=None, payload=None):
    assert base_url == smoke.STAGING_BASE
    if path == "/health":
        return smoke.Response(200, json.dumps({
            "status": "ok", "agentcore_configured": True, "demo_mode": False
        }).encode())
    if path == "/operator/config":
        return smoke.Response(200, b'{}')
    if path == "/v1/operator/overview":
        return smoke.Response(200 if token == "operator-secret" else 401)
    if path == "/v1/agent/chat":
        return smoke.Response(200 if token == "customer-secret" else 401)
    if path == "/v1/agent/tools/get_order":
        return smoke.Response(200 if token == "obo-secret" else 401)
    raise AssertionError((method, path))


def test_boundary_probe_never_claims_authenticated_e2e():
    ok, messages = smoke.run_checks(
        smoke.STAGING_BASE, {}, boundary_only=True, sender=fake_sender
    )
    assert ok is True
    assert any("BOUNDARY ONLY" in line for line in messages)


def test_full_e2e_requires_all_three_tokens_and_synthetic_order():
    tokens = {"customer": "customer-secret", "operator": "operator-secret"}
    ok, messages = smoke.run_checks(
        smoke.STAGING_BASE, tokens, synthetic_order_id="synthetic-order",
        sender=fake_sender, invoke_model=True,
    )
    assert ok is False
    assert any("INCOMPLETE" in line for line in messages)


def test_full_e2e_requires_live_managed_harness_inference():
    tokens = {
        "customer": "customer-secret",
        "obo": "obo-secret",
        "operator": "operator-secret",
    }
    ok, messages = smoke.run_checks(
        smoke.STAGING_BASE, tokens, synthetic_order_id="synthetic-order",
        sender=fake_sender, invoke_model=False,
    )
    assert ok is False
    assert any("NOT RUN" in line for line in messages)


def test_full_authenticated_probe_covers_separated_jwt_boundaries():
    tokens = {
        "customer": "customer-secret",
        "obo": "obo-secret",
        "operator": "operator-secret",
    }
    ok, messages = smoke.run_checks(
        smoke.STAGING_BASE, tokens, synthetic_order_id="synthetic-order",
        sender=fake_sender, invoke_model=True,
    )
    assert ok is True
    assert len([line for line in messages if line.startswith("PASS")]) == 10
    assert not any(secret in " ".join(messages) for secret in tokens.values())


@pytest.mark.parametrize("bad_url", [
    "https://evil.example/prod",
    "http://eh90jsiseg.execute-api.ap-southeast-2.amazonaws.com/prod",
    "https://eh90jsiseg.execute-api.ap-southeast-2.amazonaws.com/other",
    "https://eh90jsiseg.execute-api.ap-southeast-2.amazonaws.com/prod?next=1",
    "https://eh90jsiseg.execute-api.ap-southeast-2.amazonaws.com.evil.example/prod",
    "https://alice@eh90jsiseg.execute-api.ap-southeast-2.amazonaws.com/prod",
])
def test_probes_never_send_customer_tokens_to_unapproved_urls(bad_url):
    with pytest.raises(ValueError, match="staging URL"):
        smoke.validate_base_url(bad_url)
