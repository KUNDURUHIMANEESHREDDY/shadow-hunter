"""Offline sponsor integration tests: no external provider requests are made."""
from contextlib import nullcontext
from types import SimpleNamespace
import json
from unittest.mock import patch
import urllib.error

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shadow_hunter.sponsors import (
    BandDecisionPublisher,
    LyzrAdvisor,
    SponsorConfigurationError,
    SponsorProviderError,
    _post_json,
    sponsor_status,
)


class _Response:
    status = 200

    def __init__(self, data):
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, count):
        return self.data


def test_lyzr_uses_real_documented_inference_path_and_never_authorizes(monkeypatch):
    recorded = {}

    def fake_post(url, header, key, body):
        recorded.update(url=url, header=header, key=key, body=body)
        return {"response": "Advisory risk: require gateway approval"}

    monkeypatch.setattr("shadow_hunter.sponsors._post_json", fake_post)
    answer = LyzrAdvisor("lyzr-sample-key", "agent-123", "demo-user").advise("Synthetic policy review")
    assert "require gateway approval" in answer
    assert recorded["url"] == "https://agent-prod.studio.lyzr.ai/v3/inference/chat/"
    assert recorded["header"] == "x-api-key"
    assert recorded["body"]["agent_id"] == "agent-123"
    assert recorded["body"]["session_id"].startswith("shadow-hunter-")
    assert "refund_request" not in recorded["body"]
    assert "tool" not in recorded["body"]


def test_lyzr_rejects_unconfigured_oversize_and_invalid_provider_output(monkeypatch):
    with pytest.raises(SponsorConfigurationError):
        LyzrAdvisor("", "agent-123", "user")
    client = LyzrAdvisor("lyzr-sample-key", "agent-123", "user")
    with pytest.raises(SponsorConfigurationError):
        client.advise("x" * 1501)
    monkeypatch.setattr("shadow_hunter.sponsors._post_json", lambda *_: {"response": ""})
    with pytest.raises(SponsorProviderError):
        client.advise("Synthetic test")


def test_band_publication_contains_only_bound_policy_summary(monkeypatch):
    calls = []

    def fake_post(*args):
        calls.append(args)
        return {}

    monkeypatch.setattr("shadow_hunter.sponsors._post_json", fake_post)
    publisher = BandDecisionPublisher("band-demo-key", "chat-123", "peer-123")
    publisher.publish_decision("DENY", "RESOURCE_OWNER_MISMATCH")
    url, header, key, body = calls[0]
    assert url == "https://app.band.ai/api/v1/agent/chats/chat-123/messages"
    assert header == "X-API-Key"
    assert body["message"]["mentions"] == [{"id": "peer-123"}]
    assert "DENY" in body["message"]["content"]
    assert "customer" not in body["message"]["content"].lower()
    for decision, reason in (("ALLOW", "script injection"), ("REFUND_NOW", "POLICY"), ("DENY", "a/b")):
        with pytest.raises(SponsorConfigurationError):
            publisher.publish_decision(decision, reason)
    with pytest.raises(SponsorConfigurationError):
        BandDecisionPublisher("band-demo-key", "https://evil.example/path")


def test_post_json_disables_redirects_and_rejects_oversize(monkeypatch):
    captured = {}

    def fake_open(request, timeout):
        captured["url"] = request.full_url
        captured["timeout"] = timeout
        captured["headers"] = dict(request.header_items())
        return _Response(b'{"response":"ok"}')

    monkeypatch.setattr("shadow_hunter.sponsors._HTTP.open", fake_open)
    answer = _post_json("https://agent-prod.studio.lyzr.ai/v3/inference/chat/", "x-api-key", "fake-key", {"message": "hello"})
    assert answer == {"response": "ok"}
    assert captured["timeout"] == 7.0
    assert captured["url"].startswith("https://")
    with pytest.raises(SponsorConfigurationError):
        _post_json("https://x", "X-API-Key", "key", {"message": "x" * 9000})
    assert any(type(x).__name__ == "_NoRedirect" for x in __import__("shadow_hunter.sponsors", fromlist=["_HTTP"])._HTTP.handlers)


def test_sponsor_status_never_discloses_credentials(monkeypatch):
    monkeypatch.setenv("SHADOW_HUNTER_BAND_API_KEY", "private-band-credential")
    monkeypatch.setenv("SHADOW_HUNTER_BAND_CHAT_ID", "chat-1")
    raw = json.dumps(sponsor_status())
    assert "private-band-credential" not in raw
    assert sponsor_status()["band"]["configured"] is True
    assert sponsor_status()["finch"]["configured"] is False


class _SessionManager:
    def run(self):
        return nullcontext()


def _client(tmp_path, monkeypatch):
    import shadow_hunter.api as api
    from shadow_hunter.auth import TokenAuthenticator
    from shadow_hunter.store import SQLiteStore
    monkeypatch.setattr(
        api,
        "build_mcp_runtime",
        lambda *_: (SimpleNamespace(session_manager=_SessionManager()), FastAPI()),
    )
    app = api.create_app(
        store=SQLiteStore(tmp_path / "sponsors.sqlite3"),
        authenticator=TokenAuthenticator(
            operator_tokens={"operator-token": {"subject_id": "operator-demo"}}
        ),
    )
    return TestClient(app), app


def test_sponsor_routes_require_operator_and_fail_closed_without_config(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)
    assert client.get("/v1/operator/sponsors/status").status_code == 401
    assert client.post("/v1/operator/sponsors/lyzr/advise", json={"scenario": "demo"}).status_code == 401
    assert client.post("/v1/operator/sponsors/band/publish-trace", json={"trace_id": "trace"}).status_code == 401
    headers = {"Authorization": "Bearer operator-token"}
    monkeypatch.delenv("SHADOW_HUNTER_LYZR_API_KEY", raising=False)
    assert client.post("/v1/operator/sponsors/lyzr/advise", headers=headers, json={"scenario": "demo"}).status_code == 503
    assert client.post("/v1/operator/sponsors/band/publish-trace", headers=headers, json={"trace_id": "missing"}).status_code == 404
    assert "api_key" not in client.get("/v1/operator/sponsors/status", headers=headers).text


def test_sponsor_lyzr_operator_advice_is_audited_and_advisory_only(tmp_path, monkeypatch):
    client, app = _client(tmp_path, monkeypatch)
    from shadow_hunter.sponsors import LyzrAdvisor
    monkeypatch.setattr(LyzrAdvisor, "from_environment", classmethod(lambda cls: LyzrAdvisor("sample-key-123", "a1", "u1")))
    monkeypatch.setattr(LyzrAdvisor, "advise", lambda self, scenario: "Review policy independently")
    headers = {"Authorization": "Bearer operator-token"}
    result = client.post("/v1/operator/sponsors/lyzr/advise", headers=headers, json={"scenario": "synthetic"})
    assert result.status_code == 200
    assert result.json()["authority"] == "advisory_only"
    assert "Review policy" in result.json()["advice"]
    assert any(event["event_type"] == "SPONSOR_LYZR_ADVICE_REQUESTED" for event in app.state.store.list_audit())


def test_band_publish_uses_persisted_decision_not_user_supplied_verdict(tmp_path, monkeypatch):
    client, app = _client(tmp_path, monkeypatch)
    published = []
    from shadow_hunter.sponsors import BandDecisionPublisher
    monkeypatch.setattr(BandDecisionPublisher, "from_environment", classmethod(lambda cls: cls("sample-key-123", "room-1")))
    monkeypatch.setattr(BandDecisionPublisher, "publish_decision", lambda self, decision, reason: published.append((decision, reason)))
    app.state.store.append_audit(
        event_type="POLICY_DECISION", trace_id="trace-sponsor-1", request_id="req-1",
        decision="DENY", reason_code="UNKNOWN_OR_FORBIDDEN_TOOL", actor_id="demo-customer",
        tenant_id="tenant-1", resource_id="internal-order",
    )
    headers = {"Authorization": "Bearer operator-token"}
    result = client.post(
        "/v1/operator/sponsors/band/publish-trace",
        headers=headers,
        json={"trace_id": "trace-sponsor-1"},
    )
    assert result.status_code == 200
    assert published == [("DENY", "UNKNOWN_OR_FORBIDDEN_TOOL")]
    assert result.json()["summary_only"] is True
    assert "internal-order" not in result.text
    assert app.state.store.get_trace_events("trace-sponsor-1")[-1]["event_type"] == "SPONSOR_BAND_SUMMARY_PUBLISHED"
    assert client.post(
        "/v1/operator/sponsors/band/publish-trace",
        headers=headers,
        json={"trace_id": "trace-sponsor-1", "decision": "ALLOW"},
    ).status_code == 422
