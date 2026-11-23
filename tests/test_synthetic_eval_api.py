"""Operator's keyless Red/Blue lab: only synthetic, verified local evidence."""
from __future__ import annotations

from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shadow_hunter.auth import TokenAuthenticator
from shadow_hunter.store import SQLiteStore


@pytest.fixture
def setup_lab(tmp_path, monkeypatch):
    # The module-level app is constructed at import time, so stub MCP before
    # importing api on systems without the project's exact SDK build.
    import shadow_hunter.mcp_server as mcp_server

    class SessionManager:
        def run(self):
            return nullcontext()

    stub = lambda *_: (SimpleNamespace(session_manager=SessionManager()), FastAPI())
    monkeypatch.setattr(mcp_server, "build_mcp_runtime", stub)
    import shadow_hunter.api as api
    monkeypatch.setattr(api, "build_mcp_runtime", stub)
    monkeypatch.setenv("SHADOW_HUNTER_SYNTHETIC_EVAL_ENABLED", "true")
    monkeypatch.setenv("SHADOW_HUNTER_EVAL_ENABLED", "false")
    store = SQLiteStore(tmp_path / "operator-real-data.sqlite3")
    app = api.create_app(
        store=store,
        authenticator=TokenAuthenticator(
            operator_tokens={"operator-token": {"subject_id": "operator-1"}},
            customer_tokens={"customer-token": {
                "subject_id": "customer-1",
                "tenant_id": "tenant-1",
                "customer_id": "customer-1",
            }},
        ),
    )
    return TestClient(app), store, api


def invoke(client, payload=None, *, token="operator-token"):
    return client.post(
        "/v1/operator/agent-evaluations/synthetic",
        headers={"Authorization": "Bearer " + token} if token else {},
        json={"rounds": 2} if payload is None else payload,
    )


def test_operator_can_run_keyless_synthetic_red_blue_and_view_verified_receipts(setup_lab):
    client, store, _ = setup_lab
    result = invoke(client)
    assert result.status_code == 200, result.text
    data = result.json()
    assert data["runtime"] == "deterministic_local_synthetic"
    assert data["hosted_model_used"] is False
    assert data["provider"] == "none"
    assert data["verified_rounds"] == 2
    assert data["refunds_executed"] == 0
    assert len(data["results"]) == 2
    assert all(row["evidence_verified"] and len(row["evidence_sha256"]) == 64
               for row in data["results"])
    assert store.get_order("synthetic-owned-order") is None
    assert store.overview()["refund_requests"] == 0
    assert store.overview()["executed_refunds"] == 0

    latest = client.get(
        "/v1/operator/agent-evaluations/latest",
        headers={"Authorization": "Bearer operator-token"},
    )
    assert latest.status_code == 200
    snapshot = latest.json()
    assert snapshot["run"]["trace_id"] == data["run_id"]
    assert snapshot["run"]["details"]["hosted_model_used"] is False
    assert len(snapshot["results"]) == 2
    assert all(row["details"]["evidence_verified"] for row in snapshot["results"])
    assert result.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("token", [None, "customer-token", "invalid"])
def test_synthetic_evaluation_requires_operator_identity(setup_lab, token):
    client, store, _ = setup_lab
    assert invoke(client, token=token).status_code == 401
    assert store.latest_agent_evaluation()["run"] is None


@pytest.mark.parametrize("payload", [
    {"rounds": 0}, {"rounds": 9}, {"rounds": True},
    {"rounds": 1.5}, {"rounds": "8"},
    {"rounds": 1, "tenant_id": "other"}, {"rounds": 2, "model": "hosted"},
])
def test_synthetic_endpoint_rejects_unbounded_or_authority_fields(setup_lab, payload):
    client, store, _ = setup_lab
    assert invoke(client, payload=payload).status_code == 422
    assert store.latest_agent_evaluation()["run"] is None


def test_synthetic_operator_cooldown_is_fail_closed(setup_lab):
    client, _, _ = setup_lab
    assert invoke(client, payload={"rounds": 1}).status_code == 200
    blocked = invoke(client, payload={"rounds": 1})
    assert blocked.status_code == 429
    assert "cooldown" in blocked.json()["detail"].lower()


def test_synthetic_evaluation_can_be_disabled(setup_lab, monkeypatch):
    client, store, _ = setup_lab
    monkeypatch.setenv("SHADOW_HUNTER_SYNTHETIC_EVAL_ENABLED", "false")
    assert invoke(client).status_code == 503
    assert store.latest_agent_evaluation()["run"] is None


def test_synthetic_evidence_failure_never_marks_run_complete(setup_lab, monkeypatch):
    client, store, api = setup_lab
    def fail(*, rounds):
        raise RuntimeError("synthetic evidence mismatch")
    monkeypatch.setattr(api, "evaluate_synthetic", fail)
    response = invoke(client)
    assert response.status_code == 503
    assert store.latest_agent_evaluation()["run"] is None
    assert "synthetic evidence mismatch" not in response.text


def test_dashboard_offline_lab_controls_are_present_and_distinguishable():
    from pathlib import Path
    html = (Path(__file__).resolve().parents[1] / "src/shadow_hunter/web/operator.html").read_text(encoding="utf-8")
    assert 'id="run-synthetic-evaluation"' in html
    assert 'id="agent-eval-mode"' in html
    assert '"/v1/operator/agent-evaluations/synthetic"' in html
    assert "No API key or cloud model calls" in html
    assert "deterministic_local_synthetic" in html
