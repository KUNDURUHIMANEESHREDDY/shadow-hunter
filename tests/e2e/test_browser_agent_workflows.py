"""Real Chromium -> localhost HTTP -> actual FastAPI/policy/SQLite E2E tests.

No mocked business decisions. Only optional external sponsor responses are
stubbed in one browser-boundary test; provider connectivity is not claimed.
"""
from __future__ import annotations

import pytest

pytest.importorskip("playwright.sync_api")
from playwright.sync_api import expect

from .conftest import (
    CUSTOMER_TOKEN, FOREIGN_ORDER, FOREIGN_TOKEN,
    OPERATOR_TOKEN, OWN_ORDER,
)


def agent_tool(page, base_url, token, tool_name, arguments, *, trace_id=None):
    body = {"arguments": arguments}
    if trace_id:
        body["trace_id"] = trace_id
    return page.request.post(
        f"{base_url}/v1/agent/tools/{tool_name}",
        headers={"Authorization": f"Bearer {token}"},
        data=body,
    )


def connect(page, base_url, token=OPERATOR_TOKEN):
    page.goto(base_url + "/operator", wait_until="domcontentloaded")
    expect(page.locator("#message")).to_contain_text("Local authentication mode")
    page.locator("#operator-token").fill(token)
    page.locator("#connect").click()
    expect(page.locator("#refresh-console")).to_be_visible()
    expect(page.locator("#message")).to_contain_text("Connected")


def test_real_browser_login_security_pulse_filters_trace_and_disconnect(page, local_server):
    base_url = local_server
    assert agent_tool(page, base_url, CUSTOMER_TOKEN, "get_order",
                      {"order_id": OWN_ORDER}, trace_id="e2e-allowed-read").json()["decision"] == "ALLOW"
    denied = agent_tool(page, base_url, CUSTOMER_TOKEN, "get_order",
                        {"order_id": FOREIGN_ORDER}, trace_id="e2e-denied-read")
    assert denied.status == 200
    assert denied.json()["decision"] == "DENY"

    connect(page, base_url)
    expect(page.locator("#security-metrics .metric").nth(0).locator("strong")).to_have_text("2")
    expect(page.locator("#security-metrics .metric").nth(1).locator("strong")).to_have_text("1")
    page.locator("#audit-decision").select_option("DENY")
    expect(page.locator("#audit tr")).to_have_count(1)
    expect(page.locator("#audit")).to_contain_text("e2e-denied")
    page.locator("#audit-search").fill("e2e-allowed")
    expect(page.locator("#audit")).to_contain_text("No matching audit events")
    page.locator("#audit-search").fill("")
    page.locator("#audit button[data-trace]").first.click()
    expect(page.locator("#trace-panel")).to_be_visible()
    expect(page.locator("#trace-id")).to_have_text("e2e-denied-read")

    page.get_by_role("button", name="Disconnect").click()
    expect(page.locator("#trace-panel")).to_be_hidden()
    expect(page.locator("#audit")).to_contain_text("Sign in to load audit events")
    expect(page.locator("#security-metrics")).to_contain_text("—")
    expect(page.locator("#refresh-console")).to_be_hidden()
    assert page.evaluate("() => !!window.localStorage.getItem('shadow_hunter_token')") is False


def test_agent_http_policy_blocks_cross_tenant_unknown_tools_and_unauthenticated_access(page, local_server):
    base_url = local_server
    assert page.request.post(
        base_url + "/v1/agent/tools/get_order",
        data={"arguments": {"order_id": OWN_ORDER}},
    ).status == 401
    owned = agent_tool(page, base_url, CUSTOMER_TOKEN, "get_order", {"order_id": OWN_ORDER})
    assert owned.status == 200
    assert owned.json()["decision"] == "ALLOW"
    foreign = agent_tool(page, base_url, CUSTOMER_TOKEN, "get_order", {"order_id": FOREIGN_ORDER})
    missing = agent_tool(page, base_url, CUSTOMER_TOKEN, "get_order", {"order_id": "missing-order"})
    assert foreign.status == missing.status == 200
    assert foreign.json()["decision"] == missing.json()["decision"] == "DENY"
    assert foreign.json()["reason_code"] == missing.json()["reason_code"] == "RESOURCE_NOT_AVAILABLE"
    assert set(foreign.json()) == set(missing.json())
    assert agent_tool(page, base_url, FOREIGN_TOKEN, "get_order",
                      {"order_id": FOREIGN_ORDER}).json()["decision"] == "ALLOW"
    forbidden = agent_tool(page, base_url, CUSTOMER_TOKEN, "execute_refund",
                           {"refund_request_id": "fake", "approval_token": "fake"})
    assert forbidden.status == 200
    assert forbidden.json()["decision"] == "DENY"
    # The stored funds are unchanged by all tool requests.
    assert agent_tool(page, base_url, CUSTOMER_TOKEN, "get_order",
                      {"order_id": OWN_ORDER}).json()["order"]["refundable_minor"] == 25_000


def test_agent_to_human_approval_to_demo_execution_in_real_browser(page, local_server):
    base_url = local_server
    requested = agent_tool(
        page, base_url, CUSTOMER_TOKEN, "create_refund_request",
        {
            "order_id": OWN_ORDER,
            "amount_minor": 5000,
            "currency": "USD",
            "reason": "Synthetic damaged item",
            "idempotency_key": "synthetic-e2e-approval-001",
        },
        trace_id="e2e-human-approval",
    )
    assert requested.status == 200
    created = requested.json()
    assert created["decision"] == "ALLOW"
    assert created["approval"]["status"] == "PENDING"
    assert created["refund_request"]["status"] == "PENDING_APPROVAL"
    assert agent_tool(page, base_url, CUSTOMER_TOKEN, "get_order",
                      {"order_id": OWN_ORDER}).json()["order"]["refundable_minor"] == 25_000

    connect(page, base_url)
    row = page.locator("#approvals tr").filter(has_text=OWN_ORDER)
    expect(row).to_be_visible()
    row.locator("[data-approve]").click()
    expect(row.locator("[data-execute]")).to_be_visible()
    page.once("dialog", lambda dialog: dialog.accept())
    row.locator("[data-execute]").click()
    expect(page.locator("#message")).to_contain_text("Refund executed in the local demo ledger")
    expect(row).to_contain_text("CONSUMED")

    order = agent_tool(page, base_url, CUSTOMER_TOKEN, "get_order",
                       {"order_id": OWN_ORDER}).json()
    assert order["decision"] == "ALLOW"
    assert order["order"]["refundable_minor"] == 20_000
    trace = page.request.get(
        base_url + "/v1/operator/audit/trace/e2e-human-approval",
        headers={"Authorization": f"Bearer {OPERATOR_TOKEN}"},
    )
    assert trace.status == 200
    assert "REFUND_EXECUTED" in {event["event_type"] for event in trace.json()}


def test_escalation_keeps_balance_unchanged_without_human_approval(page, local_server):
    base_url = local_server
    result = agent_tool(
        page, base_url, CUSTOMER_TOKEN, "create_refund_request", {
            "order_id": OWN_ORDER,
            "amount_minor": 15000,
            "currency": "USD",
            "reason": "Synthetic high value return",
            "idempotency_key": "synthetic-e2e-escalation-002",
        },
    )
    assert result.status == 200
    assert result.json()["decision"] == "ESCALATE"
    assert result.json()["refund_request"]["status"] == "PENDING_APPROVAL"
    assert agent_tool(page, base_url, CUSTOMER_TOKEN, "get_order",
                      {"order_id": OWN_ORDER}).json()["order"]["refundable_minor"] == 25_000


def test_browser_sponsor_forms_send_only_fixed_synthetic_data(page, local_server):
    base_url = local_server
    requests = []

    # Fake only the external-provider facing responses in this test. Real
    # operator sign-in, JavaScript, rendering and HTTP transport run in Chromium.
    def sponsor_status(route):
        route.fulfill(json={
            "lyzr": {"configured": True, "mode": "advisory_only"},
            "band": {"configured": True, "publication_ready": True},
        })

    def fake_lyzr(route):
        body = route.request.post_data_json
        requests.append(("lyzr", body))
        route.fulfill(json={
            "authority": "advisory_only",
            "provider": "lyzr",
            "advice": '<img src=x onerror="window.__executed=true">',
        })

    def fake_band(route):
        requests.append(("band", route.request.post_data_json))
        route.fulfill(json={"published": True, "summary_only": True, "provider": "band"})

    page.route("**/v1/operator/sponsors/status", sponsor_status)
    page.route("**/v1/operator/sponsors/lyzr/advise", fake_lyzr)
    page.route("**/v1/operator/sponsors/band/publish-trace", fake_band)

    connect(page, base_url)
    page.locator("#lyzr-scenario").select_option("unknown-tool")
    page.locator("#run-lyzr").click()
    expect(page.locator("#lyzr-advice")).to_contain_text("<img src=x onerror")
    assert page.locator("#lyzr-advice img").count() == 0
    assert page.evaluate("() => !!window.__executed") is False
    assert len(requests) == 1
    assert list(requests[0][1]) == ["scenario"]
    assert "Synthetic-only" in requests[0][1]["scenario"]
    assert OWN_ORDER not in requests[0][1]["scenario"]

    page.locator("#band-trace").fill("e2e-synthetic-trace")
    page.once("dialog", lambda dialog: dialog.accept())
    page.locator("#publish-band").click()
    expect(page.locator("#message")).to_contain_text("Redacted policy verdict published")
    assert requests[1] == ("band", {"trace_id": "e2e-synthetic-trace"})



def test_browser_evaluation_marks_only_valid_gateway_evidence_receipts(page, local_server):
    """UI shows persisted-proof status without treating model prose as authority."""
    proof = "a" * 64

    def latest_evaluation(route):
        route.fulfill(json={
            "run": {
                "details": {
                    "attack_attempts": 2,
                    "attack_success_rate": 0,
                    "defensive_effectiveness": 1,
                    "false_denial_rate": 0,
                    "policy_decision_accuracy": 1,
                    "verified_rounds": 1,
                }
            },
            "results": [
                {
                    "decision": "DENY",
                    "details": {
                        "round": 1,
                        "scenario_id": "synthetic-a",
                        "strategy_id": "ownership_probe",
                        "risk_score": 90,
                        "threat_categories": ["unauthorized_resource_access"],
                        "analysis_summary": '<svg onload="window.__unsafe=true"></svg>',
                        "passed": True,
                        "is_attack": True,
                        "attack_success": False,
                        "evidence_verified": True,
                        "evidence_sha256": proof,
                    },
                },
                {
                    "decision": "DENY",
                    "details": {
                        "round": 2,
                        "scenario_id": "synthetic-b",
                        "strategy_id": "unknown_tool",
                        "passed": True,
                        "is_attack": True,
                        "attack_success": False,
                        "evidence_verified": True,
                        "evidence_sha256": "not-a-valid-proof",
                    },
                },
            ],
        })

    page.route("**/v1/operator/agent-evaluations/latest", latest_evaluation)
    connect(page, local_server)
    table = page.locator("#agent-eval-results")
    expect(table.locator("tr")).to_have_count(2)
    expect(table.locator("tr").nth(0)).to_contain_text("Verified audit · " + proof[:12])
    expect(table.locator("tr").nth(1)).to_contain_text("Not independently verified")
    assert table.locator("svg").count() == 0
    assert page.evaluate("() => !!window.__unsafe") is False

def test_browser_runs_real_local_red_blue_lab_without_hosted_models(page, local_server):
    """Chromium invokes actual FastAPI, signed A2A and SQLite policy receipts."""
    connect(page, local_server)
    page.locator("#run-synthetic-evaluation").click()
    expect(page.locator("#agent-eval-mode")).to_contain_text(
        "Local synthetic simulation", timeout=30000
    )
    expect(page.locator("#agent-eval-results tr")).to_have_count(8)
    expect(page.locator("#agent-eval-results")).to_contain_text("Verified audit")
    latest = page.request.get(
        local_server + "/v1/operator/agent-evaluations/latest",
        headers={"Authorization": f"Bearer {OPERATOR_TOKEN}"},
    )
    assert latest.status == 200
    details = latest.json()["run"]["details"]
    assert details["hosted_model_used"] is False
    assert details["runtime"] == "deterministic_local_synthetic"
    assert details["refunds_executed"] == 0
    page.get_by_role("button", name="Disconnect").click()
    expect(page.locator("#agent-eval-mode")).to_have_text("Sign in to view evaluations.")
    expect(page.locator("#agent-eval-results")).to_contain_text("Sign in to load evaluations.")
