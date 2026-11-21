from contextlib import nullcontext
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

import shadow_hunter.mcp_server as mcp_server

class _SessionManager:
    def run(self):
        return nullcontext()

mcp_server.build_mcp_runtime = lambda _gateway, _authenticator: (
    SimpleNamespace(session_manager=_SessionManager()),
    FastAPI(),
)

from shadow_hunter.api import create_app
from shadow_hunter.auth import TokenAuthenticator
from shadow_hunter.store import SQLiteStore


class FakeIntegrationSecrets:
    def __init__(self):
        self.nim_key = None
        self.rotated = False

    def status(self):
        return {
            "nvidia_nim": {"storage_available": True, "configured": bool(self.nim_key)},
            "red_blue_signing": {"storage_available": True, "configured": self.rotated},
        }

    def save_nim_api_key(self, api_key):
        self.nim_key = api_key

    def rotate_a2a_keys(self):
        self.rotated = True
        return {"red_key_id": "red-test-01", "blue_key_id": "blue-test-01"}


def _client(tmp_path, monkeypatch):
    monkeypatch.setenv("SHADOW_HUNTER_AUTH_MODE", "local")
    monkeypatch.delenv("SHADOW_HUNTER_COGNITO_HOSTED_UI_DOMAIN", raising=False)
    monkeypatch.delenv("SHADOW_HUNTER_COGNITO_OPERATOR_CLIENT_ID", raising=False)
    secrets = FakeIntegrationSecrets()
    app = create_app(
        store=SQLiteStore(tmp_path / "operator-settings.sqlite3"),
        authenticator=TokenAuthenticator(
            operator_tokens={"operator-token": {"subject_id": "operator-1"}}
        ),
        integration_secrets=secrets,
    )
    return TestClient(app), secrets


def test_operator_integration_settings_require_operator_auth(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)

    response = client.get("/v1/operator/settings/integrations")

    assert response.status_code == 401


def test_operator_can_save_nim_key_without_echoing_or_auditing_it(tmp_path, monkeypatch):
    client, secrets = _client(tmp_path, monkeypatch)
    secret_value = "nvapi-never-return-this"

    response = client.put(
        "/v1/operator/settings/nvidia-nim",
        headers={"Authorization": "Bearer operator-token"},
        json={"api_key": secret_value},
    )

    assert response.status_code == 200
    assert response.json() == {"saved": True, "secret_returned": False}
    assert secrets.nim_key == secret_value
    assert secret_value not in response.text
    events = client.get(
        "/v1/operator/audit",
        headers={"Authorization": "Bearer operator-token"},
    ).json()
    assert secret_value not in str(events)
    assert any(row["event_type"] == "OPERATOR_INTEGRATION_SECRET_UPDATED" for row in events)


def test_operator_can_rotate_a2a_keys_without_receiving_secret_values(tmp_path, monkeypatch):
    client, secrets = _client(tmp_path, monkeypatch)

    response = client.post(
        "/v1/operator/settings/red-blue/rotate",
        headers={"Authorization": "Bearer operator-token"},
        json={},
    )

    assert response.status_code == 200
    assert response.json() == {
        "rotated": True,
        "red_key_id": "red-test-01",
        "blue_key_id": "blue-test-01",
        "secrets_returned": False,
    }
    assert secrets.rotated is True


def test_public_operator_config_exposes_only_cognito_client_configuration(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)
    monkeypatch.setenv("SHADOW_HUNTER_AUTH_MODE", "cognito")
    monkeypatch.setenv(
        "SHADOW_HUNTER_COGNITO_HOSTED_UI_DOMAIN",
        "https://shadow-hunter.auth.us-east-1.amazoncognito.com",
    )
    monkeypatch.setenv("SHADOW_HUNTER_COGNITO_OPERATOR_CLIENT_ID", "public-client-id")

    response = client.get("/operator/config")

    assert response.status_code == 200
    assert response.json()["cognito"] == {
        "hosted_ui_domain": "https://shadow-hunter.auth.us-east-1.amazoncognito.com",
        "operator_client_id": "public-client-id",
        "login_available": True,
    }
    assert "secret" not in response.text.lower()


def test_operator_console_has_clickjacking_and_browser_security_headers(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)

    response = client.get("/operator")

    assert response.status_code == 200
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"


def test_agentcore_error_details_are_not_reflected_to_customers(tmp_path, monkeypatch):
    from shadow_hunter.agentcore import AgentCoreInvocationError

    class FailingHarness:
        def invoke(self, **kwargs):
            raise AgentCoreInvocationError("sensitive-provider-detail-do-not-return")

    monkeypatch.setenv("SHADOW_HUNTER_AUTH_MODE", "local")
    store = SQLiteStore(tmp_path / "agentcore-error.sqlite3")
    auth = TokenAuthenticator(
        customer_tokens={
            "customer-token": {
                "subject_id": "customer-1",
                "tenant_id": "tenant-1",
                "customer_id": "customer-1",
            }
        }
    )
    app = create_app(
        store=store,
        authenticator=auth,
        harness_client=FailingHarness(),
    )
    client = TestClient(app)

    response = client.post(
        "/v1/agent/chat",
        headers={"Authorization": "Bearer customer-token"},
        json={"prompt": "Check my order"},
    )

    assert response.status_code == 502
    assert response.json()["detail"]["message"] == "AgentCore invocation failed"
    assert response.json()["detail"]["trace_id"]
    assert "sensitive-provider-detail-do-not-return" not in response.text


def test_operator_can_recover_approved_token_after_browser_refresh(tmp_path, monkeypatch):
    from shadow_hunter.policy import Principal

    client, _ = _client(tmp_path, monkeypatch)
    gateway = client.app.state.gateway
    created = gateway.invoke(
        principal=Principal("customer-1", "tenant-1", "customer-1", True),
        tool_name="create_refund_request",
        arguments={
            "order_id": "order-api-recovery",
            "amount_minor": 500,
            "currency": "USD",
            "reason": "Damaged",
            "idempotency_key": "api-recovery-01",
        },
    ) if client.app.state.store.get_order("order-api-recovery") else None
    if created is None:
        client.app.state.store.add_order(
            order_id="order-api-recovery",
            tenant_id="tenant-1",
            customer_id="customer-1",
            currency="USD",
            refundable_minor=1000,
        )
        created = gateway.invoke(
            principal=Principal("customer-1", "tenant-1", "customer-1", True),
            tool_name="create_refund_request",
            arguments={
                "order_id": "order-api-recovery",
                "amount_minor": 500,
                "currency": "USD",
                "reason": "Damaged",
                "idempotency_key": "api-recovery-02",
            },
        )
    approval_id = created["approval"]["approval_id"]
    headers = {"Authorization": "Bearer operator-token"}
    approved = client.post(
        f"/v1/operator/approvals/{approval_id}/approve", headers=headers, json={}
    )
    assert approved.status_code == 200
    recovered = client.post(
        f"/v1/operator/approvals/{approval_id}/recover-token", headers=headers, json={}
    )
    assert recovered.status_code == 200
    assert recovered.json()["token_delivery"] == "shown_once"
    assert recovered.json()["approval_token"] != approved.json()["approval_token"]


def test_hosted_evaluation_kill_switch_blocks_operator_runs(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)
    monkeypatch.setenv("SHADOW_HUNTER_EVAL_ENABLED", "false")

    response = client.post(
        "/v1/operator/agent-evaluations/run",
        headers={"Authorization": "Bearer operator-token"},
        json={"rounds": 1},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "Hosted agent evaluations are disabled"



def test_customer_tool_http_response_does_not_disclose_order_existence(tmp_path, monkeypatch):
    monkeypatch.setenv("SHADOW_HUNTER_AUTH_MODE", "local")
    store = SQLiteStore(tmp_path / "order-enumeration-api.sqlite3")
    store.add_order(
        order_id="foreign-order",
        tenant_id="tenant-1",
        customer_id="another-customer",
        currency="USD",
        refundable_minor=1200,
    )
    auth = TokenAuthenticator(
        customer_tokens={
            "customer-token": {
                "subject_id": "customer-1",
                "tenant_id": "tenant-1",
                "customer_id": "customer-1",
            }
        },
        operator_tokens={"operator-token": {"subject_id": "operator-1"}},
    )
    app = create_app(
        store=store,
        authenticator=auth,
        integration_secrets=FakeIntegrationSecrets(),
    )
    client = TestClient(app)
    headers = {"Authorization": "Bearer customer-token"}

    missing = client.post(
        "/v1/agent/tools/get_order",
        headers=headers,
        json={"arguments": {"order_id": "does-not-exist"}},
    )
    foreign = client.post(
        "/v1/agent/tools/get_order",
        headers=headers,
        json={"arguments": {"order_id": "foreign-order"}},
    )

    assert missing.status_code == foreign.status_code == 200
    assert missing.json()["decision"] == foreign.json()["decision"] == "DENY"
    assert missing.json()["reason_code"] == foreign.json()["reason_code"] == "RESOURCE_NOT_AVAILABLE"
    assert set(missing.json()) == set(foreign.json())
    audit = client.get(
        "/v1/operator/audit",
        headers={"Authorization": "Bearer operator-token"},
    ).json()
    policy_reasons = {
        row["reason_code"]
        for row in audit
        if row["event_type"] == "POLICY_DECISION"
    }
    assert "ORDER_CONTEXT_MISSING" in policy_reasons
    assert "RESOURCE_OWNER_MISMATCH" in policy_reasons
