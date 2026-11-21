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
