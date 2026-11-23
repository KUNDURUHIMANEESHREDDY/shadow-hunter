"""Keyless AWS CLI browser sign-in and Cognito customer login contract tests."""
from __future__ import annotations

import importlib.util
import shutil
import subprocess
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shadow_hunter.auth import TokenAuthenticator
from shadow_hunter.store import SQLiteStore

ROOT = Path(__file__).resolve().parents[1]
HTML = ROOT / "src" / "shadow_hunter" / "web" / "customer.html"
CLI = ROOT / "scripts" / "connect_aws.py"


def _cli_module():
    spec = importlib.util.spec_from_file_location("keyless_auth_cli", CLI)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def _mock_cli(monkeypatch, cli, *, account="123456789012", version="2.42.1"):
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        if command[:2] == ["aws", "--version"]:
            return SimpleNamespace(returncode=0, stdout=f"aws-cli/{version}")
        if command[:3] == ["aws", "sts", "get-caller-identity"]:
            return SimpleNamespace(returncode=0, stdout=account)
        if command[:2] == ["aws", "login"]:
            return SimpleNamespace(returncode=0)
        if command[0] == cli.sys.executable:
            return SimpleNamespace(returncode=0)
        raise AssertionError("Unexpected executable or AWS action")

    monkeypatch.setattr(cli.shutil, "which", lambda command: "aws.exe")
    monkeypatch.setattr(cli.subprocess, "run", run)
    return calls


def test_browser_sign_in_does_not_require_or_forward_long_lived_aws_keys(monkeypatch, capsys):
    cli = _cli_module()
    calls = _mock_cli(monkeypatch, cli)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "do-not-forward")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "do-not-forward")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "do-not-forward")
    assert cli.main(["--profile", "shadow-hunter-staging"]) == 0
    assert any(command[:2] == ["aws", "login"] for command, _ in calls)
    assert any(command[:3] == ["aws", "sts", "get-caller-identity"] for command, _ in calls)
    for _, kwargs in calls:
        assert kwargs["shell"] is False
        assert not any(k in kwargs["env"] for k in (
            "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        ))
    out = capsys.readouterr().out
    assert "PASS: AWS session verified" in out
    assert "123456789012" not in out
    assert "do-not-forward" not in out


def test_check_mode_only_inspects_sts_and_never_opens_browser(monkeypatch):
    cli = _cli_module()
    calls = _mock_cli(monkeypatch, cli)
    assert cli.main(["--check", "--expected-account", "123456789012"]) == 0
    assert not any(command[:2] == ["aws", "login"] for command, _ in calls)


def test_wrong_account_fails_closed_without_disclosing_id(monkeypatch, capsys):
    cli = _cli_module()
    _mock_cli(monkeypatch, cli, account="999999999999")
    assert cli.main(["--check", "--expected-account", "123456789012"]) == 1
    assert "999999999999" not in capsys.readouterr().err


def test_outdated_aws_cli_does_not_start_login(monkeypatch, capsys):
    cli = _cli_module()
    calls = _mock_cli(monkeypatch, cli, version="2.30.0")
    assert cli.main([]) == 1
    assert not any(command[:2] == ["aws", "login"] for command, _ in calls)
    assert "2.32.0" in capsys.readouterr().err


def test_staging_probe_is_read_only_and_separate_from_mfa(monkeypatch):
    cli = _cli_module()
    calls = _mock_cli(monkeypatch, cli)
    assert cli.main([
        "--check", "--verify-staging", "--expected-account", "123456789012",
    ]) == 0
    smoke = [command for command, _ in calls if command[0] == cli.sys.executable]
    assert len(smoke) == 1
    assert smoke[0][-1].endswith("smoke_cognito_identity.py")
    assert "--mfa" not in smoke[0] and "--obo" not in smoke[0]


def test_cli_rejects_invalid_profile_and_wrong_staging_region(monkeypatch):
    cli = _cli_module()
    with pytest.raises(SystemExit):
        cli.main(["--profile", "bad; exit 0"])
    with pytest.raises(SystemExit):
        cli.main(["--verify-staging", "--region", "us-east-1"])


def _client(monkeypatch, tmp_path):
    from shadow_hunter import mcp_server

    monkeypatch.setattr(
        mcp_server, "build_mcp_runtime",
        lambda *_: (
            SimpleNamespace(session_manager=SimpleNamespace(run=lambda: nullcontext())),
            FastAPI(),
        ),
    )
    # The module creates a default app during import. Keep the default in
    # local mode; the test instance itself uses the explicit authenticator.
    import os
    configured_mode = os.environ.get("SHADOW_HUNTER_AUTH_MODE")
    monkeypatch.setenv("SHADOW_HUNTER_AUTH_MODE", "local")
    from shadow_hunter import api
    if configured_mode is None:
        monkeypatch.delenv("SHADOW_HUNTER_AUTH_MODE", raising=False)
    else:
        monkeypatch.setenv("SHADOW_HUNTER_AUTH_MODE", configured_mode)

    monkeypatch.setattr(
        api, "build_mcp_runtime",
        lambda *_: (
            SimpleNamespace(session_manager=SimpleNamespace(run=lambda: nullcontext())),
            FastAPI(),
        ),
    )
    app = api.create_app(
        store=SQLiteStore(tmp_path / "keyless-customer.sqlite3"),
        authenticator=TokenAuthenticator(
            customer_tokens={
                "customer-token": {
                    "subject_id": "test-subject", "tenant_id": "test-tenant",
                    "customer_id": "test-customer",
                },
            },
            operator_tokens={"operator-token": {"subject_id": "operator-subject"}},
        ),
    )
    return TestClient(app)


def test_customer_page_and_config_never_expose_credentials(monkeypatch, tmp_path):
    monkeypatch.setenv("SHADOW_HUNTER_AUTH_MODE", "cognito")
    monkeypatch.setenv(
        "SHADOW_HUNTER_COGNITO_HOSTED_UI_DOMAIN",
        "https://synthetic.auth.ap-southeast-2.amazoncognito.com",
    )
    monkeypatch.setenv("SHADOW_HUNTER_COGNITO_CUSTOMER_CLIENT_ID", "customerpublic123")
    monkeypatch.setenv("SHADOW_HUNTER_COGNITO_CUSTOMER_SCOPE", "shadow-hunter/customer")
    monkeypatch.setenv("SHADOW_HUNTER_COGNITO_TOOL_SCOPE", "shadow-hunter-api/refunds")
    with _client(monkeypatch, tmp_path) as client:
        response = client.get("/customer")
        assert response.status_code == 200
        assert "Sign in with Cognito" in response.text
        assert response.headers["cache-control"] == "no-store"
        config = client.get("/customer/config")
        assert config.status_code == 200
        assert config.headers["cache-control"] == "no-store"
        oauth = config.json()["cognito"]
        assert oauth["login_available"] is True
        assert oauth["customer_client_id"] == "customerpublic123"
        assert oauth["scopes"] == (
            "openid email shadow-hunter/customer shadow-hunter-api/refunds"
        )
        assert "secret" not in str(config.json()).lower()


@pytest.mark.parametrize("domain", [
    "http://insecure.example.com", "https://user:pass@example.com",
    "https://example.com/path", "https://example.com/?redirect=https://bad.example",
])
def test_customer_config_fails_closed_on_unsafe_oauth_domains(
    monkeypatch, tmp_path, domain,
):
    monkeypatch.setenv("SHADOW_HUNTER_AUTH_MODE", "cognito")
    monkeypatch.setenv("SHADOW_HUNTER_COGNITO_HOSTED_UI_DOMAIN", domain)
    monkeypatch.setenv("SHADOW_HUNTER_COGNITO_CUSTOMER_CLIENT_ID", "customer123")
    with _client(monkeypatch, tmp_path) as client:
        config = client.get("/customer/config").json()["cognito"]
        assert config["login_available"] is False
        assert config["hosted_ui_domain"] == ""
        assert config["customer_client_id"] == ""


def test_customer_session_rejects_anonymous_and_operator_tokens(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        assert client.get("/v1/customer/session").status_code == 401
        assert client.get(
            "/v1/customer/session",
            headers={"Authorization": "Bearer operator-token"},
        ).status_code == 401
        authorized = client.get(
            "/v1/customer/session",
            headers={"Authorization": "Bearer customer-token"},
        )
        assert authorized.status_code == 200
        assert authorized.json() == {"authenticated": True}
        assert authorized.headers["cache-control"] == "no-store"


def test_browser_page_keeps_access_token_in_memory_and_uses_pkce():
    html = HTML.read_text(encoding="utf-8")
    assert "crypto.subtle.digest(" in html
    assert 'code_challenge_method: "S256"' in html
    assert "shadow_hunter_customer_pkce_verifier" in html
    assert 'sessionStorage.setItem(STORAGE_VERIFIER, verifier)' in html
    assert 'sessionStorage.removeItem(STORAGE_VERIFIER)' in html
    assert "localStorage.setItem" not in html
    assert "sessionStorage.setItem(STORAGE_STATE, state)" in html
    assert "await verifySession(tokens.access_token)" in html
    assert "clearSession();" in html
    assert "accessToken = \"\";" in html


def test_customer_browser_script_parses_without_syntax_errors(tmp_path):
    if not shutil.which("node"):
        pytest.skip("Node.js unavailable")
    html = HTML.read_text(encoding="utf-8")
    script = html.split("<script>", 1)[1].split("</script>", 1)[0]
    file = tmp_path / "customer.js"
    file.write_text(script, encoding="utf-8")
    result = subprocess.run(
        ["node", "--check", str(file)],
        check=False, capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr[:1000]
