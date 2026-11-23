"""Operator console regression checks: no stale data or cached sensitive API."""
from __future__ import annotations

import re
import shutil
import subprocess
from contextlib import nullcontext
from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shadow_hunter.auth import TokenAuthenticator
from shadow_hunter.store import SQLiteStore


HTML = Path(__file__).resolve().parents[1] / "src/shadow_hunter/web/operator.html"


class IdParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids: list[str] = []

    def handle_starttag(self, tag, attrs):
        self.ids.extend(value for key, value in attrs if key == "id")


def _client(tmp_path, monkeypatch):
    import shadow_hunter.api as api

    class SessionManager:
        def run(self):
            return nullcontext()

    monkeypatch.setattr(
        api,
        "build_mcp_runtime",
        lambda *_: (SimpleNamespace(session_manager=SessionManager()), FastAPI()),
    )
    app = api.create_app(
        store=SQLiteStore(tmp_path / "cache-security.sqlite3"),
        authenticator=TokenAuthenticator(
            operator_tokens={"operator-test": {"subject_id": "operator-test"}},
            customer_tokens={
                "customer-test": {
                    "subject_id": "subject-test",
                    "tenant_id": "tenant-test",
                    "customer_id": "customer-test",
                }
            },
        ),
    )
    return TestClient(app)


@pytest.mark.parametrize("path,method", [
    ("/operator", "GET"),
    ("/operator/config", "GET"),
    ("/v1/operator/overview", "GET"),
    ("/v1/operator/audit", "GET"),
    ("/v1/agent/chat", "POST"),
    ("/v1/agent/tools/get_order", "POST"),
])
def test_sensitive_routes_explicitly_disable_http_caching(tmp_path, monkeypatch, path, method):
    client = _client(tmp_path, monkeypatch)
    response = client.request(method, path)
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_authenticated_audit_is_not_cacheable_either(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    response = client.get(
        "/v1/operator/audit",
        headers={"Authorization": "Bearer operator-test"},
    )
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"


def test_console_has_single_unique_dom_target_per_control():
    parser = IdParser()
    parser.feed(HTML.read_text(encoding="utf-8"))
    assert len(parser.ids) == len(set(parser.ids))
    for field in (
        "security-pulse", "security-metrics", "audit-search", "audit-decision",
        "last-refreshed", "refresh-console", "trace-panel", "lyzr-form",
        "band-form", "lyzr-advice", "band-status", "lyzr-status",
    ):
        assert field in parser.ids


def test_console_clears_every_sensitive_view_and_invalidates_pending_reads():
    html = HTML.read_text(encoding="utf-8")
    start = html.index("function clearSensitiveView()")
    clear = html[start:html.index("const randomBase64Url", start)]
    for target in (
        'loadGeneration += 1',
        'approvalTokens.clear()',
        'lastAuditRows = []',
        '"metrics"',
        '"security-metrics"',
        '"agent-eval-metrics"',
        '"approvals"',
        '"audit"',
        '"agent-eval-results"',
        '"trace-panel"',
        '"trace-events"',
        '"lyzr-advice"',
    ):
        assert target in clear
    assert 'if (generation !== loadGeneration || !operatorToken) return;' in html
    assert 'if (response.status === 401)' in html
    assert 'const requestToken = operatorToken;' in html
    assert 'if (operatorToken === requestToken)' in html
    assert 'setMessage("Operator session expired or invalid. Sign in again.", true)' in html
    assert 'clearSensitiveView();' in html
    assert '"Disconnect"' in html


def test_external_advice_is_text_only_and_never_given_tool_authority():
    html = HTML.read_text(encoding="utf-8")
    assert "const SYNTHETIC_ADVICE_CASES = Object.freeze" in html
    assert 'JSON.stringify({scenario})' in html
    assert '$("lyzr-advice").textContent' in html
    assert 'JSON.stringify({trace_id: traceId})' in html
    assert 'window.confirm("Send this trace' in html
    assert 'window.confirm("Execute this approved refund?' in html
    assert 'localStorage.setItem(' not in html


def test_inline_console_script_parses_with_node_when_available(tmp_path):
    if not shutil.which("node"):
        pytest.skip("Node.js unavailable; static dashboard checks still apply")
    html = HTML.read_text(encoding="utf-8")
    script = html.split("<script>", 1)[1].split("</script>", 1)[0]
    script_file = tmp_path / "operator-ui.js"
    script_file.write_text(script, encoding="utf-8")
    result = subprocess.run(
        ["node", "--check", str(script_file)],
        capture_output=True, text=True, check=False, timeout=15,
    )
    assert result.returncode == 0, result.stderr[:2000]
