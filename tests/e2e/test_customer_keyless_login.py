"""Real Chromium PKCE browser sign-in tests with simulated OAuth responses.

No Cognito user, token, secret, AWS account or external OAuth endpoint is used.
The customer page and the real local FastAPI session verifier are exercised.
"""
from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest

pytest.importorskip("playwright.sync_api")
from playwright.sync_api import expect

from .conftest import CUSTOMER_TOKEN, OPERATOR_TOKEN

DOMAIN = "https://synthetic-login.example.test"


def _configure(page, base_url, *, callback_state_override=None, token=CUSTOMER_TOKEN):
    events = {"authorized": [], "exchanged": []}
    page.route(
        "**/customer/config",
        lambda route: route.fulfill(json={
            "auth_mode": "cognito",
            "cognito": {
                "login_available": True,
                "hosted_ui_domain": DOMAIN,
                "customer_client_id": "syntheticpublicclient",
                "scopes": "openid email shadow-hunter/customer shadow-hunter-api/refunds",
            },
        }),
    )

    def authorize(route):
        params = parse_qs(urlsplit(route.request.url).query)
        events["authorized"].append(params)
        assert params["response_type"] == ["code"]
        assert params["code_challenge_method"] == ["S256"]
        assert params["scope"] == [
            "openid email shadow-hunter/customer shadow-hunter-api/refunds"
        ]
        assert "code_verifier" not in params
        state = callback_state_override or params["state"][0]
        route.fulfill(
            status=302,
            headers={"Location": base_url + "/customer?" + urlencode({
                "code": "synthetic-auth-code", "state": state,
            })},
        )

    def exchange(route):
        params = parse_qs(route.request.post_data or "")
        events["exchanged"].append(params)
        assert params["grant_type"] == ["authorization_code"]
        assert params["code"] == ["synthetic-auth-code"]
        assert params["client_id"] == ["syntheticpublicclient"]
        assert params["redirect_uri"] == [base_url + "/customer"]
        verifier = params["code_verifier"][0]
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        assert challenge == events["authorized"][0]["code_challenge"][0]
        route.fulfill(
            json={"access_token": token, "token_type": "Bearer", "expires_in": 900},
            headers={"Access-Control-Allow-Origin": "*"},
        )

    page.route(DOMAIN + "/oauth2/authorize?*", authorize)
    page.route(DOMAIN + "/oauth2/token", exchange)
    return events


def test_customer_authorization_code_pkce_and_verified_session(page, local_server):
    events = _configure(page, local_server)
    page.goto(local_server + "/customer", wait_until="domcontentloaded")
    expect(page.locator("#sign-in")).to_be_enabled()
    expect(page.locator("#chat")).to_be_hidden()
    page.locator("#sign-in").click()
    expect(page.locator("#chat")).to_be_visible()
    expect(page.locator("#status")).to_contain_text("Signed in")
    assert len(events["authorized"]) == len(events["exchanged"]) == 1
    assert page.evaluate("sessionStorage.length") == 0
    assert page.evaluate("localStorage.length") == 0
    assert "?code=" not in page.url

    page.locator("#prompt").fill("Read a synthetic order")
    page.locator("#send").click()
    expect(page.locator("#answer")).to_contain_text(
        "managed AgentCore Harness is not configured"
    )
    # Tokens deliberately do not survive reload.
    page.reload()
    expect(page.locator("#chat")).to_be_hidden()
    expect(page.locator("#sign-in")).to_be_enabled()


def test_wrong_oauth_state_is_rejected_before_token_exchange(page, local_server):
    events = _configure(
        page, local_server, callback_state_override="untrusted-callback-state",
    )
    page.goto(local_server + "/customer", wait_until="domcontentloaded")
    page.locator("#sign-in").click()
    expect(page.locator("#status")).to_contain_text("state could not be verified")
    expect(page.locator("#chat")).to_be_hidden()
    assert len(events["authorized"]) == 1
    assert not events["exchanged"]
    assert page.evaluate("sessionStorage.length") == 0


def test_operator_token_cannot_open_customer_session(page, local_server):
    events = _configure(page, local_server, token=OPERATOR_TOKEN)
    page.goto(local_server + "/customer", wait_until="domcontentloaded")
    page.locator("#sign-in").click()
    expect(page.locator("#status")).to_contain_text("failed Shadow Hunter verification")
    expect(page.locator("#chat")).to_be_hidden()
    assert len(events["exchanged"]) == 1
