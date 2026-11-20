from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from shadow_hunter.auth import (
    AuthenticationConfigurationError,
    CognitoJWTAuthenticator,
    TokenAuthenticator,
    build_authenticator_from_environment,
)


class StaticJWKClient:
    def __init__(self, public_key):
        self.public_key = public_key

    def get_signing_key_from_jwt(self, token):
        return SimpleNamespace(key=self.public_key)


@pytest.fixture
def signing_material():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def issue_token(private_key, claims):
    return jwt.encode(
        claims,
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )


def cognito_auth(public_key):
    return CognitoJWTAuthenticator(
        issuer="https://cognito-idp.us-east-1.amazonaws.com/us-east-1_test",
        customer_client_id="customer-client",
        customer_scope="shadow-hunter/customer",
        tool_audience="shadow-hunter-api",
        tool_scope="shadow-hunter-api/refunds",
        actor_subject="refund-agent-client",
        operator_group="shadow_hunter_operators",
        jwks_client=StaticJWKClient(public_key),
    )


def base_claims():
    now = datetime.now(timezone.utc)
    return {
        "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_test",
        "sub": "customer-subject-123",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=10)).timestamp()),
        "token_use": "access",
        "client_id": "customer-client",
        "scope": "openid shadow-hunter/customer shadow-hunter-api/refunds",
        "tenant_id": "tenant-1",
        "customer_id": "customer-1",
    }


def test_customer_jwt_maps_only_verified_identity_claims(signing_material):
    private_key, public_key = signing_material
    auth = cognito_auth(public_key)
    token = issue_token(private_key, base_claims())

    principal = auth.authenticate_customer(token)

    assert principal is not None
    assert principal.subject_id == "customer-subject-123"
    assert principal.tenant_id == "tenant-1"
    assert principal.customer_id == "customer-1"


def test_customer_jwt_rejects_wrong_client_or_missing_scope(signing_material):
    private_key, public_key = signing_material
    auth = cognito_auth(public_key)
    claims = base_claims()
    claims["client_id"] = "another-client"
    assert auth.authenticate_customer(issue_token(private_key, claims)) is None

    claims = base_claims()
    claims["scope"] = "openid"
    assert auth.authenticate_customer(issue_token(private_key, claims)) is None


def test_customer_jwt_rejects_missing_tenant_or_customer_claims(signing_material):
    private_key, public_key = signing_material
    auth = cognito_auth(public_key)
    claims = base_claims()
    claims.pop("tenant_id")
    assert auth.authenticate_customer(issue_token(private_key, claims)) is None


def test_gateway_tool_requires_audience_scope_and_delegated_actor(signing_material):
    private_key, public_key = signing_material
    auth = cognito_auth(public_key)
    claims = base_claims()
    claims["aud"] = "shadow-hunter-api"
    claims["act"] = {"sub": "refund-agent-client"}
    token = issue_token(private_key, claims)

    principal = auth.authenticate_gateway_tool(token)

    assert principal is not None
    assert principal.subject_id == "customer-subject-123"

    claims["act"] = {"sub": "unexpected-agent"}
    assert auth.authenticate_gateway_tool(issue_token(private_key, claims)) is None


def test_gateway_tool_rejects_wrong_audience_or_missing_scope(signing_material):
    private_key, public_key = signing_material
    auth = cognito_auth(public_key)
    claims = base_claims()
    claims["aud"] = "another-api"
    claims["act"] = {"sub": "refund-agent-client"}
    assert auth.authenticate_gateway_tool(issue_token(private_key, claims)) is None

    claims["aud"] = "shadow-hunter-api"
    claims["scope"] = "openid"
    assert auth.authenticate_gateway_tool(issue_token(private_key, claims)) is None


def test_operator_requires_configured_cognito_group(signing_material):
    private_key, public_key = signing_material
    auth = cognito_auth(public_key)
    claims = base_claims()
    claims["cognito:groups"] = ["shadow_hunter_operators"]
    token = issue_token(private_key, claims)
    assert auth.authenticate_operator(token) == "customer-subject-123"

    claims["cognito:groups"] = ["customers"]
    assert auth.authenticate_operator(issue_token(private_key, claims)) is None


def test_local_auth_still_supports_separate_operator_tokens():
    auth = TokenAuthenticator(
        customer_tokens={
            "customer-token": {
                "subject_id": "subject-1",
                "tenant_id": "tenant-1",
                "customer_id": "customer-1",
            }
        },
        operator_tokens={"operator-token": {"subject_id": "support-1"}},
    )
    assert auth.authenticate_customer("customer-token") is not None
    assert auth.authenticate_gateway_tool("customer-token") is not None
    assert auth.authenticate_operator("customer-token") is None
    assert auth.authenticate_operator("operator-token") == "support-1"


def test_auth_mode_selection_fails_closed(monkeypatch):
    monkeypatch.setenv("SHADOW_HUNTER_AUTH_MODE", "unknown")
    with pytest.raises(AuthenticationConfigurationError):
        build_authenticator_from_environment()
