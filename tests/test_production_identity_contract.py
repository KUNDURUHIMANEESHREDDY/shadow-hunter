from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from shadow_hunter.auth import CognitoJWTAuthenticator
from shadow_hunter.cognito_pretoken import handler as cognito_pretoken_handler


ISSUER = "https://cognito-idp.local.invalid/us-east-1_shadowhunter"
CUSTOMER_CLIENT_ID = "synthetic-customer-client"
OPERATOR_CLIENT_ID = "synthetic-operator-client"
ACTOR_SUBJECT = "synthetic-refund-agent"
CUSTOMER_SCOPE = "shadow-hunter/customer"
TOOL_SCOPE = "shadow-hunter-api/refunds"
TOOL_AUDIENCE = "shadow-hunter-api"


class StaticJwkClient:
    def __init__(self, public_key):
        self.public_key = public_key

    def get_signing_key_from_jwt(self, token):
        return SimpleNamespace(key=self.public_key)


@pytest.fixture
def identity_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


@pytest.fixture
def production_auth(identity_keys):
    _, public_key = identity_keys
    return CognitoJWTAuthenticator(
        issuer=ISSUER,
        customer_client_id=CUSTOMER_CLIENT_ID,
        customer_scope=CUSTOMER_SCOPE,
        tool_audience=TOOL_AUDIENCE,
        tool_scope=TOOL_SCOPE,
        actor_subject=ACTOR_SUBJECT,
        operator_client_id=OPERATOR_CLIENT_ID,
        jwks_client=StaticJwkClient(public_key),
    )


def _cognito_event(trigger_source: str) -> dict:
    return {
        "version": "3",
        "triggerSource": trigger_source,
        "request": {
            "userAttributes": {
                "sub": "synthetic-customer-sub",
                "custom:tenant_id": "tenant-prod-contract",
                "custom:customer_id": "customer-prod-contract",
            }
        },
        "response": {},
    }


def _issue_access_token(private_key, claims: dict) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "iss": ISSUER,
        "sub": "synthetic-customer-sub",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "token_use": "access",
        "client_id": CUSTOMER_CLIENT_ID,
        "tenant_id": "tenant-prod-contract",
        "customer_id": "customer-prod-contract",
        **claims,
    }
    return jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": "synthetic-local-key"},
    )


def test_customer_pretoken_claims_are_accepted_by_production_authenticator(
    identity_keys, production_auth
):
    private_key, _ = identity_keys
    event = cognito_pretoken_handler(
        _cognito_event("TokenGeneration_Authentication"),
        None,
    )
    overrides = event["response"]["claimsAndScopeOverrideDetails"][
        "accessTokenGeneration"
    ]["claimsToAddOrOverride"]

    token = _issue_access_token(
        private_key,
        {
            **overrides,
            "client_id": CUSTOMER_CLIENT_ID,
            "scope": f"openid {CUSTOMER_SCOPE} {TOOL_SCOPE}",
        },
    )

    principal = production_auth.authenticate_customer(token)

    assert principal is not None
    assert principal.subject_id == "synthetic-customer-sub"
    assert principal.tenant_id == "tenant-prod-contract"
    assert principal.customer_id == "customer-prod-contract"


def test_delegated_token_requires_exact_resource_and_actor(
    identity_keys, production_auth
):
    private_key, _ = identity_keys
    event = cognito_pretoken_handler(
        _cognito_event("TokenGeneration_TokenExchange"),
        None,
    )
    overrides = event["response"]["claimsAndScopeOverrideDetails"][
        "accessTokenGeneration"
    ]["claimsToAddOrOverride"]
    token = _issue_access_token(
        private_key,
        {
            **overrides,
            "scope": TOOL_SCOPE,
            "aud": TOOL_AUDIENCE,
            "act": {"sub": ACTOR_SUBJECT},
        },
    )

    principal = production_auth.authenticate_gateway_tool(token)

    assert principal is not None
    assert principal.subject_id == "synthetic-customer-sub"
    assert principal.tenant_id == "tenant-prod-contract"
    assert principal.customer_id == "customer-prod-contract"


def test_operator_token_requires_separate_client_and_operator_group(
    identity_keys, production_auth
):
    private_key, _ = identity_keys
    token = _issue_access_token(
        private_key,
        {
            "client_id": OPERATOR_CLIENT_ID,
            "cognito:groups": ["shadow_hunter_operators"],
        },
    )

    assert production_auth.authenticate_operator(token) == "synthetic-customer-sub"

    wrong_client = _issue_access_token(
        private_key,
        {
            "client_id": CUSTOMER_CLIENT_ID,
            "cognito:groups": ["shadow_hunter_operators"],
        },
    )
    wrong_group = _issue_access_token(
        private_key,
        {
            "client_id": OPERATOR_CLIENT_ID,
            "cognito:groups": ["customers"],
        },
    )

    assert production_auth.authenticate_operator(wrong_client) is None
    assert production_auth.authenticate_operator(wrong_group) is None


def test_missing_trusted_tenant_claim_blocks_token_issuance():
    event = _cognito_event("TokenGeneration_Authentication")
    event["request"]["userAttributes"].pop("custom:tenant_id")

    with pytest.raises(ValueError, match="trusted tenant and customer"):
        cognito_pretoken_handler(event, None)


def test_wrong_actor_and_wrong_resource_are_denied(identity_keys, production_auth):
    private_key, _ = identity_keys
    base = {
        "scope": TOOL_SCOPE,
        "aud": TOOL_AUDIENCE,
        "act": {"sub": "attacker-agent"},
    }
    wrong_actor = _issue_access_token(private_key, base)
    wrong_audience = _issue_access_token(
        private_key,
        {
            "scope": TOOL_SCOPE,
            "aud": "another-resource",
            "act": {"sub": ACTOR_SUBJECT},
        },
    )

    assert production_auth.authenticate_gateway_tool(wrong_actor) is None
    assert production_auth.authenticate_gateway_tool(wrong_audience) is None


def test_operator_group_trigger_and_operator_jwt_form_one_contract(
    identity_keys, production_auth
):
    private_key, _ = identity_keys
    event = {
        "version": "3",
        "triggerSource": "TokenGeneration_Authentication",
        "request": {
            "userAttributes": {"sub": "synthetic-operator-sub"},
            "groupConfiguration": {
                "groupsToOverride": ["shadow_hunter_operators"]
            },
        },
        "response": {},
    }

    processed = cognito_pretoken_handler(event, None)
    assert processed["response"] == {}

    token = _issue_access_token(
        private_key,
        {
            "sub": "synthetic-operator-sub",
            "client_id": OPERATOR_CLIENT_ID,
            "cognito:groups": ["shadow_hunter_operators"],
        },
    )

    assert production_auth.authenticate_operator(token) == "synthetic-operator-sub"
