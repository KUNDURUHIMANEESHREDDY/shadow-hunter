from __future__ import annotations

import copy

import pytest

from shadow_hunter.cognito_pretoken import handler


def cognito_event(
    *,
    trigger_source: str = "TokenGeneration_Authentication",
    version: str = "2",
    attributes: dict | None = None,
) -> dict:
    return {
        "version": version,
        "triggerSource": trigger_source,
        "request": {
            "userAttributes": attributes
            if attributes is not None
            else {
                "sub": "user-subject",
                "custom:tenant_id": "tenant-001",
                "custom:customer_id": "customer-001",
            },
            "scopes": [
                "openid",
                "shadow-hunter/customer",
                "shadow-hunter-api/refunds",
            ],
        },
        "response": {"claimsAndScopeOverrideDetails": []},
    }


def test_user_authentication_adds_only_trusted_identity_claims():
    event = cognito_event()

    result = handler(event, None)

    access_claims = result["response"]["claimsAndScopeOverrideDetails"][
        "accessTokenGeneration"
    ]["claimsToAddOrOverride"]
    assert access_claims == {
        "tenant_id": "tenant-001",
        "customer_id": "customer-001",
    }
    assert result["request"]["scopes"] == event["request"]["scopes"]


def test_token_exchange_adds_the_resolved_users_identity_claims():
    event = cognito_event(trigger_source="TokenGeneration_TokenExchange")

    result = handler(event, None)

    access_claims = result["response"]["claimsAndScopeOverrideDetails"][
        "accessTokenGeneration"
    ]["claimsToAddOrOverride"]
    assert access_claims["tenant_id"] == "tenant-001"
    assert access_claims["customer_id"] == "customer-001"


def test_m2m_actor_token_is_returned_unchanged():
    event = cognito_event(
        trigger_source="TokenGeneration_ClientCredentials",
        version="3",
        attributes={},
    )
    original = copy.deepcopy(event)

    assert handler(event, None) == original


def test_existing_access_token_claim_overrides_are_preserved():
    event = cognito_event()
    event["response"]["claimsAndScopeOverrideDetails"] = {
        "accessTokenGeneration": {
            "claimsToAddOrOverride": {"existing_claim": "preserved"},
            "scopesToSuppress": ["unwanted-scope"],
        }
    }

    result = handler(event, None)
    access = result["response"]["claimsAndScopeOverrideDetails"][
        "accessTokenGeneration"
    ]
    assert access["claimsToAddOrOverride"] == {
        "existing_claim": "preserved",
        "tenant_id": "tenant-001",
        "customer_id": "customer-001",
    }
    assert access["scopesToSuppress"] == ["unwanted-scope"]


@pytest.mark.parametrize(
    "attributes",
    [
        {},
        {"custom:tenant_id": "tenant-001"},
        {"custom:customer_id": "customer-001"},
        {"custom:tenant_id": " ", "custom:customer_id": "customer-001"},
    ],
)
def test_missing_or_invalid_identity_attributes_fail_token_issuance(attributes):
    with pytest.raises(ValueError):
        handler(cognito_event(attributes=attributes), None)


def test_v1_trigger_version_is_rejected():
    with pytest.raises(ValueError):
        handler(cognito_event(version="1"), None)
