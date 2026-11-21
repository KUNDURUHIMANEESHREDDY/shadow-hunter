from __future__ import annotations

import copy

import pytest

from shadow_hunter.cognito_pretoken import handler


def cognito_event(
    *,
    trigger_source: str = "TokenGeneration_Authentication",
    version: str = "3",
    attributes: dict | None = None,
) -> dict:
    return {
        "version": version,
        "triggerSource": trigger_source,
        "request": {
            "groupConfiguration": {"groupsToOverride": []},
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


def test_non_v3_trigger_versions_are_rejected():
    with pytest.raises(ValueError):
        handler(cognito_event(version="1"), None)


def test_operator_group_can_mint_operator_token_without_customer_attributes():
    event = cognito_event(attributes={"sub": "operator-subject"})
    event["request"]["groupConfiguration"]["groupsToOverride"] = [
        "shadow_hunter_operators"
    ]
    original_response = copy.deepcopy(event["response"])

    result = handler(event, None)

    assert result["response"] == original_response


def test_missing_customer_attributes_without_operator_group_fail_closed():
    event = cognito_event(attributes={"sub": "ordinary-user"})
    event["request"]["groupConfiguration"]["groupsToOverride"] = ["customers"]

    with pytest.raises(ValueError, match="trusted tenant and customer"):
        handler(event, None)


def test_operator_group_never_receives_customer_claim_overrides():
    event = cognito_event()
    event["request"]["groupConfiguration"]["groupsToOverride"] = [
        "shadow_hunter_operators"
    ]
    original_response = copy.deepcopy(event["response"])

    result = handler(event, None)

    assert result["response"] == original_response

def test_v2_trigger_version_is_rejected_for_production_identity():
    with pytest.raises(ValueError, match="V3_0"):
        handler(cognito_event(version="2"), None)
