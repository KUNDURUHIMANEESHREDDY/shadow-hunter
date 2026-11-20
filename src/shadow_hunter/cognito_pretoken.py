"""Cognito pre-token-generation trigger for Shadow Hunter.

Add tenant and customer identity from trusted user-pool custom attributes to
human access tokens and token-exchange access tokens. M2M client-credentials
tokens represent the agent actor, not a customer, and are returned unchanged.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any


_SUPPORTED_VERSIONS = {"2", "3"}
_M2M_TRIGGER = "TokenGeneration_ClientCredentials"


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Return a Cognito V2/V3 event with trusted access-token identity claims.

    Required user-pool attributes:
      - custom:tenant_id
      - custom:customer_id

    The trigger deliberately does not modify scopes. Cognito token exchange
    must remain down-scoped to the subject token's granted scopes.
    """
    if not isinstance(event, dict):
        raise ValueError("Cognito trigger event must be an object")

    version = event.get("version")
    if str(version) not in _SUPPORTED_VERSIONS:
        raise ValueError("Shadow Hunter requires Cognito pre-token trigger V2_0 or V3_0")

    if event.get("triggerSource") == _M2M_TRIGGER:
        # Actor tokens identify the service/agent, not an end customer.
        return event

    request = event.get("request")
    attributes = request.get("userAttributes") if isinstance(request, Mapping) else None
    if not isinstance(attributes, Mapping):
        raise ValueError("Cognito user attributes are required")

    tenant_id = _trusted_attribute(attributes, "custom:tenant_id")
    customer_id = _trusted_attribute(attributes, "custom:customer_id")
    if not tenant_id or not customer_id:
        # Fail token issuance rather than minting a token with incomplete
        # authorization context.
        raise ValueError("User must have trusted tenant and customer attributes")

    response = event.get("response")
    if not isinstance(response, dict):
        response = {}

    details = response.get("claimsAndScopeOverrideDetails")
    if not isinstance(details, dict):
        details = {}

    access = details.get("accessTokenGeneration")
    if not isinstance(access, dict):
        access = {}

    claims = access.get("claimsToAddOrOverride")
    if not isinstance(claims, dict):
        claims = {}

    claims["tenant_id"] = tenant_id
    claims["customer_id"] = customer_id
    access["claimsToAddOrOverride"] = claims
    details["accessTokenGeneration"] = access
    response["claimsAndScopeOverrideDetails"] = details
    event["response"] = response
    return event


def _trusted_attribute(attributes: Mapping[str, Any], name: str) -> str | None:
    value = attributes.get(name)
    if not isinstance(value, str) or not value or value.strip() != value:
        return None
    return value
