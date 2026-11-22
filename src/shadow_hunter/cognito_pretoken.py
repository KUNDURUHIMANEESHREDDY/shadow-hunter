"""Cognito pre-token-generation trigger for Shadow Hunter.

Add tenant and customer identity from trusted user-pool custom attributes to
customer access tokens and token-exchange access tokens. Operators are
authorized by the Cognito operator group and do not need a customer identity.
M2M client-credentials events identify the agent actor and pass through.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

_SUPPORTED_VERSIONS = {"3"}
_M2M_TRIGGER = "TokenGeneration_ClientCredentials"
_OPERATOR_GROUP = "shadow_hunter_operators"


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Return a Cognito V3 event with trusted access-token identity claims.

    Customer and delegated-user events require custom:tenant_id and
    custom:customer_id. Operator-group users can receive an operator token
    without being assigned a synthetic customer identity. M2M actor tokens
    are passed through unchanged.
    """
    if not isinstance(event, dict):
        raise ValueError("Cognito trigger event must be an object")

    version = event.get("version")
    if str(version) not in _SUPPORTED_VERSIONS:
        raise ValueError("Shadow Hunter production requires Cognito pre-token trigger V3_0")

    if event.get("triggerSource") == _M2M_TRIGGER:
        # Actor tokens identify the service/agent, not an end customer.
        return event

    request = event.get("request")
    attributes = request.get("userAttributes") if isinstance(request, Mapping) else None
    if not isinstance(attributes, Mapping):
        raise ValueError("Cognito user attributes are required")

    group_configuration = (
        request.get("groupConfiguration")
        if isinstance(request, Mapping)
        else None
    )
    groups = (
        group_configuration.get("groupsToOverride")
        if isinstance(group_configuration, Mapping)
        else None
    )
    is_operator = isinstance(groups, list) and _OPERATOR_GROUP in groups
    if is_operator:
        # Keep operator identity separate from customer identity even if
        # customer attributes happen to exist on the same User Pool account.
        return event

    tenant_id = _trusted_attribute(attributes, "custom:tenant_id")
    customer_id = _trusted_attribute(attributes, "custom:customer_id")
    if not tenant_id or not customer_id:
        # Customer and delegated-user tokens fail closed without both
        # trusted tenant/customer attributes.
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
