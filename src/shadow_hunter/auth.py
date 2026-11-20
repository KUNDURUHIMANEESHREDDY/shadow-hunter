"""Environment-backed bearer-token authentication for local development.

Production deployments should use Cognito/JWT validation at API Gateway and
map verified authorizer claims into the same Principal contract. Never accept
customer or tenant identifiers from an agent request body.
"""
from __future__ import annotations

import hmac
import json
import os
from collections.abc import Mapping
from typing import Any

from .policy import Principal


class AuthenticationConfigurationError(RuntimeError):
    pass


class TokenAuthenticator:
    def __init__(
        self,
        customer_tokens: Mapping[str, Mapping[str, Any]] | None = None,
        operator_tokens: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> None:
        self.customer_tokens = dict(customer_tokens or {})
        self.operator_tokens = dict(operator_tokens or {})
        for token, claims in self.customer_tokens.items():
            if not token or not isinstance(claims, Mapping):
                raise AuthenticationConfigurationError("Invalid customer token mapping")
        for token, claims in self.operator_tokens.items():
            if not token or not isinstance(claims, Mapping):
                raise AuthenticationConfigurationError("Invalid operator token mapping")

    @classmethod
    def from_environment(cls) -> "TokenAuthenticator":
        return cls(
            customer_tokens=_load_mapping("SHADOW_HUNTER_CUSTOMER_TOKENS"),
            operator_tokens=_load_mapping("SHADOW_HUNTER_OPERATOR_TOKENS"),
        )

    def authenticate_customer(self, token: str | None) -> Principal | None:
        claims = self._lookup(self.customer_tokens, token)
        if claims is None:
            return None
        values = (
            claims.get("subject_id"),
            claims.get("tenant_id"),
            claims.get("customer_id"),
        )
        if not all(
            isinstance(value, str) and value and value.strip() == value
            for value in values
        ):
            return None
        return Principal(
            subject_id=values[0],
            tenant_id=values[1],
            customer_id=values[2],
            authenticated=True,
        )

    def authenticate_operator(self, token: str | None) -> str | None:
        claims = self._lookup(self.operator_tokens, token)
        if claims is None:
            return None
        subject_id = claims.get("subject_id")
        if (
            not isinstance(subject_id, str)
            or not subject_id
            or subject_id.strip() != subject_id
        ):
            return None
        return subject_id

    @staticmethod
    def _lookup(
        mapping: Mapping[str, Mapping[str, Any]], supplied: str | None
    ) -> Mapping[str, Any] | None:
        if not isinstance(supplied, str) or not supplied:
            return None
        for expected, claims in mapping.items():
            if hmac.compare_digest(expected, supplied):
                return claims
        return None


def _load_mapping(environment_name: str) -> dict[str, Any]:
    raw = os.environ.get(environment_name, "")
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AuthenticationConfigurationError(
            f"{environment_name} must contain a JSON object"
        ) from exc
    if not isinstance(value, dict):
        raise AuthenticationConfigurationError(
            f"{environment_name} must contain a JSON object"
        )
    return value
