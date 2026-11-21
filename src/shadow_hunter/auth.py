"""Local and Cognito JWT authentication for Shadow Hunter.

Local opaque-token mappings are for demos only. Production Cognito mode
verifies RS256 signatures from the user-pool JWKS and validates distinct
customer and Gateway on-behalf-of access-token profiles before creating a
trusted Principal. Never accept identity fields from model arguments.
"""
from __future__ import annotations

import hmac
import json
import os
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from .policy import Principal


class AuthenticationConfigurationError(RuntimeError):
    pass


class TokenAuthenticator:
    """Environment-backed opaque bearer tokens for local development only."""

    def __init__(
        self,
        customer_tokens: Mapping[str, Mapping[str, Any]] | None = None,
        operator_tokens: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> None:
        self.customer_tokens = dict(customer_tokens or {})
        self.operator_tokens = dict(operator_tokens or {})
        for token, claims in self.customer_tokens.items():
            if not isinstance(token, str) or not token or not isinstance(claims, Mapping):
                raise AuthenticationConfigurationError("Invalid customer token mapping")
        for token, claims in self.operator_tokens.items():
            if not isinstance(token, str) or not token or not isinstance(claims, Mapping):
                raise AuthenticationConfigurationError("Invalid operator token mapping")

    @classmethod
    def from_environment(cls) -> "TokenAuthenticator":
        return cls(
            customer_tokens=_load_mapping("SHADOW_HUNTER_CUSTOMER_TOKENS"),
            operator_tokens=_load_mapping("SHADOW_HUNTER_OPERATOR_TOKENS"),
        )

    def authenticate_customer(self, token: str | None) -> Principal | None:
        return _principal_from_claims(self._lookup(self.customer_tokens, token))

    def authenticate_gateway_tool(self, token: str | None) -> Principal | None:
        # Local direct-tool exercises use the configured customer identity.
        # Cognito mode requires a distinct OBO JWT profile instead.
        return self.authenticate_customer(token)

    def authenticate_operator(self, token: str | None) -> str | None:
        claims = self._lookup(self.operator_tokens, token)
        if claims is None:
            return None
        return _claim_string(claims, "subject_id")

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


class CognitoJWTAuthenticator:
    """Verify customer and delegated Gateway tokens from one Cognito pool.

    Customer chat calls use an access token whose client_id identifies the
    customer application. Gateway tool calls use an OBO token with a configured
    resource audience, scope, and act.sub agent identity.
    """

    def __init__(
        self,
        *,
        issuer: str,
        customer_client_id: str,
        customer_scope: str,
        tool_audience: str,
        tool_scope: str,
        actor_subject: str,
        operator_client_id: str,
        operator_group: str = "shadow_hunter_operators",
        jwks_client: Any | None = None,
    ) -> None:
        parsed = urlsplit(issuer)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.query
            or parsed.fragment
        ):
            raise AuthenticationConfigurationError(
                "Cognito issuer must be an HTTPS issuer URL without query or fragment"
            )
        required_values = {
            "customer_client_id": customer_client_id,
            "customer_scope": customer_scope,
            "tool_audience": tool_audience,
            "tool_scope": tool_scope,
            "actor_subject": actor_subject,
            "operator_client_id": operator_client_id,
            "operator_group": operator_group,
        }
        if any(
            not isinstance(value, str) or not value.strip()
            for value in required_values.values()
        ):
            raise AuthenticationConfigurationError(
                "Cognito JWT configuration contains an empty value"
            )

        self.issuer = issuer.rstrip("/")
        self.customer_client_id = customer_client_id
        self.customer_scope = customer_scope
        self.tool_audience = tool_audience
        self.tool_scope = tool_scope
        if hmac.compare_digest(customer_client_id, operator_client_id):
            raise AuthenticationConfigurationError(
                "Customer and operator Cognito app clients must be distinct"
            )

        self.actor_subject = actor_subject
        self.operator_group = operator_group
        self.operator_client_id = operator_client_id

        try:
            import jwt
        except ImportError as exc:
            raise AuthenticationConfigurationError(
                "Cognito auth requires PyJWT with cryptography support; install the server extra"
            ) from exc
        self._jwt = jwt
        self._jwks_client = jwks_client or jwt.PyJWKClient(
            f"{self.issuer}/.well-known/jwks.json",
            cache_keys=True,
            max_cached_keys=16,
            cache_jwk_set=True,
            lifespan=300,
            timeout=5,
        )

    @classmethod
    def from_environment(cls) -> "CognitoJWTAuthenticator":
        names = {
            "issuer": "SHADOW_HUNTER_COGNITO_ISSUER",
            "customer_client_id": "SHADOW_HUNTER_COGNITO_CUSTOMER_CLIENT_ID",
            "tool_audience": "SHADOW_HUNTER_COGNITO_TOOL_AUDIENCE",
            "tool_scope": "SHADOW_HUNTER_COGNITO_TOOL_SCOPE",
            "actor_subject": "SHADOW_HUNTER_COGNITO_ACTOR_SUB",
            "operator_client_id": "SHADOW_HUNTER_COGNITO_OPERATOR_CLIENT_ID",
        }
        values = {
            key: os.environ.get(env_name, "").strip()
            for key, env_name in names.items()
        }
        missing = [
            env_name for key, env_name in names.items() if not values[key]
        ]
        if missing:
            raise AuthenticationConfigurationError(
                "Missing Cognito configuration: " + ", ".join(missing)
            )
        return cls(
            **values,
            customer_scope=os.environ.get(
                "SHADOW_HUNTER_COGNITO_CUSTOMER_SCOPE",
                "shadow-hunter/customer",
            ).strip(),
            operator_group=os.environ.get(
                "SHADOW_HUNTER_COGNITO_OPERATOR_GROUP",
                "shadow_hunter_operators",
            ).strip()
        )

    def authenticate_customer(self, token: str | None) -> Principal | None:
        claims = self._decode_access_token(token, audience=None)
        if claims is None or claims.get("client_id") != self.customer_client_id:
            return None
        if not self._has_scope(claims, self.customer_scope):
            return None
        return _principal_from_claims(claims)

    def authenticate_gateway_tool(self, token: str | None) -> Principal | None:
        claims = self._decode_access_token(
            token,
            audience=self.tool_audience,
        )
        if claims is None or not self._has_scope(claims, self.tool_scope):
            return None
        actor = claims.get("act")
        actor_subject = actor.get("sub") if isinstance(actor, Mapping) else None
        if (
            not isinstance(actor_subject, str)
            or not hmac.compare_digest(actor_subject, self.actor_subject)
        ):
            return None
        return _principal_from_claims(claims)

    def authenticate_operator(self, token: str | None) -> str | None:
        claims = self._decode_access_token(token, audience=None)
        if claims is None or claims.get("client_id") != self.operator_client_id:
            return None
        groups = claims.get("cognito:groups", [])
        if not isinstance(groups, list) or self.operator_group not in groups:
            return None
        return _claim_string(claims, "sub")

    def _decode_access_token(
        self,
        token: str | None,
        *,
        audience: str | None,
    ) -> Mapping[str, Any] | None:
        if (
            not isinstance(token, str)
            or not token
            or len(token) > 16_384
            or token.count(".") != 2
        ):
            return None
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            claims = self._jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                issuer=self.issuer,
                audience=audience,
                options={
                    "require": ["exp", "iat", "iss", "sub"],
                    "verify_aud": audience is not None,
                },
                leeway=30,
            )
        except Exception:
            # Invalid, expired, unknown-key, or unavailable-JWKS tokens never
            # fall back to local identity or authorize a tool call.
            return None
        if not isinstance(claims, Mapping) or claims.get("token_use") != "access":
            return None
        if audience is not None and claims.get("aud") != audience:
            # Cognito issues one resource audience for this delegated profile.
            # Reject arrays or multi-resource tokens to prevent audience confusion.
            return None
        return claims

    @staticmethod
    def _has_scope(claims: Mapping[str, Any], required_scope: str) -> bool:
        raw_scope = claims.get("scope")
        return (
            isinstance(raw_scope, str)
            and required_scope in raw_scope.split()
        )


def build_authenticator_from_environment() -> TokenAuthenticator | CognitoJWTAuthenticator:
    """Select auth explicitly; Cognito mode never falls back to opaque tokens."""
    mode = os.environ.get("SHADOW_HUNTER_AUTH_MODE", "local").strip().lower()
    if mode == "local":
        return TokenAuthenticator.from_environment()
    if mode == "cognito":
        return CognitoJWTAuthenticator.from_environment()
    raise AuthenticationConfigurationError(
        "SHADOW_HUNTER_AUTH_MODE must be either 'local' or 'cognito'"
    )


def _principal_from_claims(
    claims: Mapping[str, Any] | None,
) -> Principal | None:
    if claims is None:
        return None
    subject_id = _claim_string(claims, "sub", "subject_id")
    tenant_id = _claim_string(claims, "tenant_id", "custom:tenant_id")
    customer_id = _claim_string(claims, "customer_id", "custom:customer_id")
    if not all((subject_id, tenant_id, customer_id)):
        return None
    return Principal(
        subject_id=subject_id,
        tenant_id=tenant_id,
        customer_id=customer_id,
        authenticated=True,
    )


def _claim_string(
    claims: Mapping[str, Any],
    *names: str,
) -> str | None:
    for name in names:
        value = claims.get(name)
        if isinstance(value, str) and value and value.strip() == value:
            return value
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
