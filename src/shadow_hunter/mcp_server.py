"""Authenticated MCP adapter for Shadow Hunter's existing tool gateway.

This is a Streamable HTTP server intended to sit behind an MCP-aware proxy.
It does not trust MCP client metadata or tool arguments for caller identity.
Every HTTP request must carry a token accepted by the existing gateway
authenticator; every tool invocation is then evaluated by ToolGateway.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from .auth import CognitoJWTAuthenticator
from .gateway import ToolGateway
from .policy import Principal


AGENT_MCP_TOOLS = frozenset(
    {"get_order", "check_refund_eligibility", "create_refund_request"}
)
_AGENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_MAX_BEARER_LENGTH = 16_384


@dataclass(frozen=True, slots=True)
class MCPCaller:
    """Identity established by the HTTP authentication boundary."""

    principal: Principal
    agent_id: str


_current_caller: ContextVar[MCPCaller | None] = ContextVar(
    "shadow_hunter_mcp_caller", default=None
)


def get_mcp_caller() -> MCPCaller | None:
    """Return the authenticated identity for the current MCP request."""

    return _current_caller.get()


def _trusted_agent_id(authenticator: Any) -> str:
    """Resolve agent identity only from verified server-side configuration."""

    if isinstance(authenticator, CognitoJWTAuthenticator):
        # authenticate_gateway_tool validates the token's act.sub against this
        # configured value before the request reaches a tool handler.
        candidate = authenticator.actor_subject
    else:
        # Opaque local token mappings are for local demonstrations only.
        candidate = os.environ.get(
            "SHADOW_HUNTER_MCP_LOCAL_AGENT_ID", "shadow-hunter-local-agent"
        ).strip()

    if not isinstance(candidate, str) or _AGENT_ID.fullmatch(candidate) is None:
        raise RuntimeError("A valid server-configured MCP agent identity is required")
    return candidate


def _bearer_from_scope(scope: dict[str, Any]) -> str | None:
    """Read exactly one Authorization Bearer header; reject ambiguous input."""

    headers = scope.get("headers", [])
    values = [
        value
        for name, value in headers
        if isinstance(name, bytes) and name.lower() == b"authorization"
    ]
    if len(values) != 1:
        return None

    try:
        authorization = values[0].decode("latin-1")
    except (AttributeError, UnicodeDecodeError):
        return None
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1]
    if not token or len(token) > _MAX_BEARER_LENGTH:
        return None
    return token


async def _reject(send: Any, *, status: int, error: str) -> None:
    """Send a minimal response without exposing auth or policy internals."""

    body = json.dumps({"error": error}, separators=(",", ":")).encode("utf-8")
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("ascii")),
        (b"cache-control", b"no-store"),
    ]
    if status == 401:
        headers.append(
            (b"www-authenticate", b'Bearer realm="shadow-hunter-mcp", error="invalid_token"')
        )
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


def _valid_principal(value: object) -> bool:
    return (
        isinstance(value, Principal)
        and value.authenticated is True
        and all(
            isinstance(item, str) and bool(item) and item.strip() == item
            for item in (value.subject_id, value.tenant_id, value.customer_id)
        )
    )


class AuthenticatedMCPASGI:
    """Authenticate every HTTP request before MCP parses or dispatches it."""

    def __init__(self, app: Any, authenticator: Any, agent_id: str) -> None:
        if not callable(getattr(authenticator, "authenticate_gateway_tool", None)):
            raise TypeError("authenticator must implement authenticate_gateway_tool")
        if not isinstance(agent_id, str) or _AGENT_ID.fullmatch(agent_id) is None:
            raise ValueError("agent_id must be a valid server-configured identifier")
        self.app = app
        self.authenticator = authenticator
        self.agent_id = agent_id

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            # Streamable HTTP is the only transport mounted by this adapter.
            await self.app(scope, receive, send)
            return

        bearer = _bearer_from_scope(scope)
        if bearer is None:
            await _reject(send, status=401, error="authentication_required")
            return

        try:
            principal = self.authenticator.authenticate_gateway_tool(bearer)
        except Exception:
            # JWKS/network/configuration failures never fall back to local identity.
            principal = None

        if not _valid_principal(principal):
            await _reject(send, status=401, error="authentication_required")
            return

        caller = MCPCaller(principal=principal, agent_id=self.agent_id)
        context_token = _current_caller.set(caller)
        try:
            await self.app(scope, receive, send)
        finally:
            _current_caller.reset(context_token)


def invoke_current_tool(
    gateway: ToolGateway,
    tool_name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    """Submit one MCP proposal through the existing deterministic gateway."""

    caller = get_mcp_caller()
    request_id = str(uuid4())
    trace_id = str(uuid4())
    if caller is None:
        # In-memory or non-HTTP invocation has no authenticated request context.
        # It must never inherit an identity from clientInfo or tool arguments.
        return {
            "decision": "DENY",
            "reason_code": "MCP_AUTHENTICATION_REQUIRED",
            "request_id": request_id,
            "trace_id": trace_id,
        }

    return gateway.invoke(
        principal=caller.principal,
        agent_id=caller.agent_id,
        tool_name=tool_name,
        arguments=arguments,
        request_id=request_id,
        trace_id=trace_id,
    )


def build_mcp_runtime(gateway: ToolGateway, authenticator: Any) -> tuple[Any, Any]:
    """Build the official MCP SDK server and its authenticated ASGI application."""

    try:
        from mcp.server import MCPServer
    except ImportError as exc:
        raise RuntimeError(
            'Install the server extra to enable MCP: pip install -e ".[server]"'
        ) from exc

    agent_id = _trusted_agent_id(authenticator)
    server = MCPServer("Shadow Hunter")

    @server.tool()
    async def get_order(order_id: str) -> dict[str, Any]:
        """Read a summary of an order owned by the authenticated customer."""

        return await asyncio.to_thread(
            invoke_current_tool, gateway, "get_order", {"order_id": order_id}
        )

    @server.tool()
    async def check_refund_eligibility(order_id: str) -> dict[str, Any]:
        """Check refund eligibility using trusted order and customer records."""

        return await asyncio.to_thread(
            invoke_current_tool,
            gateway,
            "check_refund_eligibility",
            {"order_id": order_id},
        )

    @server.tool()
    async def create_refund_request(
        order_id: str,
        amount_minor: int,
        currency: str,
        reason: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Create a refund request; execution still requires operator approval."""

        return await asyncio.to_thread(
            invoke_current_tool,
            gateway,
            "create_refund_request",
            {
                "order_id": order_id,
                "amount_minor": amount_minor,
                "currency": currency,
                "reason": reason,
                "idempotency_key": idempotency_key,
            },
        )

    # The SDK's default transport security is localhost-only. Do not expose this
    # endpoint on a public hostname until an explicit host allowlist and TLS
    # deployment have been reviewed.
    http_app = server.streamable_http_app(streamable_http_path="/")
    authenticated_app = AuthenticatedMCPASGI(
        http_app, authenticator=authenticator, agent_id=agent_id
    )
    return server, authenticated_app
