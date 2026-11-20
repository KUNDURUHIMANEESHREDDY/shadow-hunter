from __future__ import annotations

import asyncio

from shadow_hunter.mcp_server import (
    AGENT_MCP_TOOLS,
    AuthenticatedMCPASGI,
    MCPCaller,
    get_mcp_caller,
    invoke_current_tool,
)
from shadow_hunter.policy import Principal


class StubAuthenticator:
    def __init__(self, accepted: bool = True, raises: bool = False) -> None:
        self.accepted = accepted
        self.raises = raises

    def authenticate_gateway_tool(self, token: str | None):
        if self.raises:
            raise RuntimeError("verification unavailable")
        if self.accepted and token == "valid-token":
            return Principal("subject-1", "tenant-1", "customer-1", True)
        return None


def _http_scope(*authorization_values: bytes):
    return {
        "type": "http",
        "method": "POST",
        "headers": [(b"authorization", value) for value in authorization_values],
    }


def _run_asgi(app, scope):
    events = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(event):
        events.append(event)

    asyncio.run(app(scope, receive, send))
    return events


def _status(events):
    return next(event["status"] for event in events if event["type"] == "http.response.start")


def test_mcp_surface_contains_only_the_three_registered_agent_tools():
    assert AGENT_MCP_TOOLS == {
        "get_order",
        "check_refund_eligibility",
        "create_refund_request",
    }
    assert "execute_refund" not in AGENT_MCP_TOOLS


def test_missing_bearer_is_rejected_before_mcp_dispatch():
    called = []

    async def downstream(scope, receive, send):
        called.append(True)

    app = AuthenticatedMCPASGI(
        downstream, StubAuthenticator(), agent_id="trusted-agent"
    )

    events = _run_asgi(app, _http_scope())

    assert _status(events) == 401
    assert called == []


def test_duplicate_authorization_headers_are_rejected():
    called = []

    async def downstream(scope, receive, send):
        called.append(True)

    app = AuthenticatedMCPASGI(
        downstream, StubAuthenticator(), agent_id="trusted-agent"
    )

    events = _run_asgi(
        app,
        _http_scope(b"Bearer valid-token", b"Bearer other-token"),
    )

    assert _status(events) == 401
    assert called == []


def test_invalid_token_and_authenticator_failure_both_fail_closed():
    async def downstream(scope, receive, send):
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    for authenticator in (
        StubAuthenticator(accepted=False),
        StubAuthenticator(raises=True),
    ):
        app = AuthenticatedMCPASGI(
            downstream, authenticator, agent_id="trusted-agent"
        )
        events = _run_asgi(app, _http_scope(b"Bearer valid-token"))
        assert _status(events) == 401


def test_authenticated_request_gets_server_assigned_identity_and_context_resets():
    observed = []

    async def downstream(scope, receive, send):
        observed.append(get_mcp_caller())
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    app = AuthenticatedMCPASGI(
        downstream, StubAuthenticator(), agent_id="trusted-agent"
    )

    events = _run_asgi(app, _http_scope(b"Bearer valid-token"))

    assert _status(events) == 204
    assert observed == [
        MCPCaller(
            principal=Principal("subject-1", "tenant-1", "customer-1", True),
            agent_id="trusted-agent",
        )
    ]
    assert get_mcp_caller() is None


def test_tool_dispatch_without_http_identity_returns_deny_without_calling_gateway():
    class RecordingGateway:
        def __init__(self):
            self.called = False

        def invoke(self, **kwargs):
            self.called = True
            return {"decision": "ALLOW", **kwargs}

    gateway = RecordingGateway()

    result = invoke_current_tool(
        gateway, "get_order", {"order_id": "order-1"}
    )

    assert result["decision"] == "DENY"
    assert result["reason_code"] == "MCP_AUTHENTICATION_REQUIRED"
    assert gateway.called is False


def test_tool_dispatch_uses_authenticated_principal_and_server_assigned_agent():
    class RecordingGateway:
        def __init__(self):
            self.arguments = None

        def invoke(self, **kwargs):
            self.arguments = kwargs
            return {"decision": "ALLOW", "trace_id": kwargs["trace_id"]}

    gateway = RecordingGateway()
    principal = Principal("subject-1", "tenant-1", "customer-1", True)
    identity = MCPCaller(principal=principal, agent_id="trusted-agent")

    from shadow_hunter import mcp_server

    marker = mcp_server._current_caller.set(identity)
    try:
        result = invoke_current_tool(
            gateway, "get_order", {"order_id": "order-1"}
        )
    finally:
        mcp_server._current_caller.reset(marker)

    assert result["decision"] == "ALLOW"
    assert gateway.arguments["principal"] == principal
    assert gateway.arguments["agent_id"] == "trusted-agent"
    assert gateway.arguments["tool_name"] == "get_order"



def test_customer_pass_through_uses_cognito_customer_authenticator():
    class CustomerAuthenticator:
        def authenticate_customer(self, token):
            if token == "customer-token":
                return Principal("customer-sub", "tenant-1", "customer-1", True)
            return None

    seen = []

    async def downstream(scope, receive, send):
        seen.append(get_mcp_caller())
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    app = AuthenticatedMCPASGI(
        downstream,
        CustomerAuthenticator(),
        agent_id="agntid-integration",
        auth_profile="customer",
    )
    events = _run_asgi(app, _http_scope(b"Bearer customer-token"))
    assert _status(events) == 204
    assert seen[0].principal.subject_id == "customer-sub"
    assert seen[0].agent_id == "agntid-integration"


def test_demo_header_is_uuid_correlation_only():
    from shadow_hunter.mcp_server import _demo_run_id_from_scope

    run_id = "9c7f5c21-7c18-4b99-9c14-f07fcf79c401"
    scope = _http_scope(b"Bearer valid-token")
    scope["headers"].append((b"x-shadow-hunter-demo-id", run_id.encode("ascii")))
    assert _demo_run_id_from_scope(scope) == run_id


def test_duplicate_demo_correlation_headers_are_ignored():
    from shadow_hunter.mcp_server import _demo_run_id_from_scope

    run_id = b"9c7f5c21-7c18-4b99-9c14-f07fcf79c401"
    scope = _http_scope(b"Bearer valid-token")
    scope["headers"].extend([
        (b"x-shadow-hunter-demo-id", run_id),
        (b"x-shadow-hunter-demo-id", run_id),
    ])
    assert _demo_run_id_from_scope(scope) is None


def test_customer_profile_rejects_authenticator_without_customer_method():
    import pytest

    with pytest.raises(TypeError, match="authenticate_customer"):
        AuthenticatedMCPASGI(
            lambda scope, receive, send: None,
            object(),
            agent_id="agent",
            auth_profile="customer",
        )
