"""Fault-injection tests for AgentCore stream interruption and HTTP safety.

All Harness responses are injected fakes; no AWS or model endpoint is called.
"""
from __future__ import annotations

from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from shadow_hunter.agentcore import AgentCoreHarnessClient, AgentCoreInvocationError

ARN = "arn:aws:bedrock-agentcore:us-east-1:123456789012:harness/synthetic"
JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.signature"
SESSION = "synthetic-session-000000000000000000000001"


class FaultHarness:
    def __init__(self, outcome):
        self.outcome = outcome
        self.calls = 0
        self.closed = 0

    def invoke_harness(self, **kwargs):
        self.calls += 1
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome

    def close(self):
        self.closed += 1


def invoke(harness):
    return harness.invoke(
        prompt="Read a synthetic order",
        bearer_token=JWT,
        actor_id="synthetic-customer",
        session_id=SESSION,
        trace_id="synthetic-trace",
    )


def test_complete_harness_stream_reports_success_only_after_end_turn():
    transport = FaultHarness({"stream": [
        {"contentBlockDelta": {"delta": {"text": "Synthetic order checked."}}},
        {"messageStop": {"stopReason": "end_turn"}},
    ]})
    result = invoke(AgentCoreHarnessClient(ARN, "us-east-1", client=transport))
    assert result["text"] == "Synthetic order checked."
    assert result["tool_execution_verified"] is False
    assert transport.calls == 1


@pytest.mark.parametrize("outcome", [
    {"stream": [{"contentBlockDelta": {"delta": {"text": "Partial"}}}]},
    {"stream": [{"messageStop": {"stopReason": "max_tokens"}}]},
    {"stream": []},
    {},
    TimeoutError("synthetic disconnected transport"),
])
def test_incomplete_timeout_or_nonfinal_stream_fails_without_automatic_retry(outcome):
    transport = FaultHarness(outcome)
    with pytest.raises(AgentCoreInvocationError):
        invoke(AgentCoreHarnessClient(ARN, "us-east-1", client=transport))
    # Unknown remote side effects: never replay a tool-bearing agent prompt.
    assert transport.calls == 1


def test_partial_stream_followed_by_timeout_is_not_reported_as_complete():
    def broken_stream():
        yield {"contentBlockDelta": {"delta": {"text": "Unverified partial text"}}}
        raise TimeoutError("interrupted after first chunk")

    transport = FaultHarness({"stream": broken_stream()})
    with pytest.raises(AgentCoreInvocationError, match="TimeoutError"):
        invoke(AgentCoreHarnessClient(ARN, "us-east-1", client=transport))
    assert transport.calls == 1


def test_untrusted_provider_diagnostic_does_not_leak_to_caller():
    secret = "synthetic-private-provider-payload"
    transport = FaultHarness({"stream": [
        {"runtimeClientError": {"message": secret}}
    ]})
    with pytest.raises(AgentCoreInvocationError) as exc:
        invoke(AgentCoreHarnessClient(ARN, "us-east-1", client=transport))
    assert secret not in str(exc.value)


def test_owned_transport_closes_after_interrupted_stream(monkeypatch):
    transport = FaultHarness({"stream": [
        {"contentBlockDelta": {"delta": {"text": "Partial"}}}
    ]})
    harness = AgentCoreHarnessClient(ARN, "us-east-1")
    monkeypatch.setattr(harness, "_create_bearer_client", lambda _jwt: transport)
    with pytest.raises(AgentCoreInvocationError):
        invoke(harness)
    assert transport.calls == 1
    assert transport.closed == 1


@pytest.mark.parametrize("failure", ["timeout", "truncated", "provider"])
def test_http_chat_does_not_claim_success_or_expose_upstream_errors(
    tmp_path, monkeypatch, failure
):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from shadow_hunter.auth import TokenAuthenticator
    from shadow_hunter.store import SQLiteStore
    from shadow_hunter import mcp_server

    def stub(_gateway, _auth):
        return (
            SimpleNamespace(session_manager=SimpleNamespace(run=lambda: nullcontext())),
            FastAPI(),
        )

    monkeypatch.setattr(mcp_server, "build_mcp_runtime", stub)
    from shadow_hunter import api as api_module
    monkeypatch.setattr(api_module, "build_mcp_runtime", stub)

    secret = "synthetic-private-provider-payload"
    if failure == "timeout":
        outcome = TimeoutError(secret)
    elif failure == "truncated":
        outcome = {"stream": [
            {"contentBlockDelta": {"delta": {"text": secret}}}
        ]}
    else:
        outcome = {"stream": [{"runtimeClientError": {"message": secret}}]}
    transport = FaultHarness(outcome)
    harness = AgentCoreHarnessClient(ARN, "us-east-1", client=transport)
    auth = TokenAuthenticator(customer_tokens={
        JWT: {
            "subject_id": "synthetic-customer",
            "tenant_id": "synthetic-tenant",
            "customer_id": "synthetic-customer",
        }
    })
    app = api_module.create_app(
        store=SQLiteStore(tmp_path / "timeout-chat.sqlite3"),
        authenticator=auth,
        harness_client=harness,
    )
    with TestClient(app) as client:
        response = client.post(
            "/v1/agent/chat",
            headers={"Authorization": "Bearer " + JWT},
            json={"prompt": "Check the synthetic order"},
        )
    assert response.status_code == 502
    assert response.json()["detail"]["message"] == "AgentCore invocation failed"
    assert response.json()["detail"]["trace_id"]
    assert secret not in response.text
    assert transport.calls == 1
