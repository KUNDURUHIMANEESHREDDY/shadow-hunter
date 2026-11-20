from __future__ import annotations

from shadow_hunter.agentcore import AgentCoreHarnessClient, AgentCoreInvocationError


class FakeHarnessClient:
    def __init__(self):
        self.kwargs = None

    def invoke_harness(self, **kwargs):
        self.kwargs = kwargs
        return {
            "stream": [
                {"contentBlockDelta": {"delta": {"text": "Refund "}}},
                {"contentBlockDelta": {"delta": {"text": "request recorded."}}},
                {"messageStop": {"stopReason": "end_turn"}},
            ]
        }


def test_agentcore_harness_client_uses_managed_harness_api():
    client = FakeHarnessClient()
    harness = AgentCoreHarnessClient(
        "arn:aws:bedrock-agentcore:us-east-1:123456789012:harness/demo",
        "us-east-1",
        client=client,
    )
    result = harness.invoke(
        prompt="Please check my order",
        bearer_token="eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJjdXN0b21lci0xMjMifQ.signature",
        session_id="session-id-with-at-least-33-characters",
        actor_id="customer-123",
    )
    assert result["text"] == "Refund request recorded."
    assert client.kwargs["runtimeSessionId"] == "session-id-with-at-least-33-characters"
    assert client.kwargs["runtimeUserId"] == "customer-123"
    assert client.kwargs["actorId"] == "customer-123"
    assert client.kwargs["traceId"] == result["trace_id"]


def test_agentcore_harness_client_rejects_short_session_id():
    harness = AgentCoreHarnessClient(
        "arn:aws:bedrock-agentcore:us-east-1:123456789012:harness/demo",
        "us-east-1",
        client=FakeHarnessClient(),
    )
    try:
        harness.invoke(
            prompt="Hello",
            bearer_token="eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJjdXN0b21lci0xMjMifQ.signature",
            session_id="short",
            actor_id="customer-123",
        )
    except Exception as exc:
        assert "at least 33 characters" in str(exc)
    else:
        raise AssertionError("Short session IDs must be rejected")


def test_agentcore_harness_client_rejects_session_id_over_100_characters():
    harness = AgentCoreHarnessClient(
        "arn:aws:bedrock-agentcore:us-east-1:123456789012:harness/demo",
        "us-east-1",
        client=FakeHarnessClient(),
    )
    try:
        harness.invoke(
            prompt="Hello",
            bearer_token="eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJjdXN0b21lci0xMjMifQ.signature",
            session_id="a" * 101,
            actor_id="customer-123",
        )
    except Exception as exc:
        assert "33–100" in str(exc)
    else:
        raise AssertionError("Overlong session IDs must be rejected")


def test_agentcore_harness_client_rejects_opaque_local_tokens():
    harness = AgentCoreHarnessClient(
        "arn:aws:bedrock-agentcore:us-east-1:123456789012:harness/demo",
        "us-east-1",
        client=FakeHarnessClient(),
    )
    try:
        harness.invoke(
            prompt="Hello",
            bearer_token="local-customer-token",
            actor_id="customer-123",
        )
    except AgentCoreInvocationError as exc:
        assert "JWT access token" in str(exc)
    else:
        raise AssertionError("Opaque local tokens must not be forwarded to the Harness")
