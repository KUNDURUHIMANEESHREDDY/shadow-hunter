"""Harness streaming output is evidence, never an authorization assertion."""
from __future__ import annotations

import pytest
from shadow_hunter.agentcore import AgentCoreHarnessClient, AgentCoreInvocationError
from shadow_hunter.agentcore_evidence import read_harness_stream

TOKEN = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJjdXN0b21lci0xMjMifQ.signature"


def test_reader_drops_intermediate_tool_data_and_restricts_to_final_assistant():
    stream = [
        {"messageStart": {"role": "assistant"}},
        {"contentBlockDelta": {"delta": {"text": "I am thinking about a tool"}}},
        {"contentBlockStart": {"start": {"toolUse": {"name": "get_order", "toolUseId": "one"}}}},
        {"contentBlockDelta": {"delta": {"toolUse": {"input": "sensitive tool arguments"}}}},
        {"messageStop": {"stopReason": "tool_use"}},
        {"messageStart": {"role": "user"}},
        {"contentBlockStart": {"start": {"toolResult": {"toolUseId": "one", "status": "success"}}}},
        {"contentBlockDelta": {"delta": {"text": "private customer record must not leak"}}},
        {"messageStop": {"stopReason": "tool_result"}},
        {"messageStart": {"role": "assistant"}},
        {"contentBlockDelta": {"delta": {"text": "The request was checked."}}},
        {"messageStop": {"stopReason": "end_turn"}},
    ]
    result = read_harness_stream(stream)
    assert result["text"] == "The request was checked."
    assert result["model_tool_activity"] == {
        "observed_tool_uses": 1, "observed_tool_results": 1,
        "observed_tool_errors": 0, "evidence_level": "stream_only_unverified",
    }
    assert "private customer" not in str(result)
    assert "sensitive tool" not in str(result)


@pytest.mark.parametrize("reason", [
    "max_tokens", "max_iterations_exceeded", "timeout_exceeded",
    "content_filtered", "interrupted", "malformed_tool_use",
])
def test_reader_never_claims_completed_answer_on_failure(reason):
    with pytest.raises(AgentCoreInvocationError, match="did not complete"):
        read_harness_stream([
            {"contentBlockDelta": {"delta": {"text": "Looks successful"}}},
            {"messageStop": {"stopReason": reason}},
        ])


@pytest.mark.parametrize("event", [
    {"runtimeClientError": {"message": "secret third party stack"}},
    {"validationException": {"message": "secret provider error"}},
    {"internalServerException": {"message": "secret AWS data"}},
])
def test_reader_sanitizes_errors(event):
    with pytest.raises(AgentCoreInvocationError) as exc:
        read_harness_stream([event])
    assert "secret" not in str(exc.value)


def test_reader_rejects_empty_unfinished_or_oversized_stream():
    for events in (
        [],
        [{"contentBlockDelta": {"delta": {"text": "not complete"}}}],
        [{"contentBlockDelta": {"delta": {"text": "x" * 16385}}},
         {"messageStop": {"stopReason": "end_turn"}}],
    ):
        with pytest.raises(AgentCoreInvocationError):
            read_harness_stream(events)


def test_client_labels_stream_activity_as_unverified():
    class Fake:
        def invoke_harness(self, **kwargs):
            return {"stream": [
                {"contentBlockStart": {"start": {"toolUse": {"name": "get_order"}}}},
                {"contentBlockDelta": {"delta": {"text": "Order checked"}}},
                {"messageStop": {"stopReason": "end_turn"}},
            ]}
    harness = AgentCoreHarnessClient(
        "arn:aws:bedrock-agentcore:us-east-1:123456789012:harness/demo",
        "us-east-1", client=Fake(),
    )
    data = harness.invoke(prompt="Get synthetic order",bearer_token=TOKEN,actor_id="synthetic-actor")
    assert data["tool_execution_verified"] is False
    assert data["model_tool_activity"]["observed_tool_uses"] == 1
