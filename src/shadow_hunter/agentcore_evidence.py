"""Privacy-bounded reader for AgentCore Harness event streams.

Only final assistant response text is exposed. Untrusted tool input/output,
intermediate chain-of-thought, and provider error details never leave this
module. Observed stream events are *not* verified gateway tool execution.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

MAX_EVENTS = 3000
MAX_FINAL_OUTPUT_BYTES = 16 * 1024


def read_harness_stream(stream: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    from .agentcore import AgentCoreInvocationError

    role = "assistant"  # Backwards compatibility with minimal SDK test streams.
    fragments: list[str] = []
    final_text: str | None = None
    current_text_bytes = 0
    uses = 0
    results = 0
    failed_results = 0
    seen_message_stop = False
    count = 0
    for event in stream:
        count += 1
        if count > MAX_EVENTS or not isinstance(event, Mapping):
            raise AgentCoreInvocationError("Invalid or excessively long AgentCore stream")
        if any(name in event for name in (
            "runtimeClientError", "internalServerException", "validationException",
            "accessDeniedException", "throttlingException",
            "serviceQuotaExceededException",
        )):
            raise AgentCoreInvocationError("AgentCore returned an execution error")
        if "messageStart" in event:
            data = event["messageStart"]
            if not isinstance(data, Mapping):
                raise AgentCoreInvocationError("Invalid AgentCore message start")
            role = data.get("role", "")
            if role not in {"assistant", "user"}:
                raise AgentCoreInvocationError("Unexpected AgentCore message role")
            fragments = []
            current_text_bytes = 0
        if "contentBlockStart" in event:
            item = event["contentBlockStart"]
            start = item.get("start", {}) if isinstance(item, Mapping) else {}
            if isinstance(start, Mapping):
                if isinstance(start.get("toolUse"), Mapping):
                    uses += 1
                result = start.get("toolResult")
                if isinstance(result, Mapping):
                    results += 1
                    if result.get("status") == "error":
                        failed_results += 1
        if "contentBlockDelta" in event:
            block = event["contentBlockDelta"]
            delta = block.get("delta", {}) if isinstance(block, Mapping) else {}
            if role == "assistant" and isinstance(delta, Mapping):
                snippet = delta.get("text")
                if isinstance(snippet, str):
                    current_text_bytes += len(snippet.encode("utf-8"))
                    if current_text_bytes > MAX_FINAL_OUTPUT_BYTES:
                        raise AgentCoreInvocationError("AgentCore output exceeds the safety limit")
                    fragments.append(snippet)
        if "messageStop" in event:
            item = event["messageStop"]
            reason = item.get("stopReason") if isinstance(item, Mapping) else None
            if reason == "end_turn":
                if role != "assistant":
                    raise AgentCoreInvocationError("AgentCore did not finish with an assistant reply")
                final_text = "".join(fragments)
                seen_message_stop = True
            elif reason in {"tool_use", "tool_result", "partial_turn"}:
                # Discard intermediate tool narratives. They are not final
                # assistant output and must not be presented as completion.
                fragments = []
                current_text_bytes = 0
            else:
                raise AgentCoreInvocationError("AgentCore did not complete its response")
    if not seen_message_stop or not isinstance(final_text, str) or not final_text.strip():
        raise AgentCoreInvocationError("AgentCore did not return a completed assistant answer")
    return {
        "text": final_text,
        "model_tool_activity": {
            "observed_tool_uses": uses,
            "observed_tool_results": results,
            "observed_tool_errors": failed_results,
            "evidence_level": "stream_only_unverified",
        },
    }
