"""Amazon Bedrock AgentCore managed-harness client.

This adapter invokes an already-deployed AgentCore Harness. It does not create
AWS resources. Tool access must be configured on the harness through a
Gateway whose Policy Engine is attached in ENFORCE mode.
"""
from __future__ import annotations

import os
import re
from typing import Any
from uuid import uuid4


class AgentCoreNotConfigured(RuntimeError):
    pass


class AgentCoreInvocationError(RuntimeError):
    pass


class AgentCoreHarnessClient:
    def __init__(self, harness_arn: str, region: str, client: Any | None = None) -> None:
        if not harness_arn or not harness_arn.startswith("arn:"):
            raise AgentCoreNotConfigured("A valid AgentCore harness ARN is required")
        if not region:
            raise AgentCoreNotConfigured("AWS region is required")
        self.harness_arn = harness_arn
        self.region = region
        if client is None:
            try:
                import boto3
            except ImportError as exc:
                raise AgentCoreNotConfigured(
                    "Install the aws optional dependency to use AgentCore"
                ) from exc
            client = boto3.client("bedrock-agentcore", region_name=region)
        self.client = client

    @classmethod
    def from_environment(cls) -> "AgentCoreHarnessClient | None":
        harness_arn = os.environ.get("SHADOW_HUNTER_HARNESS_ARN")
        if not harness_arn:
            return None
        region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
        if not region:
            raise AgentCoreNotConfigured("Set AWS_REGION for the configured harness")
        return cls(harness_arn, region)

    def invoke(
        self,
        *,
        prompt: str,
        session_id: str | None = None,
        actor_id: str,
        trace_id: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 8_000:
            raise AgentCoreInvocationError("Prompt must contain 1–8000 characters")
        session_id = session_id or f"{uuid4().hex}{uuid4().hex}"
        if (
            not isinstance(session_id, str)
            or not 33 <= len(session_id) <= 100
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", session_id) is None
        ):
            raise AgentCoreInvocationError(
                "AgentCore session IDs must be 33–100 alphanumeric, hyphen, or underscore characters"
            )
        trace_id = trace_id or str(uuid4())
        if not isinstance(trace_id, str) or not trace_id or len(trace_id) > 1024:
            raise AgentCoreInvocationError("Invalid AgentCore trace ID")
        try:
            response = self.client.invoke_harness(
                harnessArn=self.harness_arn,
                runtimeSessionId=session_id,
                runtimeUserId=actor_id,
                actorId=actor_id,
                traceId=trace_id,
                messages=[
                    {
                        "role": "user",
                        "content": [{"text": prompt}],
                    }
                ],
            )
            text_parts: list[str] = []
            for event in response.get("stream", []):
                if "contentBlockDelta" in event:
                    delta = event["contentBlockDelta"].get("delta", {})
                    if isinstance(delta.get("text"), str):
                        text_parts.append(delta["text"])
                elif "runtimeClientError" in event:
                    message = event["runtimeClientError"].get(
                        "message", "Runtime client error"
                    )
                    raise AgentCoreInvocationError(message)
                elif "internalServerException" in event:
                    raise AgentCoreInvocationError("AgentCore returned an internal error")
            return {
                "text": "".join(text_parts),
                "session_id": session_id,
                "trace_id": trace_id,
                "harness_arn": self.harness_arn,
            }
        except AgentCoreInvocationError:
            raise
        except Exception as exc:
            raise AgentCoreInvocationError(
                f"AgentCore invocation failed: {type(exc).__name__}"
            ) from exc
