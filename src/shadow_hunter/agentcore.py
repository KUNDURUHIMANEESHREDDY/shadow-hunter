"""Amazon Bedrock AgentCore managed-harness client.

This adapter invokes an already-deployed AgentCore Harness. It does not create
AWS resources. End-user invocations use a caller-supplied JWT Bearer token;
SigV4 does not carry per-user identity through the Harness. Tool access must be
configured through a Gateway whose Policy Engine is attached in ENFORCE mode.
"""
from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from .agentcore_evidence import read_harness_stream


_COMPACT_JWT = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


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
        # Dependency injection is reserved for tests. Production clients are
        # created per invocation so concurrent users cannot share auth headers.
        self._injected_client = client

    @classmethod
    def from_environment(cls) -> "AgentCoreHarnessClient | None":
        harness_arn = os.environ.get("SHADOW_HUNTER_HARNESS_ARN")
        if not harness_arn:
            return None
        region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
        if not region:
            raise AgentCoreNotConfigured("Set AWS_REGION for the configured harness")
        return cls(harness_arn, region)

    def _create_bearer_client(self, bearer_token: str) -> Any:
        """Create an unsigned SDK client that sends only the caller's JWT.

        A fresh client and token-bound event handler are used for each request.
        The handler refuses to send the token to any host other than this
        Region's AgentCore data-plane endpoint.
        """
        try:
            import boto3
            from botocore import UNSIGNED
            from botocore.config import Config
        except ImportError as exc:
            raise AgentCoreNotConfigured(
                "Install the aws optional dependency to use AgentCore"
            ) from exc

        client = boto3.session.Session().client(
            "bedrock-agentcore",
            region_name=self.region,
            config=Config(signature_version=UNSIGNED),
        )
        allowed_hosts = {
            f"bedrock-agentcore.{self.region}.amazonaws.com",
            f"bedrock-agentcore.{self.region}.amazonaws.com.cn",
        }

        def attach_bearer_token(request: Any, **_: Any) -> None:
            hostname = urlsplit(request.url).hostname
            if hostname not in allowed_hosts:
                raise AgentCoreInvocationError(
                    "Refusing to forward the caller token to an unexpected AgentCore endpoint"
                )
            request.headers["Authorization"] = f"Bearer {bearer_token}"

        client.meta.events.register(
            "before-send.bedrock-agentcore.InvokeHarness",
            attach_bearer_token,
        )
        return client

    def invoke(
        self,
        *,
        prompt: str,
        bearer_token: str,
        session_id: str | None = None,
        actor_id: str,
        trace_id: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 8_000:
            raise AgentCoreInvocationError("Prompt must contain 1–8000 characters")
        if (
            not isinstance(bearer_token, str)
            or _COMPACT_JWT.fullmatch(bearer_token) is None
        ):
            raise AgentCoreInvocationError(
                "A compact OIDC Bearer JWT access token is required for AgentCore Harness invocation"
            )
        if not isinstance(actor_id, str) or not 1 <= len(actor_id) <= 128:
            raise AgentCoreInvocationError("A valid authenticated actor ID is required")

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

        owns_client = self._injected_client is None
        client = self._create_bearer_client(bearer_token) if owns_client else self._injected_client
        try:
            response = client.invoke_harness(
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
            evidence = read_harness_stream(response.get("stream", []))
            return {
                "text": evidence["text"],
                "session_id": session_id,
                "trace_id": trace_id,
                "harness_arn": self.harness_arn,
                "model_tool_activity": evidence["model_tool_activity"],
                # Stream observations are NOT proof that a protected API tool
                # was invoked: operator audit trace correlation is required.
                "tool_execution_verified": False,
            }
        except AgentCoreInvocationError:
            raise
        except Exception as exc:
            raise AgentCoreInvocationError(
                f"AgentCore invocation failed: {type(exc).__name__}"
            ) from exc
        finally:
            if owns_client and client is not None:
                client.close()
