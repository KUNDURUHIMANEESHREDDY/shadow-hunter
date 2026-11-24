"""FastAPI application for the governed refund agent and operator console."""
from __future__ import annotations

import os
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import Body, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse

from .agentcore import (
    AgentCoreHarnessClient,
    AgentCoreInvocationError,
    AgentCoreNotConfigured,
)
from .agents import (
    A2AConfigurationError,
    A2AProtocolError,
    AdversarialStrategyEngine,
    AgentAuthenticator,
    BlueAgent,
    EvaluationMetrics,
    RedBlueSimulation,
)
from .approvals import ApprovalService
from .auth import TokenAuthenticator, build_authenticator_from_environment
from .gateway import GatewayError, ToolGateway, public_tool_result
from .evidence import verify_round_evidence
from .mcp_server import build_mcp_runtime
from .nim import (
    NIMBlueDefenseReasoner,
    NIMChatClient,
    NIMConfigurationError,
    NIMInferenceError,
    NIMRedStrategyPlanner,
)
from .policy import PolicyConfig, PolicyEngine, Principal
from .settings import IntegrationSecretStore, IntegrationSettingsError
from .store import SQLiteStore, StoreError
from .synthetic_eval import evaluate as evaluate_synthetic
from .sponsors import (
    BandDecisionPublisher, LyzrAdvisor,
    SponsorConfigurationError, SponsorProviderError, sponsor_status,
)

WEB_ROOT = Path(__file__).parent / "web"
NIM_EVALUATION_TIMEOUT_BUDGET_SECONDS = 24.0


def _bearer(authorization: str | None) -> str | None:
    if not isinstance(authorization, str):
        return None
    scheme, separator, token = authorization.partition(" ")
    if separator and scheme.lower() == "bearer" and token.strip():
        return token.strip()
    return None


def create_app(
    *,
    store: Any | None = None,
    authenticator: Any | None = None,
    harness_client: AgentCoreHarnessClient | None = None,
    integration_secrets: IntegrationSecretStore | None = None,
) -> FastAPI:
    if store is None:
        backend = os.environ.get("SHADOW_HUNTER_STORE_BACKEND", "sqlite").strip().lower()
        if backend == "sqlite":
            database_path = os.environ.get("SHADOW_HUNTER_DB_PATH", "shadow_hunter.sqlite3")
            store = SQLiteStore(database_path)
        elif backend == "dynamodb":
            from .dynamodb_store import DynamoDBStore

            store = DynamoDBStore.from_environment()
        else:
            raise StoreError(
                "SHADOW_HUNTER_STORE_BACKEND must be either 'sqlite' or 'dynamodb'"
            )
    authenticator = authenticator or build_authenticator_from_environment()
    approval_ttl = int(os.environ.get("SHADOW_HUNTER_APPROVAL_TTL_SECONDS", "600"))
    refund_limit = int(os.environ.get("SHADOW_HUNTER_REFUND_LIMIT_MINOR", "10000"))
    approvals = ApprovalService(store, ttl_seconds=approval_ttl)
    policy = PolicyEngine(
        PolicyConfig(self_service_refund_limit_minor=refund_limit)
    )
    gateway = ToolGateway(store, policy, approvals)
    mcp_server, mcp_http_app = build_mcp_runtime(gateway, authenticator)
    if harness_client is None:
        try:
            harness_client = AgentCoreHarnessClient.from_environment()
        except AgentCoreNotConfigured:
            harness_client = None

    def auto_jobs_enabled():
        return (
            isinstance(store, SQLiteStore)
            and isinstance(authenticator, TokenAuthenticator)
            and os.environ.get("SHADOW_HUNTER_LOCAL_READONLY_ENABLED", "").lower()=="true"
            and os.environ.get("SHADOW_HUNTER_AUTH_MODE", "local").lower()=="local"
            and os.environ.get("SHADOW_HUNTER_AUTO_JOBS_ENABLED", "true").lower()=="true"
            and not os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
        )

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        import asyncio
        import logging
        stop=asyncio.Event()
        async def worker():
            from .scheduler import DurableScheduler
            while not stop.is_set():
                if auto_jobs_enabled():
                    try:
                        await asyncio.to_thread(lambda: DurableScheduler(store).dispatch_due(
                            gateway,authenticator.resolve_scheduled_owner))
                    except Exception:
                        logging.getLogger(__name__).warning("Local job dispatch failed")
                try:
                    await asyncio.wait_for(stop.wait(),timeout=1)
                except TimeoutError:
                    pass
        async with mcp_server.session_manager.run():
            task=asyncio.create_task(worker()) if auto_jobs_enabled() else None
            try:
                yield
            finally:
                stop.set()
                if task is not None:
                    await task

    app = FastAPI(
        title="Shadow Hunter",
        version="0.3.0",
        description="Deterministic policy enforcement with an authenticated MCP tool server.",
        lifespan=lifespan,
    )
    @app.middleware("http")
    async def add_browser_security_headers(request, call_next):
        response = await call_next(request)
        response.headers.setdefault(
            "Content-Security-Policy",
            "frame-ancestors 'none'; object-src 'none'; base-uri 'none'",
        )
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        # Operator and agent responses can contain audit evidence or other
        # account-scoped information. Do not let browsers/shared caches retain
        # API data across sign-out, expired tokens, or account switches.
        if request.url.path in {"/operator", "/customer", "/operator/config", "/customer/config", "/local-workspace"} or request.url.path.startswith(("/operator/", "/customer/", "/v1/")):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        return response

    app.state.store = store
    app.state.authenticator = authenticator
    app.state.approvals = approvals
    app.state.gateway = gateway
    app.state.harness_client = harness_client
    app.state.mcp_server = mcp_server
    app.state.integration_secrets = integration_secrets or IntegrationSecretStore.from_environment()
    app.state.demo_mode = os.environ.get("SHADOW_HUNTER_DEMO_MODE", "").lower() == "true"

    def customer(authorization: str | None):
        principal = authenticator.authenticate_customer(_bearer(authorization))
        if principal is None:
            raise HTTPException(status_code=401, detail="Valid customer authentication required")
        return principal

    def gateway_tool_principal(authorization: str | None):
        principal = authenticator.authenticate_gateway_tool(_bearer(authorization))
        if principal is None:
            raise HTTPException(status_code=401, detail="Valid delegated Gateway token required")
        return principal

    def operator(authorization: str | None) -> str:
        operator_id = authenticator.authenticate_operator(_bearer(authorization))
        if operator_id is None:
            raise HTTPException(status_code=401, detail="Valid operator authentication required")
        return operator_id

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "agentcore_configured": harness_client is not None,
            "mcp_server_enabled": True,
            "demo_mode": app.state.demo_mode,
        }

    @app.get("/operator/config")
    def operator_console_config() -> dict[str, Any]:
        # Cognito's hosted UI domain and app-client ID are public OAuth client
        # configuration, not credentials. Never return provider or HMAC secrets.
        hosted_domain = os.environ.get(
            "SHADOW_HUNTER_COGNITO_HOSTED_UI_DOMAIN", ""
        ).strip().rstrip("/")
        parsed_domain = urlsplit(hosted_domain) if hosted_domain else None
        valid_domain = bool(
            parsed_domain
            and parsed_domain.scheme == "https"
            and parsed_domain.hostname
            and not parsed_domain.username
            and not parsed_domain.password
            and not parsed_domain.query
            and not parsed_domain.fragment
            and parsed_domain.path in ("", "/")
        )
        mode = os.environ.get("SHADOW_HUNTER_AUTH_MODE", "local").strip().lower()
        return {
            "auth_mode": mode,
            "cognito": {
                "hosted_ui_domain": hosted_domain if valid_domain else "",
                "operator_client_id": os.environ.get(
                    "SHADOW_HUNTER_COGNITO_OPERATOR_CLIENT_ID", ""
                ).strip(),
                "login_available": bool(
                    mode == "cognito"
                    and valid_domain
                    and os.environ.get(
                        "SHADOW_HUNTER_COGNITO_OPERATOR_CLIENT_ID", ""
                    ).strip()
                ),
            },
        }

    @app.get("/operator")
    def operator_console() -> FileResponse:
        return FileResponse(WEB_ROOT / "operator.html")

    @app.get("/customer/config")
    def customer_console_config() -> dict[str, Any]:
        # Only publish public OAuth metadata, never AWS credentials or M2M secrets.
        hosted_domain = os.environ.get(
            "SHADOW_HUNTER_COGNITO_HOSTED_UI_DOMAIN", ""
        ).strip().rstrip("/")
        parsed = urlsplit(hosted_domain) if hosted_domain else None
        allowed_domain = bool(
            parsed and parsed.scheme == "https" and parsed.hostname
            and not parsed.username and not parsed.password
            and not parsed.query and not parsed.fragment
            and parsed.path in ("", "/")
        )
        mode = os.environ.get("SHADOW_HUNTER_AUTH_MODE", "local").strip().lower()
        client_id = os.environ.get(
            "SHADOW_HUNTER_COGNITO_CUSTOMER_CLIENT_ID", ""
        ).strip()
        customer_scope = os.environ.get(
            "SHADOW_HUNTER_COGNITO_CUSTOMER_SCOPE", "shadow-hunter/customer"
        ).strip()
        tool_scope = os.environ.get(
            "SHADOW_HUNTER_COGNITO_TOOL_SCOPE", "shadow-hunter-api/refunds"
        ).strip()
        scopes_valid = all(
            scope and all(ch.isalnum() or ch in "-_./:" for ch in scope)
            for scope in (customer_scope, tool_scope)
        )
        available = bool(
            mode == "cognito" and allowed_domain and client_id
            and client_id.isalnum() and scopes_valid
        )
        return {
            "auth_mode": mode,
            "cognito": {
                "login_available": available,
                "hosted_ui_domain": hosted_domain if available else "",
                "customer_client_id": client_id if available else "",
                "scopes": (
                    f"openid email {customer_scope} {tool_scope}"
                    if available else ""
                ),
            },
        }

    @app.get("/customer")
    def customer_console() -> FileResponse:
        return FileResponse(WEB_ROOT / "customer.html")

    @app.get("/v1/customer/session")
    def customer_session(
        authorization: str | None = Header(default=None),
    ) -> dict[str, bool]:
        customer(authorization)  # JWT issuer, expiry, audience, scopes and trusted claims.
        return {"authenticated": True}

    @app.get("/v1/operator/settings/integrations")
    def integration_settings_status(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operator(authorization)
        try:
            return app.state.integration_secrets.status()
        except IntegrationSettingsError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.put("/v1/operator/settings/nvidia-nim")
    def save_nvidia_nim_settings(
        body: dict[str, Any] = Body(...),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operator_id = operator(authorization)
        if set(body) != {"api_key"}:
            raise HTTPException(status_code=422, detail="Only api_key is accepted")
        try:
            app.state.integration_secrets.save_nim_api_key(body.get("api_key"))
        except IntegrationSettingsError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        event_id = str(uuid4())
        try:
            store.append_audit(
                event_type="OPERATOR_INTEGRATION_SECRET_UPDATED",
                trace_id=event_id,
                request_id=event_id,
                actor_id=operator_id,
                tenant_id="operator",
                resource_id="nvidia_nim",
                details={"integration": "nvidia_nim", "operation": "secret_updated"},
            )
        except StoreError as exc:
            raise HTTPException(
                status_code=503,
                detail="Secret was updated, but its audit record could not be persisted. Verify status before retrying.",
            ) from exc
        return {"saved": True, "secret_returned": False}

    @app.post("/v1/operator/settings/nvidia-nim/test")
    def test_nvidia_nim_connection(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operator(authorization)
        try:
            client = NIMChatClient.from_environment(timeout_cap_seconds=5)
            probe = client.complete_json(
                model=NIMRedStrategyPlanner.from_environment(client).model,
                system_prompt="Return the required JSON object and nothing else.",
                user_prompt="Reply with the value true for the ok field.",
                seed=0,
                max_tokens=64,
                response_schema={
                    "type": "object",
                    "properties": {"ok": {"type": "boolean"}},
                    "required": ["ok"],
                    "additionalProperties": False,
                },
            )
            if probe.get("ok") is not True:
                raise NIMInferenceError("NVIDIA NIM connection test returned an invalid result")
        except (NIMConfigurationError, NIMInferenceError) as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return {"connected": True, "provider": "nvidia_nim"}

    @app.post("/v1/operator/settings/red-blue/rotate")
    def rotate_red_blue_keys(
        body: dict[str, Any] = Body(default={}),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operator_id = operator(authorization)
        if body:
            raise HTTPException(status_code=422, detail="This operation accepts no fields")
        try:
            key_ids = app.state.integration_secrets.rotate_a2a_keys()
        except IntegrationSettingsError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        event_id = str(uuid4())
        try:
            store.append_audit(
                event_type="OPERATOR_INTEGRATION_SECRET_UPDATED",
                trace_id=event_id,
                request_id=event_id,
                actor_id=operator_id,
                tenant_id="operator",
                resource_id="red_blue_signing",
                details={
                    "integration": "red_blue_signing",
                    "operation": "keys_rotated",
                    **key_ids,
                },
            )
        except StoreError as exc:
            raise HTTPException(
                status_code=503,
                detail="Signing keys were rotated, but their audit record could not be persisted. Verify status before retrying.",
            ) from exc
        return {
            "rotated": True,
            "red_key_id": key_ids["red_key_id"],
            "blue_key_id": key_ids["blue_key_id"],
            "secrets_returned": False,
        }

    @app.get("/v1/operator/sponsors/status")
    def sponsor_integration_status(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operator(authorization)
        return sponsor_status()

    @app.post("/v1/operator/sponsors/lyzr/advise")
    def sponsor_lyzr_advice(
        body: dict[str, Any] = Body(...),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operator_id = operator(authorization)
        if set(body) != {"scenario"} or not isinstance(body.get("scenario"), str):
            raise HTTPException(status_code=422, detail="Only a synthetic scenario is accepted")
        scenario = body["scenario"]
        if not 1 <= len(scenario.strip()) <= 1500:
            raise HTTPException(status_code=422, detail="Scenario must be 1-1500 characters")
        try:
            advisor = LyzrAdvisor.from_environment()
        except SponsorConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        trace_id = str(uuid4())
        try:
            store.append_audit(
                event_type="SPONSOR_LYZR_ADVICE_REQUESTED", trace_id=trace_id,
                request_id=trace_id, actor_id=operator_id, tenant_id="operator",
                resource_id="lyzr_advisory", details={"scenario_length": len(scenario)},
            )
        except StoreError as exc:
            raise HTTPException(status_code=503, detail="Could not audit sponsor request") from exc
        try:
            advice = advisor.advise(scenario)
        except SponsorConfigurationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except SponsorProviderError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return {
            "provider": "lyzr", "authority": "advisory_only",
            "trace_id": trace_id, "advice": advice,
        }

    @app.post("/v1/operator/sponsors/band/publish-trace")
    def sponsor_band_publish_trace(
        body: dict[str, Any] = Body(...),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operator_id = operator(authorization)
        if set(body) != {"trace_id"} or not isinstance(body.get("trace_id"), str):
            raise HTTPException(status_code=422, detail="Only trace_id is accepted")
        trace_id = body["trace_id"]
        if not 1 <= len(trace_id) <= 128 or any(
            char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
            for char in trace_id
        ):
            raise HTTPException(status_code=422, detail="Invalid trace ID")
        try:
            events = store.get_trace_events(trace_id)
        except StoreError as exc:
            raise HTTPException(status_code=503, detail="Could not load audit trace") from exc
        decisions = [
            event for event in events
            if event.get("event_type") == "POLICY_DECISION"
            and event.get("decision") in {"ALLOW", "DENY", "ESCALATE"}
        ]
        if not decisions:
            raise HTTPException(status_code=404, detail="No audited policy decision for this trace")
        selected = decisions[-1]
        decision, reason = selected["decision"], selected.get("reason_code", "")
        try:
            publisher = BandDecisionPublisher.from_environment()
        except SponsorConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        try:
            store.append_audit(
                event_type="SPONSOR_BAND_PUBLICATION_REQUESTED",
                trace_id=trace_id, request_id=str(uuid4()), actor_id=operator_id,
                tenant_id="operator", resource_id="band_collaboration",
                details={"decision": decision, "reason_code": reason},
            )
        except StoreError as exc:
            raise HTTPException(status_code=503, detail="Could not audit publication request") from exc
        try:
            publisher.publish_decision(decision, reason)
        except SponsorConfigurationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except SponsorProviderError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        try:
            store.append_audit(
                event_type="SPONSOR_BAND_SUMMARY_PUBLISHED",
                trace_id=trace_id, request_id=str(uuid4()), actor_id=operator_id,
                tenant_id="operator", resource_id="band_collaboration",
                details={"decision": decision, "reason_code": reason},
            )
        except StoreError as exc:
            raise HTTPException(
                status_code=503,
                detail="BAND accepted the summary, but audit confirmation failed",
            ) from exc
        return {"provider": "band", "published": True, "summary_only": True}

    def require_local_runtime():
        if (
            os.environ.get("SHADOW_HUNTER_LOCAL_READONLY_ENABLED", "").lower() != "true"
            or os.environ.get("SHADOW_HUNTER_AUTH_MODE", "local").lower() != "local"
            or not isinstance(store, SQLiteStore)
            or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
        ):
            raise HTTPException(status_code=503, detail="Local read-only runtime disabled")

    def local_task_inputs(body, authorization):
        principal = gateway_tool_principal(authorization)
        require_local_runtime()
        if set(body) != {"prompt", "order_id"}:
            raise HTTPException(status_code=422, detail="Expected prompt and order_id")
        prompt, order_id = body["prompt"], body["order_id"]
        if (not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 1000
                or not isinstance(order_id, str) or not order_id.strip()
                or len(order_id) > 128 or order_id.strip() != order_id):
            raise HTTPException(status_code=422, detail="Invalid local task")
        return principal, prompt, order_id

    def local_scheduler(authorization):
        principal = gateway_tool_principal(authorization)
        require_local_runtime()
        from .scheduler import DurableScheduler
        return principal, DurableScheduler(store)

    @app.get("/v1/agent/local-jobs")
    def list_local_jobs(authorization: str | None = Header(default=None)):
        principal, scheduler = local_scheduler(authorization)
        from .scheduler import CAPABILITIES
        return {"capabilities": list(CAPABILITIES), "jobs": scheduler.list(principal),
                "automatic_enabled": auto_jobs_enabled()}

    @app.post("/v1/agent/local-jobs")
    def enqueue_local_job(body: dict[str, Any] = Body(...),
                          authorization: str | None = Header(default=None)):
        principal, scheduler = local_scheduler(authorization)
        from .scheduler import QueueBusy
        if not {"capability","order_id"} <= set(body) or set(body)-{"capability","order_id","delay_seconds"}:
            raise HTTPException(status_code=422,detail="Invalid job")
        try:
            delay=body.get("delay_seconds")
            if "delay_seconds" in body and (delay is None or not auto_jobs_enabled()):
                raise ValueError("Automatic scheduling unavailable")
            return {"job_id": scheduler.enqueue(principal,body["capability"],body["order_id"],
                                                delay_seconds=delay),
                    "status":"queued"}
        except ValueError:
            raise HTTPException(status_code=422,detail="Invalid job") from None
        except QueueBusy:
            raise HTTPException(status_code=429,detail="Job queue busy") from None

    @app.post("/v1/agent/local-jobs/run-next")
    def run_next_local_job(authorization: str | None = Header(default=None)):
        principal, scheduler = local_scheduler(authorization)
        from .scheduler import QueueBusy
        try:
            return scheduler.dispatch_next(principal,gateway) or {"status":"empty"}
        except QueueBusy:
            raise HTTPException(status_code=429,detail="Job queue busy") from None

    @app.post("/v1/agent/local-jobs/run-batch")
    def run_batch_local_jobs(authorization: str | None = Header(default=None)):
        principal, scheduler = local_scheduler(authorization)
        return {"jobs": scheduler.dispatch_batch(principal,gateway)}

    @app.post("/v1/agent/local-jobs/{job_id}/cancel")
    def cancel_queued_local_job(job_id: str, authorization: str | None = Header(default=None)):
        principal, scheduler = local_scheduler(authorization)
        if not scheduler.cancel(principal,job_id):
            raise HTTPException(status_code=404,detail="Queued job not available")
        return {"status":"cancelled"}

    @app.get("/local-workspace")
    def local_workspace():
        require_local_runtime()
        return FileResponse(WEB_ROOT / "local-workspace.html", headers={"Cache-Control": "no-store"})

    @app.get("/v1/agent/local-readonly/readiness")
    def local_model_readiness(authorization: str | None = Header(default=None)):
        from .local_runtime import model_readiness
        gateway_tool_principal(authorization)
        require_local_runtime()
        return model_readiness()

    @app.get("/v1/agent/local-readonly/history")
    def local_task_history(authorization: str | None = Header(default=None)):
        principal = gateway_tool_principal(authorization)
        require_local_runtime()
        return {"tasks": store.list_local_tasks(principal)}

    @app.post("/v1/agent/local-readonly")
    def local_readonly_chat(
        body: dict[str, Any] = Body(...),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        from .local_runtime import LocalRuntimeError, public_runtime_error, tracked_readonly_task
        principal, prompt, order_id = local_task_inputs(body, authorization)
        try:
            for event in tracked_readonly_task(gateway, principal, prompt=prompt, order_id=order_id):
                if event["type"] == "result":
                    return event["result"]
            raise LocalRuntimeError("No final result")
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Invalid local task") from exc
        except (LocalRuntimeError, GatewayError, StoreError) as exc:
            raise HTTPException(status_code=503, detail=public_runtime_error(exc)) from None

    from .local_runtime import SupportCancellationRegistry
    local_cancellations = SupportCancellationRegistry()

    @app.post("/v1/agent/local-readonly/cancel/{trace_id}")
    def cancel_local_task(trace_id: str, authorization: str | None = Header(default=None)):
        principal = gateway_tool_principal(authorization)
        require_local_runtime()
        if not local_cancellations.request(principal, trace_id):
            raise HTTPException(status_code=404, detail="Active task not available")
        return {"status": "cancellation_requested"}

    @app.post("/v1/agent/local-readonly/stream")
    def local_readonly_stream(
        body: dict[str, Any] = Body(...),
        authorization: str | None = Header(default=None),
    ):
        import json
        import threading
        from contextlib import closing
        from .local_runtime import LocalRuntimeError, TaskInterrupted, public_runtime_error, tracked_readonly_task
        principal, prompt, order_id = local_task_inputs(body, authorization)
        def events():
            signal = threading.Event()
            trace = None
            try:
                with closing(tracked_readonly_task(gateway, principal, prompt=prompt,
                                                   order_id=order_id, cancellation=signal)) as task:
                    for event in task:
                        if trace is None:
                            local_cancellations.register(principal, event["trace_id"], signal)
                            trace = event["trace_id"]
                        yield json.dumps(event, ensure_ascii=True) + "\n"
            except (LocalRuntimeError, GatewayError, StoreError, ValueError) as exc:
                yield json.dumps({"type": "error", "status": "interrupted" if isinstance(exc, TaskInterrupted) else "failed",
                                  "message": public_runtime_error(exc)}) + "\n"
            finally:
                if trace is not None:
                    local_cancellations.remove(trace, signal)
        return StreamingResponse(events(), media_type="application/x-ndjson",
                                 headers={"X-Accel-Buffering": "no", "Cache-Control": "no-store"})

    @app.post("/v1/agent/chat")
    def agent_chat(
        body: dict[str, Any] = Body(...),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        bearer_token = _bearer(authorization)
        principal = customer(authorization)
        if set(body) - {"prompt", "session_id"}:
            raise HTTPException(status_code=422, detail="Unexpected request fields")
        prompt = body.get("prompt")
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 8_000:
            raise HTTPException(status_code=422, detail="Prompt must contain 1–8000 characters")
        if harness_client is None:
            raise HTTPException(status_code=503, detail="AgentCore harness is not configured")
        session_id = body.get("session_id")
        if session_id is not None and (
            not isinstance(session_id, str)
            or not 33 <= len(session_id) <= 100
            or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for ch in session_id)
        ):
            raise HTTPException(status_code=422, detail="Invalid AgentCore session ID")
        trace_id = str(uuid4())
        try:
            result = harness_client.invoke(
                prompt=prompt,
                bearer_token=bearer_token or "",
                session_id=session_id,
                actor_id=principal.subject_id,
                trace_id=trace_id,
            )
            return result
        except AgentCoreInvocationError:
            raise HTTPException(
                status_code=502,
                detail={
                    "message": "AgentCore invocation failed",
                    "trace_id": trace_id,
                },
            ) from None

    @app.post("/v1/agent/tools/{tool_name}")
    def agent_tool(
        tool_name: str,
        body: dict[str, Any] = Body(...),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        principal = gateway_tool_principal(authorization)
        if set(body) - {"request_id", "trace_id", "arguments"}:
            raise HTTPException(status_code=422, detail="Unexpected request fields")
        arguments = body.get("arguments")
        if not isinstance(arguments, dict):
            raise HTTPException(status_code=422, detail="arguments must be an object")
        for field in ("request_id", "trace_id"):
            value = body.get(field)
            if field in body and (
                not isinstance(value, str)
                or not 1 <= len(value) <= 128
                or value.strip() != value
            ):
                raise HTTPException(status_code=422, detail=f"Invalid {field}")
        try:
            return public_tool_result(
                gateway.invoke(
                    principal=principal,
                    tool_name=tool_name,
                    arguments=arguments,
                    request_id=body.get("request_id") or str(uuid4()),
                    trace_id=body.get("trace_id") or str(uuid4()),
                )
            )
        except GatewayError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/v1/operator/overview")
    def operator_overview(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operator(authorization)
        return store.overview()

    @app.get("/v1/operator/approvals")
    def operator_approvals(
        limit: int = Query(default=100, ge=1, le=500),
        authorization: str | None = Header(default=None),
    ) -> list[dict[str, Any]]:
        operator(authorization)
        return store.list_approvals(limit)

    @app.get("/v1/operator/audit")
    def operator_audit(
        limit: int = Query(default=100, ge=1, le=500),
        authorization: str | None = Header(default=None),
    ) -> list[dict[str, Any]]:
        operator(authorization)
        return store.list_audit(limit)

    @app.get("/v1/operator/audit/trace/{trace_id}")
    def operator_trace(
        trace_id: str,
        authorization: str | None = Header(default=None),
    ) -> list[dict[str, Any]]:
        operator(authorization)
        if not trace_id or len(trace_id) > 128:
            raise HTTPException(status_code=422, detail="Invalid trace ID")
        return store.get_trace_events(trace_id)

    @app.post("/v1/operator/approvals/{approval_id}/approve")
    def approve_request(
        approval_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, str]:
        approver_id = operator(authorization)
        try:
            token = approvals.approve(approval_id, approver_id)
            return {
                "approval_id": approval_id,
                "status": "APPROVED",
                "approval_token": token,
                "token_delivery": "shown_once",
            }
        except StoreError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/operator/approvals/{approval_id}/recover-token")
    def recover_approval_token(
        approval_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, str]:
        operator_id = operator(authorization)
        try:
            token = approvals.rotate_token(approval_id, operator_id)
            return {
                "approval_id": approval_id,
                "status": "APPROVED",
                "approval_token": token,
                "token_delivery": "shown_once",
            }
        except StoreError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/operator/approvals/{approval_id}/reject")
    def reject_request(
        approval_id: str,
        body: dict[str, Any] = Body(default={}),
        authorization: str | None = Header(default=None),
    ) -> dict[str, str]:
        approver_id = operator(authorization)
        reason = body.get("reason", "Rejected by operator")
        if not isinstance(reason, str) or len(reason) > 300:
            raise HTTPException(status_code=422, detail="reason must be at most 300 characters")
        try:
            approvals.reject(approval_id, approver_id, reason)
            return {"approval_id": approval_id, "status": "REJECTED"}
        except StoreError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/operator/refunds/{refund_request_id}/execute")
    def execute_refund(
        refund_request_id: str,
        body: dict[str, Any] = Body(...),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operator_id = operator(authorization)
        if set(body) != {"approval_token"}:
            raise HTTPException(status_code=422, detail="Only approval_token is accepted")
        token = body.get("approval_token")
        if not isinstance(token, str) or not token:
            raise HTTPException(status_code=422, detail="approval_token is required")
        try:
            return gateway.execute_approved_refund(
                refund_request_id=refund_request_id,
                approval_token=token,
                operator_id=operator_id,
            )
        except GatewayError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/operator/demo/seed")
    def seed_demo_data(
        authorization: str | None = Header(default=None),
    ) -> dict[str, str]:
        operator(authorization)
        if not app.state.demo_mode:
            raise HTTPException(status_code=404, detail="Demo mode is disabled")
        if store.get_order("order-demo-001") is not None:
            raise HTTPException(status_code=409, detail="Demo order already exists; refusing to reset its balance")
        store.add_order(
            order_id="order-demo-001",
            tenant_id="demo-tenant",
            customer_id="demo-customer",
            currency="USD",
            refundable_minor=25_000,
            refund_eligible=True,
        )
        return {"status": "seeded", "order_id": "order-demo-001"}

    @app.post("/v1/operator/agent-evaluations/synthetic")
    def run_synthetic_agent_evaluation(
        body: dict[str, Any] = Body(default={}),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Run signed Red/Blue checks in an isolated synthetic SQLite sandbox.

        Only redacted results cross into the main operator audit store.
        The hosted provider client, live customer data and payment paths are
        never used by this endpoint.
        """
        operator_id = operator(authorization)
        if set(body) - {"rounds"}:
            raise HTTPException(status_code=422, detail="Only rounds is accepted")
        rounds = body.get("rounds", 8)
        if type(rounds) is not int or not 1 <= rounds <= 8:
            raise HTTPException(status_code=422, detail="rounds must be an integer between 1 and 8")
        if os.environ.get("SHADOW_HUNTER_SYNTHETIC_EVAL_ENABLED", "true").lower() not in {
            "true", "1", "yes", "on"
        }:
            raise HTTPException(status_code=503, detail="Local synthetic evaluations are disabled")
        try:
            # Independent quota from hosted evaluations; each request is
            # bounded even when no hosted model credentials exist.
            store.reserve_agent_evaluation(
                "synthetic-evaluation:" + operator_id,
                daily_limit=5,
                cooldown_seconds=10,
            )
        except (StoreError, ValueError):
            raise HTTPException(status_code=429, detail="Synthetic evaluation cooldown or daily limit exceeded") from None

        try:
            report = evaluate_synthetic(rounds=rounds)
            if (
                report.get("hosted_model_used") is not False
                or report.get("refunds_executed") != 0
                or len(report.get("results", [])) != rounds
            ):
                raise ValueError("Synthetic evaluator violated isolation invariants")
        except (ValueError, RuntimeError, StoreError):
            raise HTTPException(status_code=503, detail="Synthetic evaluation evidence could not be verified") from None

        run_id = str(uuid4())
        results = []
        for row in report["results"]:
            result = {
                **row,
                "decision": row["actual_decision"],
                "defense_model": "deterministic_rules",
                "strategy_summary": "Fixed synthetic policy scenario",
                "analysis_summary": "Independently reconciled signed A2A and policy audit events",
                "attack_prevented": row["is_attack"] and row["passed"],
                "attack_success": row["is_attack"] and row["actual_decision"] == "ALLOW",
                "evidence_verified": True,
            }
            results.append(result)
            store.append_audit(
                event_type="AGENT_EVALUATION_RESULT",
                trace_id=run_id,
                request_id=run_id + "-" + str(row["round"]),
                decision=result["decision"],
                reason_code=row["reason_code"],
                actor_id="blue-agent",
                tenant_id="evaluation-sandbox",
                resource_id=row["scenario_id"],
                details=result,
            )

        # Commit the summary last: the "latest" view never selects a partially
        # written evaluation if an individual result could not be persisted.
        summary = {
            **report["metrics"],
            "runtime": "deterministic_local_synthetic",
            "hosted_model_used": False,
            "provider": "none",
            "run_id": run_id,
            "rounds_requested": rounds,
            "verified_rounds": len(results),
            "evidence_verification": report["verification_method"],
            "evidence_chain_sha256": report["evidence_chain_sha256"],
            "catalogue_sha256": report["catalogue_sha256"],
            "refunds_executed": 0,
        }
        store.append_audit(
            event_type="AGENT_EVALUATION_RUN",
            trace_id=run_id,
            request_id=run_id,
            actor_id=operator_id,
            tenant_id="evaluation-sandbox",
            details=summary,
        )
        return {**summary, "results": results}

    @app.post("/v1/operator/agent-evaluations/run")
    def run_agent_evaluation(
        body: dict[str, Any] = Body(default={}),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operator_id = operator(authorization)
        if set(body) - {"rounds"}:
            raise HTTPException(status_code=422, detail="Only rounds is accepted")
        if os.environ.get("SHADOW_HUNTER_EVAL_ENABLED", "true").strip().lower() not in {
            "1", "true", "yes", "on"
        }:
            raise HTTPException(status_code=503, detail="Hosted agent evaluations are disabled")
        # The Lambda has a 28-second timeout. Reserve four seconds for local
        # sandbox, policy, and audit work; divide the remaining 24-second NIM
        # budget across the two sequential hosted-model calls in each round.
        max_rounds = 3
        rounds = body.get("rounds", max_rounds)
        if isinstance(rounds, bool) or not isinstance(rounds, int) or not 1 <= rounds <= max_rounds:
            raise HTTPException(
                status_code=422,
                detail=f"rounds must be an integer between 1 and {max_rounds}",
            )
        try:
            agent_authenticator = AgentAuthenticator.from_environment()
            red_key_id = agent_authenticator.key_id_for_agent("red-agent")
            blue_key_id = agent_authenticator.key_id_for_agent("blue-agent")
            nim_timeout_cap = NIM_EVALUATION_TIMEOUT_BUDGET_SECONDS / (2 * rounds)
            nim_client = NIMChatClient.from_environment(
                timeout_cap_seconds=nim_timeout_cap
            )
            red_strategy_planner = NIMRedStrategyPlanner.from_environment(nim_client)
        except (A2AConfigurationError, NIMConfigurationError) as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

        try:
            daily_limit = int(os.environ.get("SHADOW_HUNTER_EVAL_RUNS_PER_OPERATOR_DAILY", "5"))
            cooldown_seconds = int(os.environ.get("SHADOW_HUNTER_EVAL_COOLDOWN_SECONDS", "60"))
            store.reserve_agent_evaluation(
                operator_id,
                daily_limit=daily_limit,
                cooldown_seconds=cooldown_seconds,
            )
        except (ValueError, StoreError):
            raise HTTPException(
                status_code=429,
                detail="Operator evaluation cooldown or daily budget is exhausted",
            ) from None

        run_id = str(uuid4())
        try:
            # Every proposed action is evaluated against synthetic orders in a
            # disposable database. Only redacted case outcomes are copied into
            # the primary audit store; no live customer orders are exposed.
            synthetic_balance = max(refund_limit * 2, 30_000)
            with tempfile.TemporaryDirectory(prefix="shadow-hunter-eval-") as sandbox:
                evaluation_store = SQLiteStore(Path(sandbox) / "evaluation.sqlite3")
                evaluation_store.add_order(
                    order_id="evaluation-order-own",
                    tenant_id="evaluation-tenant",
                    customer_id="evaluation-customer",
                    currency="USD",
                    refundable_minor=synthetic_balance,
                    refund_eligible=True,
                )
                evaluation_store.add_order(
                    order_id="evaluation-order-foreign",
                    tenant_id="evaluation-tenant",
                    customer_id="evaluation-other-customer",
                    currency="USD",
                    refundable_minor=synthetic_balance,
                    refund_eligible=True,
                )
                evaluation_principal = Principal(
                    subject_id="evaluation-subject",
                    tenant_id="evaluation-tenant",
                    customer_id="evaluation-customer",
                    authenticated=True,
                )
                evaluation_gateway = ToolGateway(
                    evaluation_store,
                    PolicyEngine(
                        PolicyConfig(self_service_refund_limit_minor=refund_limit)
                    ),
                    ApprovalService(evaluation_store, ttl_seconds=approval_ttl),
                )
                blue_defense_reasoner = NIMBlueDefenseReasoner.from_environment(
                    nim_client, evaluation_gateway.policy
                )
                blue_agent = BlueAgent(
                    evaluation_gateway,
                    reasoner=blue_defense_reasoner,
                )
                strategies = AdversarialStrategyEngine.for_refund_workload(
                    own_order_id="evaluation-order-own",
                    foreign_order_id="evaluation-order-foreign",
                    currency="USD",
                    refundable_minor=synthetic_balance,
                    self_service_limit_minor=refund_limit,
                )
                simulation = RedBlueSimulation(
                    store=evaluation_store,
                    gateway=evaluation_gateway,
                    authenticator=agent_authenticator,
                    red_key_id=red_key_id,
                    blue_key_id=blue_key_id,
                    # The persistent store makes nonce replay detection survive
                    # across operator-triggered runs and application workers.
                    nonce_store=store,
                    blue_agent=blue_agent,
                    red_strategy_planner=red_strategy_planner,
                )
                observations = simulation.run_autonomous_loop(
                    strategies,
                    principal=evaluation_principal,
                    rounds=rounds,
                )
                metrics = EvaluationMetrics.from_observations(observations)
                trace_evidence = []
                verified_receipts: dict[str, str] = {}
                scenario_lookup = {item.scenario_id: item for item in strategies.scenarios}
                safe_detail_keys = {
                    "scenario_id", "strategy_id", "round", "is_attack",
                    "expected_decision", "actual_decision", "expected_reason_code",
                    "passed", "attack_prevented", "attack_success", "risk_score",
                    "threat_categories", "recommended_action", "message_id",
                    "sender_id", "recipient_id", "message_type", "key_id",
                    "authenticated", "tool_name", "agent_id",
                    "strategy_summary", "strategy_seed", "analysis_summary",
                    "defense_model", "defense_seed",
                    "evidence_sha256", "verification_method",
                }
                for observation in observations:
                    # Re-check independently at reporting time, after the
                    # simulation validated the evidence in each round.
                    scenario = scenario_lookup[observation.scenario_id]
                    receipt = verify_round_evidence(
                        evaluation_store, observation,
                        expected_tool_name=scenario.tool_name,
                        expected_principal_id=evaluation_principal.subject_id,
                    )
                    recorded = [
                        item for item in evaluation_store.get_trace_events(observation.trace_id)
                        if item.get("event_type") == "A2A_EVIDENCE_VERIFIED"
                    ]
                    if len(recorded) != 1 or recorded[0].get("details") != receipt.to_dict():
                        raise ValueError("Independent Red/Blue evidence receipt is invalid")
                    verified_receipts[observation.trace_id] = receipt.semantic_sha256
                    for event in evaluation_store.get_trace_events(observation.trace_id):
                        source_details = event.get("details") or {}
                        trace_evidence.append({
                            "sandbox_trace_id": observation.trace_id,
                            "request_id": event.get("request_id") or observation.proposal_message_id,
                            "event_type": event.get("event_type"),
                            "decision": event.get("decision"),
                            "reason_code": event.get("reason_code"),
                            "actor_id": event.get("actor_id"),
                            "resource_id": event.get("resource_id"),
                            "action_digest": event.get("action_digest"),
                            "policy_id": event.get("policy_id"),
                            "policy_version": event.get("policy_version"),
                            "details": {
                                key: source_details[key]
                                for key in safe_detail_keys
                                if key in source_details
                            },
                        })
                if evaluation_store.overview()["executed_refunds"] != 0:
                    raise ValueError("Evaluation sandbox must not execute refunds")
        except (
            A2AProtocolError,
            A2AConfigurationError,
            NIMConfigurationError,
            NIMInferenceError,
            StoreError,
            ValueError,
        ) as exc:
            raise HTTPException(
                status_code=503,
                detail="Agent evaluation could not complete safely",
            ) from exc

        summary = metrics.to_dict()
        store.append_audit(
            event_type="AGENT_EVALUATION_RUN",
            trace_id=run_id,
            request_id=run_id,
            actor_id=operator_id,
            tenant_id="evaluation-sandbox",
            details={
                **summary,
                "run_id": run_id,
                "runtime": "hosted_nvidia_nim",
                "provider": "nvidia_nim",
                "red_model": red_strategy_planner.model,
                "blue_model": blue_defense_reasoner.model,
                "sandbox": "isolated_synthetic_sqlite",
                "rounds_requested": rounds,
                "agent_authentication": "hmac_sha256",
                "verified_rounds": len(verified_receipts),
                "evidence_verification": "persisted_a2a_and_policy_v1",
            },
        )
        for trace_event in trace_evidence:
            store.append_audit(
                event_type="AGENT_EVALUATION_TRACE_EVENT",
                trace_id=run_id,
                request_id=trace_event["request_id"],
                decision=trace_event["decision"],
                reason_code=trace_event["reason_code"],
                actor_id=trace_event["actor_id"],
                tenant_id="evaluation-sandbox",
                resource_id=trace_event["resource_id"],
                action_digest=trace_event["action_digest"],
                policy_id=trace_event["policy_id"],
                policy_version=trace_event["policy_version"],
                details={
                    "sandbox_trace_id": trace_event["sandbox_trace_id"],
                    "source_event_type": trace_event["event_type"],
                    **trace_event["details"],
                },
            )

        result_rows = []
        for observation in observations:
            result = {
                "scenario_id": observation.scenario_id,
                "strategy_id": observation.strategy_id,
                "round": observation.round_number,
                "is_attack": observation.is_attack,
                "decision": observation.decision.value,
                "reason_code": observation.reason_code,
                "risk_score": observation.risk_score,
                "threat_categories": list(observation.threat_categories),
                "recommended_action": observation.recommended_action,
                "strategy_summary": observation.strategy_summary,
                "strategy_seed": observation.strategy_seed,
                "analysis_summary": observation.analysis_summary,
                "defense_model": observation.defense_model,
                "defense_seed": observation.defense_seed,
                "attack_prevented": observation.attack_prevented,
                "attack_success": observation.attack_success,
                "passed": observation.passed,
                "evidence_verified": True,
                "evidence_sha256": verified_receipts[observation.trace_id],
            }
            result_rows.append(result)
            store.append_audit(
                event_type="AGENT_EVALUATION_RESULT",
                trace_id=run_id,
                request_id=observation.proposal_message_id,
                decision=observation.decision.value,
                reason_code=observation.reason_code,
                actor_id="blue-agent",
                tenant_id="evaluation-sandbox",
                resource_id=observation.scenario_id,
                details=result,
            )
        return {"run_id": run_id, "verified_rounds": len(verified_receipts), **summary, "results": result_rows}

    @app.get("/v1/operator/agent-evaluations/latest")
    def latest_agent_evaluation(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operator(authorization)
        return store.latest_agent_evaluation()

    # The MCP endpoint is /mcp/ (the mount prefix plus the SDK root path).
    # Its host protection remains localhost-only until an explicit allowlist
    # is configured and reviewed for a remote deployment.
    app.mount("/mcp", mcp_http_app)

    return app


def run() -> None:
    import uvicorn

    uvicorn.run(
        "shadow_hunter.api:app",
        host=os.environ.get("SHADOW_HUNTER_HOST", "127.0.0.1"),
        port=int(os.environ.get("SHADOW_HUNTER_PORT", "8000")),
        reload=False,
    )


app = create_app()
