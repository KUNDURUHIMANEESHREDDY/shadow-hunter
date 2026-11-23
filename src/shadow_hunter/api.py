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
from fastapi.responses import FileResponse

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
from .auth import build_authenticator_from_environment
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

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        async with mcp_server.session_manager.run():
            yield

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
        if request.url.path == "/operator" or request.url.path.startswith(("/operator/", "/v1/")):
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
