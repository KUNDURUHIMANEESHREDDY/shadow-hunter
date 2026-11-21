"""FastAPI application for the governed refund agent and operator console."""
from __future__ import annotations

import os
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
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
    AgentAuthenticator,
    AdversarialStrategyEngine,
    BlueAgent,
    EvaluationMetrics,
    RedBlueSimulation,
)
from .approvals import ApprovalService
from .auth import build_authenticator_from_environment
from .gateway import GatewayError, ToolGateway
from .mcp_server import build_mcp_runtime
from .nim import (
    NIMBlueDefenseReasoner,
    NIMChatClient,
    NIMConfigurationError,
    NIMInferenceError,
    NIMRedStrategyPlanner,
)
from .policy import PolicyConfig, PolicyEngine, Principal
from .store import SQLiteStore, StoreError


WEB_ROOT = Path(__file__).parent / "web"


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
    app.state.store = store
    app.state.authenticator = authenticator
    app.state.approvals = approvals
    app.state.gateway = gateway
    app.state.harness_client = harness_client
    app.state.mcp_server = mcp_server
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

    @app.get("/operator")
    def operator_console() -> FileResponse:
        return FileResponse(WEB_ROOT / "operator.html")

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
        except AgentCoreInvocationError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

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
            return gateway.invoke(
                principal=principal,
                tool_name=tool_name,
                arguments=arguments,
                request_id=body.get("request_id") or str(uuid4()),
                trace_id=body.get("trace_id") or str(uuid4()),
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
        # The synchronous API Gateway integration is capped at 30 seconds.
        # Two bounded NIM requests per round must fit within that request window.
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
            nim_client = NIMChatClient.from_environment()
            red_strategy_planner = NIMRedStrategyPlanner.from_environment(nim_client)
        except (A2AConfigurationError, NIMConfigurationError) as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

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
                safe_detail_keys = {
                    "scenario_id", "strategy_id", "round", "is_attack",
                    "expected_decision", "actual_decision", "expected_reason_code",
                    "passed", "attack_prevented", "attack_success", "risk_score",
                    "threat_categories", "recommended_action", "message_id",
                    "sender_id", "recipient_id", "message_type", "key_id",
                    "authenticated", "tool_name", "agent_id",
                    "strategy_summary", "strategy_seed", "analysis_summary",
                    "defense_model", "defense_seed",
                }
                for observation in observations:
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
        return {"run_id": run_id, **summary, "results": result_rows}

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
