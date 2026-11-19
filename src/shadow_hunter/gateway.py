"""Single tool boundary for the customer-support/refund workload."""
from __future__ import annotations

from typing import Any
from uuid import uuid4

from .approvals import ApprovalService
from .policy import Decision, PolicyEngine, Principal, ToolInvocation
from .store import IdempotencyConflict, SQLiteStore, StoreError


class GatewayError(RuntimeError):
    """A controlled gateway failure safe to return to an API client."""


class ToolGateway:
    """Mediates every agent-facing tool call before business logic executes.

    The model supplies only tool name and arguments. Principal and order facts
    are resolved by the authenticated API and the trusted store respectively.
    Refund execution is deliberately not exposed as an agent tool; it is an
    operator-only action requiring a previously issued approval capability.
    """

    AGENT_TOOLS = frozenset(
        {"get_order", "check_refund_eligibility", "create_refund_request"}
    )

    def __init__(
        self,
        store: SQLiteStore,
        policy: PolicyEngine,
        approvals: ApprovalService,
    ) -> None:
        self.store = store
        self.policy = policy
        self.approvals = approvals

    def invoke(
        self,
        *,
        principal: Principal,
        tool_name: str,
        arguments: dict[str, Any],
        request_id: str | None = None,
        trace_id: str | None = None,
    ) -> dict[str, Any]:
        metadata_valid = all(
            isinstance(value, str)
            and 1 <= len(value) <= 128
            and value.strip() == value
            for value in (request_id, trace_id)
            if value is not None
        )
        request_id = request_id if isinstance(request_id, str) and request_id else str(uuid4())
        trace_id = trace_id if isinstance(trace_id, str) and trace_id else str(uuid4())
        if not metadata_valid:
            self._audit_denial(
                principal, str(tool_name)[:100], request_id, trace_id,
                "INVALID_INVOCATION_METADATA",
            )
            return {
                "decision": Decision.DENY.value,
                "reason_code": "INVALID_INVOCATION_METADATA",
                "request_id": request_id,
                "trace_id": trace_id,
            }

        if not isinstance(tool_name, str) or tool_name not in self.AGENT_TOOLS:
            self._audit_denial(
                principal, tool_name, request_id, trace_id, "UNKNOWN_OR_FORBIDDEN_TOOL"
            )
            return {
                "decision": Decision.DENY.value,
                "reason_code": "UNKNOWN_OR_FORBIDDEN_TOOL",
                "request_id": request_id,
                "trace_id": trace_id,
            }

        if not isinstance(arguments, dict):
            self._audit_denial(
                principal, tool_name, request_id, trace_id, "INVALID_ARGUMENTS"
            )
            return {
                "decision": Decision.DENY.value,
                "reason_code": "INVALID_ARGUMENTS",
                "request_id": request_id,
                "trace_id": trace_id,
            }

        order_id = arguments.get("order_id")
        order = self.store.get_order(order_id) if isinstance(order_id, str) else None
        invocation = ToolInvocation(
            request_id=request_id,
            trace_id=trace_id,
            agent_id="bedrock-refund-assistant",
            tool_name=tool_name,
            arguments=arguments,
        )
        result = self.policy.evaluate(principal, invocation, order)
        self.store.append_audit(
            event_type="POLICY_DECISION",
            trace_id=trace_id,
            request_id=request_id,
            decision=result.decision.value,
            reason_code=result.reason_code,
            actor_id=principal.subject_id,
            tenant_id=principal.tenant_id,
            resource_id=order_id if isinstance(order_id, str) else None,
            action_digest=result.action_digest,
            policy_id=result.policy_id,
            policy_version=result.policy_version,
            details={"tool_name": tool_name},
        )

        if result.decision is Decision.DENY:
            return self._decision_payload(result)

        if order is None:
            raise GatewayError("Policy returned ALLOW without a trusted order")

        if tool_name == "get_order":
            return {
                **self._decision_payload(result),
                "order": {
                    "order_id": order.order_id,
                    "currency": order.currency,
                    "refundable_minor": order.refundable_minor,
                    "refund_eligible": order.refund_eligible,
                },
            }

        if tool_name == "check_refund_eligibility":
            return {
                **self._decision_payload(result),
                "eligibility": {
                    "eligible": order.refund_eligible and order.refundable_minor > 0,
                    "refundable_minor": order.refundable_minor,
                    "currency": order.currency,
                },
            }

        try:
            refund = self.store.create_refund_request(
                principal=principal,
                order=order,
                amount_minor=arguments["amount_minor"],
                currency=arguments["currency"],
                reason=arguments["reason"],
                idempotency_key=arguments["idempotency_key"],
                action_digest=result.action_digest or "",
                policy_id=result.policy_id,
                policy_version=result.policy_version,
                policy_decision=result.decision.value,
                policy_reason_code=result.reason_code,
            )
            approval_id = self.approvals.request(
                refund["refund_request_id"], trace_id=trace_id, request_id=request_id
            )
        except IdempotencyConflict:
            self._audit_denial(
                principal, tool_name, request_id, trace_id, "IDEMPOTENCY_KEY_CONFLICT"
            )
            return {
                "decision": Decision.DENY.value,
                "reason_code": "IDEMPOTENCY_KEY_CONFLICT",
                "request_id": request_id,
                "trace_id": trace_id,
            }
        except StoreError as exc:
            raise GatewayError(str(exc)) from exc

        return {
            **self._decision_payload(result),
            "refund_request": {
                "refund_request_id": refund["refund_request_id"],
                "status": refund["status"],
                "amount_minor": refund["amount_minor"],
                "currency": refund["currency"],
                "policy_decision": refund["policy_decision"],
            },
            "approval": {
                "approval_id": approval_id,
                "status": "PENDING",
                "required_before_execution": True,
            },
        }

    def execute_approved_refund(
        self, *, refund_request_id: str, approval_token: str, operator_id: str
    ) -> dict[str, Any]:
        """Only the authenticated operator API may enter this execution path."""
        try:
            result = self.approvals.execute(
                refund_request_id,
                approval_token,
                operator_id,
                policy_id=self.policy.config.policy_id,
                policy_version=self.policy.config.version,
            )
            return {"decision": Decision.ALLOW.value, **result}
        except StoreError as exc:
            correlation = self.store.get_refund_trace(refund_request_id) or {
                "trace_id": refund_request_id,
                "request_id": refund_request_id,
            }
            self.store.append_audit(
                event_type="REFUND_EXECUTION_BLOCKED",
                trace_id=correlation["trace_id"],
                request_id=correlation["request_id"],
                decision=Decision.DENY.value,
                reason_code="APPROVAL_OR_EXECUTION_CHECK_FAILED",
                actor_id=operator_id,
                resource_id=refund_request_id,
                details={"error": str(exc)[:200]},
            )
            raise GatewayError(str(exc)) from exc

    def _audit_denial(
        self,
        principal: Principal,
        tool_name: str,
        request_id: str,
        trace_id: str,
        reason_code: str,
    ) -> None:
        self.store.append_audit(
            event_type="POLICY_DECISION",
            trace_id=trace_id,
            request_id=request_id,
            decision=Decision.DENY.value,
            reason_code=reason_code,
            actor_id=principal.subject_id,
            tenant_id=principal.tenant_id,
            details={"tool_name": str(tool_name)[:100]},
        )

    @staticmethod
    def _decision_payload(result) -> dict[str, Any]:
        return {
            "decision": result.decision.value,
            "reason_code": result.reason_code,
            "policy_id": result.policy_id,
            "policy_version": result.policy_version,
            "request_id": result.request_id,
            "trace_id": result.trace_id,
            "action_digest": result.action_digest,
        }
