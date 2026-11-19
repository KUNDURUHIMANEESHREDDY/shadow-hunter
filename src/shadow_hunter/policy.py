"""Deterministic policy evaluation for the first support/refund workload.

The caller must resolve Principal and OrderSnapshot from trusted server-side
identity and storage. Neither value may be constructed from model arguments.
This module decides whether a proposed tool call may proceed; it does not
execute tools, create approvals, or contact AWS.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ESCALATE = "ESCALATE"


@dataclass(frozen=True, slots=True)
class Principal:
    """Authenticated identity supplied by the API/authentication boundary."""

    subject_id: str | None
    tenant_id: str | None
    customer_id: str | None
    authenticated: bool


@dataclass(frozen=True, slots=True)
class OrderSnapshot:
    """Minimal order authorization facts loaded from the trusted data store."""

    order_id: str
    tenant_id: str
    customer_id: str
    currency: str
    refundable_minor: int
    refund_eligible: bool


@dataclass(frozen=True, slots=True)
class ToolInvocation:
    """Normalized tool request emitted by the agent runtime."""

    request_id: str
    trace_id: str
    agent_id: str
    tool_name: str
    arguments: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    policy_id: str = "support-refund-baseline"
    version: str = "0.1.0"
    self_service_refund_limit_minor: int = 10_000
    max_reason_chars: int = 500

    def __post_init__(self) -> None:
        if not self.policy_id.strip() or not self.version.strip():
            raise ValueError("policy_id and version must be non-empty")
        if (
            isinstance(self.self_service_refund_limit_minor, bool)
            or not isinstance(self.self_service_refund_limit_minor, int)
            or self.self_service_refund_limit_minor <= 0
        ):
            raise ValueError("self-service refund limit must be a positive integer")
        if (
            isinstance(self.max_reason_chars, bool)
            or not isinstance(self.max_reason_chars, int)
            or self.max_reason_chars <= 0
        ):
            raise ValueError("max_reason_chars must be a positive integer")


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    decision: Decision
    reason_code: str
    policy_id: str
    policy_version: str
    request_id: str
    trace_id: str
    action_digest: str | None


class PolicyEngine:
    """Fail-closed policy decision point for refund-workload tool calls.

    Supported tools in this first slice:
      * get_order
      * check_refund_eligibility
      * create_refund_request

    Refund execution is intentionally not registered until the parameter-bound
    approval verifier and idempotent execution path exist. Unknown tools deny.
    """

    _ARGUMENTS: dict[str, frozenset[str]] = {
        "get_order": frozenset({"order_id"}),
        "check_refund_eligibility": frozenset({"order_id"}),
        "create_refund_request": frozenset(
            {"order_id", "amount_minor", "currency", "reason", "idempotency_key"}
        ),
    }
    _CURRENCY = re.compile(r"^[A-Z]{3}$")

    def __init__(self, config: PolicyConfig | None = None) -> None:
        self.config = config if config is not None else PolicyConfig()
        if not isinstance(self.config, PolicyConfig):
            raise TypeError("config must be a PolicyConfig")

    def evaluate(
        self,
        principal: Principal | None,
        invocation: ToolInvocation | None,
        order: OrderSnapshot | None,
    ) -> PolicyDecision:
        """Evaluate one tool call. Every malformed or exceptional path denies."""
        request_id = _safe_identifier(
            invocation.request_id if isinstance(invocation, ToolInvocation) else None
        )
        trace_id = _safe_identifier(
            invocation.trace_id if isinstance(invocation, ToolInvocation) else None
        )

        try:
            return self._evaluate(principal, invocation, order, request_id, trace_id)
        except Exception:
            # Authorization must fail closed if an unexpected evaluation error occurs.
            return self._decision(
                Decision.DENY,
                "POLICY_EVALUATION_ERROR",
                request_id,
                trace_id,
                None,
            )

    def _evaluate(
        self,
        principal: Principal | None,
        invocation: ToolInvocation | None,
        order: OrderSnapshot | None,
        request_id: str,
        trace_id: str,
    ) -> PolicyDecision:
        if not isinstance(invocation, ToolInvocation):
            return self._decision(
                Decision.DENY, "INVOCATION_CONTEXT_MISSING", request_id, trace_id, None
            )
        if not _valid_identifier(invocation.request_id) or not _valid_identifier(
            invocation.trace_id
        ) or not _valid_identifier(invocation.agent_id):
            return self._decision(
                Decision.DENY, "INVOCATION_METADATA_INVALID", request_id, trace_id, None
            )

        if not isinstance(principal, Principal):
            return self._decision(
                Decision.DENY, "PRINCIPAL_CONTEXT_MISSING", request_id, trace_id, None
            )
        if principal.authenticated is not True:
            return self._decision(
                Decision.DENY, "PRINCIPAL_NOT_AUTHENTICATED", request_id, trace_id, None
            )
        if not all(
            _valid_identifier(value)
            for value in (principal.subject_id, principal.tenant_id, principal.customer_id)
        ):
            return self._decision(
                Decision.DENY, "PRINCIPAL_CONTEXT_INVALID", request_id, trace_id, None
            )

        expected_arguments = self._ARGUMENTS.get(invocation.tool_name)
        if expected_arguments is None:
            return self._decision(
                Decision.DENY, "UNKNOWN_TOOL", request_id, trace_id, None
            )
        if not isinstance(invocation.arguments, Mapping):
            return self._decision(
                Decision.DENY, "INVALID_ARGUMENTS", request_id, trace_id, None
            )
        if set(invocation.arguments.keys()) != set(expected_arguments):
            return self._decision(
                Decision.DENY, "INVALID_ARGUMENTS", request_id, trace_id, None
            )

        if not isinstance(order, OrderSnapshot):
            return self._decision(
                Decision.DENY, "ORDER_CONTEXT_MISSING", request_id, trace_id, None
            )
        if not all(
            _valid_identifier(value)
            for value in (order.order_id, order.tenant_id, order.customer_id)
        ):
            return self._decision(
                Decision.DENY, "ORDER_CONTEXT_INVALID", request_id, trace_id, None
            )
        if (
            not isinstance(order.currency, str)
            or self._CURRENCY.fullmatch(order.currency) is None
            or isinstance(order.refundable_minor, bool)
            or not isinstance(order.refundable_minor, int)
            or order.refundable_minor < 0
            or not isinstance(order.refund_eligible, bool)
        ):
            return self._decision(
                Decision.DENY, "ORDER_CONTEXT_INVALID", request_id, trace_id, None
            )

        order_id = invocation.arguments.get("order_id")
        if not _valid_identifier(order_id) or order_id != order.order_id:
            return self._decision(
                Decision.DENY, "RESOURCE_CONTEXT_MISMATCH", request_id, trace_id, None
            )
        if order.tenant_id != principal.tenant_id:
            return self._decision(
                Decision.DENY, "RESOURCE_TENANT_MISMATCH", request_id, trace_id, None
            )
        if order.customer_id != principal.customer_id:
            return self._decision(
                Decision.DENY, "RESOURCE_OWNER_MISMATCH", request_id, trace_id, None
            )

        action_digest = _action_digest(principal, invocation, order)
        if invocation.tool_name in {"get_order", "check_refund_eligibility"}:
            return self._decision(
                Decision.ALLOW, "OWNED_ORDER_READ_ALLOWED", request_id, trace_id, action_digest
            )

        amount_minor = invocation.arguments.get("amount_minor")
        currency = invocation.arguments.get("currency")
        reason = invocation.arguments.get("reason")
        idempotency_key = invocation.arguments.get("idempotency_key")

        if (
            isinstance(amount_minor, bool)
            or not isinstance(amount_minor, int)
            or amount_minor <= 0
            or not isinstance(currency, str)
            or self._CURRENCY.fullmatch(currency) is None
            or not isinstance(reason, str)
            or not reason.strip()
            or len(reason) > self.config.max_reason_chars
            or not _valid_identifier(idempotency_key, min_length=8, max_length=128)
        ):
            return self._decision(
                Decision.DENY, "INVALID_REFUND_REQUEST", request_id, trace_id, action_digest
            )
        if currency != order.currency:
            return self._decision(
                Decision.DENY, "REFUND_CURRENCY_MISMATCH", request_id, trace_id, action_digest
            )
        if order.refund_eligible is not True:
            return self._decision(
                Decision.DENY, "ORDER_NOT_REFUND_ELIGIBLE", request_id, trace_id, action_digest
            )
        if amount_minor > order.refundable_minor:
            return self._decision(
                Decision.DENY, "REFUND_EXCEEDS_REMAINING_AMOUNT", request_id, trace_id, action_digest
            )
        if amount_minor > self.config.self_service_refund_limit_minor:
            return self._decision(
                Decision.ESCALATE,
                "SELF_SERVICE_LIMIT_EXCEEDED",
                request_id,
                trace_id,
                action_digest,
            )
        return self._decision(
            Decision.ALLOW, "SELF_SERVICE_REFUND_ALLOWED", request_id, trace_id, action_digest
        )

    def _decision(
        self,
        decision: Decision,
        reason_code: str,
        request_id: str,
        trace_id: str,
        action_digest: str | None,
    ) -> PolicyDecision:
        return PolicyDecision(
            decision=decision,
            reason_code=reason_code,
            policy_id=self.config.policy_id,
            policy_version=self.config.version,
            request_id=request_id,
            trace_id=trace_id,
            action_digest=action_digest,
        )


def _valid_identifier(
    value: object, *, min_length: int = 1, max_length: int = 128
) -> bool:
    return (
        isinstance(value, str)
        and min_length <= len(value) <= max_length
        and value.strip() == value
        and bool(value)
    )


def _safe_identifier(value: object) -> str:
    return value if _valid_identifier(value) else "unknown"


def _action_digest(
    principal: Principal, invocation: ToolInvocation, order: OrderSnapshot
) -> str:
    """Stable digest for correlating an exact normalized action, without secrets."""
    canonical = {
        "agent_id": invocation.agent_id,
        "arguments": dict(invocation.arguments),
        "customer_id": principal.customer_id,
        "order_id": order.order_id,
        "principal_id": principal.subject_id,
        "tenant_id": principal.tenant_id,
        "tool_name": invocation.tool_name,
    }
    encoded = json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
