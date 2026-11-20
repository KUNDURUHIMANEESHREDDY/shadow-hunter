"""Transactional DynamoDB persistence adapter for Shadow Hunter.

The table is provisioned separately by infra/data/dynamodb.yaml. Money-related
state changes use TransactWriteItems with conditional writes so the order
balance, refund state, approval capability, and audit event change atomically.
This adapter maintains the SQLiteStore method contract.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import uuid
from datetime import timedelta
from decimal import Decimal
from typing import Any, Mapping

from .policy import OrderSnapshot, Principal
from .store import IdempotencyConflict, StoreError, iso_now, utc_now


class DynamoDBStore:
    """Single-table transactional store for production AWS deployments."""

    _STATS_KEY = {"PK": "STATS", "SK": "COUNTERS"}

    def __init__(
        self,
        table_name: str,
        *,
        region: str | None = None,
        endpoint_url: str | None = None,
        table: Any | None = None,
        client: Any | None = None,
    ) -> None:
        if not isinstance(table_name, str) or not table_name.strip():
            raise StoreError("A DynamoDB table name is required")
        try:
            from boto3.dynamodb.types import TypeSerializer
        except ImportError as exc:
            raise StoreError(
                "DynamoDB storage requires boto3; install the aws optional dependency"
            ) from exc

        self.table_name = table_name
        self._serializer = TypeSerializer()
        self._resource = None
        if table is None:
            try:
                import boto3
            except ImportError as exc:
                raise StoreError(
                    "DynamoDB storage requires boto3; install the aws optional dependency"
                ) from exc
            self._resource = boto3.resource(
                "dynamodb",
                region_name=region,
                endpoint_url=endpoint_url,
            )
            table = self._resource.Table(table_name)
        self._table = table
        self._client = client or table.meta.client

    @classmethod
    def from_environment(cls) -> "DynamoDBStore":
        table_name = os.environ.get("SHADOW_HUNTER_DYNAMODB_TABLE", "").strip()
        if not table_name:
            raise StoreError(
                "SHADOW_HUNTER_DYNAMODB_TABLE is required when "
                "SHADOW_HUNTER_STORE_BACKEND=dynamodb"
            )
        return cls(
            table_name,
            region=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"),
            endpoint_url=os.environ.get("SHADOW_HUNTER_DYNAMODB_ENDPOINT") or None,
        )

    def _serialize(self, item: Mapping[str, Any]) -> dict[str, Any]:
        return {name: self._serializer.serialize(value) for name, value in item.items()}

    def _tx_put(self, item: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "Put": {
                "TableName": self.table_name,
                "Item": self._serialize(item),
                "ConditionExpression": "attribute_not_exists(PK)",
            }
        }

    def _tx_update(
        self,
        key: Mapping[str, Any],
        *,
        update_expression: str,
        condition_expression: str | None = None,
        names: Mapping[str, str] | None = None,
        values: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        request: dict[str, Any] = {
            "TableName": self.table_name,
            "Key": self._serialize(key),
            "UpdateExpression": update_expression,
        }
        if condition_expression:
            request["ConditionExpression"] = condition_expression
        if names:
            request["ExpressionAttributeNames"] = dict(names)
        if values:
            request["ExpressionAttributeValues"] = self._serialize(values)
        return {"Update": request}

    def _stats_tx(self, deltas: Mapping[str, int]) -> dict[str, Any] | None:
        nonzero = {name: value for name, value in deltas.items() if value}
        if not nonzero:
            return None
        names = {f"#{name}": name for name in nonzero}
        values = {f":{name}": value for name, value in nonzero.items()}
        expression = "ADD " + ", ".join(f"#{name} :{name}" for name in nonzero)
        return self._tx_update(
            self._STATS_KEY,
            update_expression=expression,
            names=names,
            values=values,
        )

    @staticmethod
    def _public(item: Mapping[str, Any] | None) -> dict[str, Any] | None:
        if item is None:
            return None

        def normalize(value: Any) -> Any:
            if isinstance(value, Decimal):
                return int(value) if value == value.to_integral_value() else float(value)
            if isinstance(value, dict):
                return {key: normalize(child) for key, child in value.items()}
            if isinstance(value, list):
                return [normalize(child) for child in value]
            return value

        hidden = {
            "PK", "SK", "GSI1PK", "GSI1SK", "entity_type",
            "token_hash", "consumed_token_hash",
        }
        return {
            key: normalize(value)
            for key, value in item.items()
            if key not in hidden
        }

    def _get_item(self, pk: str, sk: str = "META") -> dict[str, Any] | None:
        response = self._table.get_item(
            Key={"PK": pk, "SK": sk},
            ConsistentRead=True,
        )
        item = response.get("Item")
        return dict(item) if isinstance(item, Mapping) else None

    def _audit_item(
        self,
        *,
        event_type: str,
        trace_id: str,
        request_id: str,
        decision: str | None = None,
        reason_code: str | None = None,
        actor_id: str | None = None,
        tenant_id: str | None = None,
        resource_id: str | None = None,
        action_digest: str | None = None,
        policy_id: str | None = None,
        policy_version: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        created_at = iso_now()
        event_id = str(uuid.uuid4())
        return {
            "PK": f"TRACE#{trace_id}",
            "SK": f"EVENT#{created_at}#{event_id}",
            "GSI1PK": "AUDIT",
            "GSI1SK": f"{created_at}#{event_id}",
            "entity_type": "AUDIT",
            "event_id": event_id,
            "trace_id": trace_id,
            "request_id": request_id,
            "event_type": event_type,
            "decision": decision,
            "reason_code": reason_code,
            "actor_id": actor_id,
            "tenant_id": tenant_id,
            "resource_id": resource_id,
            "action_digest": action_digest,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "details": details or {},
            "created_at": created_at,
        }

    def add_order(
        self,
        *,
        order_id: str,
        tenant_id: str,
        customer_id: str,
        currency: str,
        refundable_minor: int,
        refund_eligible: bool = True,
    ) -> None:
        self._table.put_item(
            Item={
                "PK": f"ORDER#{order_id}",
                "SK": "META",
                "entity_type": "ORDER",
                "order_id": order_id,
                "tenant_id": tenant_id,
                "customer_id": customer_id,
                "currency": currency,
                "refundable_minor": refundable_minor,
                "refund_eligible": refund_eligible,
                "updated_at": iso_now(),
            }
        )

    def get_order(self, order_id: str) -> OrderSnapshot | None:
        row = self._get_item(f"ORDER#{order_id}")
        if row is None:
            return None
        return OrderSnapshot(
            order_id=row["order_id"],
            tenant_id=row["tenant_id"],
            customer_id=row["customer_id"],
            currency=row["currency"],
            refundable_minor=int(row["refundable_minor"]),
            refund_eligible=bool(row["refund_eligible"]),
        )

    def create_refund_request(
        self,
        *,
        principal: Principal,
        order: OrderSnapshot,
        amount_minor: int,
        currency: str,
        reason: str,
        idempotency_key: str,
        action_digest: str,
        policy_id: str,
        policy_version: str,
        policy_decision: str,
        policy_reason_code: str,
    ) -> dict[str, Any]:
        refund_request_id = str(uuid.uuid4())
        created_at = iso_now()
        idempotency_hash = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
        idempotency_item = {
            "PK": f"IDEMP#{principal.tenant_id}",
            "SK": f"KEY#{idempotency_hash}",
            "entity_type": "IDEMPOTENCY",
            "refund_request_id": refund_request_id,
            "action_digest": action_digest,
            "principal_id": principal.subject_id,
        }
        refund_item = {
            "PK": f"REFUND#{refund_request_id}",
            "SK": "META",
            "entity_type": "REFUND",
            "refund_request_id": refund_request_id,
            "tenant_id": principal.tenant_id,
            "customer_id": principal.customer_id,
            "principal_id": principal.subject_id,
            "order_id": order.order_id,
            "amount_minor": amount_minor,
            "currency": currency,
            "reason": reason,
            "idempotency_key": idempotency_key,
            "action_digest": action_digest,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "policy_decision": policy_decision,
            "policy_reason_code": policy_reason_code,
            "status": "PENDING_APPROVAL",
            "created_at": created_at,
        }
        actions = [
            self._tx_put(idempotency_item),
            self._tx_put(refund_item),
            self._stats_tx({"refund_requests": 1}),
        ]
        try:
            self._client.transact_write_items(
                TransactItems=[action for action in actions if action is not None]
            )
        except Exception as exc:
            existing = self._get_item(
                f"IDEMP#{principal.tenant_id}",
                f"KEY#{idempotency_hash}",
            )
            if existing is not None:
                if (
                    existing.get("action_digest") != action_digest
                    or existing.get("principal_id") != principal.subject_id
                ):
                    raise IdempotencyConflict(
                        "Idempotency key already belongs to a different action"
                    ) from exc
                result = self.get_refund_request(existing["refund_request_id"])
                if result is not None:
                    return result
            raise StoreError("Could not persist refund request transaction") from exc
        return self.get_refund_request(refund_request_id) or self._public(refund_item) or {}

    def create_approval(
        self,
        refund_request_id: str,
        ttl_seconds: int,
        *,
        trace_id: str | None = None,
        request_id: str | None = None,
    ) -> str:
        refund = self.get_refund_request(refund_request_id)
        if refund is None or refund.get("status") != "PENDING_APPROVAL":
            raise StoreError("Refund request is not awaiting approval")

        pointer_key = {"PK": f"REFUND#{refund_request_id}", "SK": "APPROVAL"}
        pointer = self._get_item(pointer_key["PK"], pointer_key["SK"])
        if pointer is not None:
            return str(pointer["approval_id"])

        now = utc_now()
        approval_id = str(uuid.uuid4())
        expires_at = (now + timedelta(seconds=ttl_seconds)).isoformat(timespec="microseconds")
        actual_trace_id = trace_id or refund_request_id
        actual_request_id = request_id or refund_request_id
        created_at = iso_now()
        approval_item = {
            "PK": f"APPROVAL#{approval_id}",
            "SK": "META",
            "GSI1PK": "APPROVALS",
            "GSI1SK": f"{created_at}#{approval_id}",
            "entity_type": "APPROVAL",
            "approval_id": approval_id,
            "refund_request_id": refund_request_id,
            "trace_id": actual_trace_id,
            "request_id": actual_request_id,
            "tenant_id": refund["tenant_id"],
            "principal_id": refund["principal_id"],
            "action_digest": refund["action_digest"],
            "policy_id": refund["policy_id"],
            "policy_version": refund["policy_version"],
            "expires_at": expires_at,
            "status": "PENDING",
            "created_at": created_at,
            "order_id": refund["order_id"],
            "amount_minor": refund["amount_minor"],
            "currency": refund["currency"],
            "reason": refund["reason"],
            "policy_decision": refund["policy_decision"],
            "policy_reason_code": refund["policy_reason_code"],
        }
        pointer_item = {
            **pointer_key,
            "entity_type": "REFUND_APPROVAL_POINTER",
            "approval_id": approval_id,
            "trace_id": actual_trace_id,
            "request_id": actual_request_id,
        }
        event = self._audit_item(
            event_type="APPROVAL_REQUESTED",
            trace_id=actual_trace_id,
            request_id=actual_request_id,
            actor_id=refund["principal_id"],
            tenant_id=refund["tenant_id"],
            resource_id=refund["order_id"],
            action_digest=refund["action_digest"],
            policy_id=refund["policy_id"],
            policy_version=refund["policy_version"],
            details={
                "approval_id": approval_id,
                "refund_request_id": refund_request_id,
                "expires_at": expires_at,
            },
        )
        actions = [
            self._tx_put(approval_item),
            self._tx_put(pointer_item),
            self._tx_put(event),
            self._stats_tx({"pending_approvals": 1, "audit_events": 1}),
        ]
        try:
            self._client.transact_write_items(
                TransactItems=[action for action in actions if action is not None]
            )
        except Exception as exc:
            existing = self._get_item(pointer_key["PK"], pointer_key["SK"])
            if existing is not None:
                return str(existing["approval_id"])
            raise StoreError("Could not create approval transaction") from exc
        return approval_id

    def _mark_expired(self, approval: Mapping[str, Any]) -> None:
        try:
            actions = [
                self._tx_update(
                    {"PK": approval["PK"], "SK": approval["SK"]},
                    update_expression="SET #status = :expired",
                    condition_expression="#status = :pending AND expires_at <= :now",
                    names={"#status": "status"},
                    values={
                        ":expired": "EXPIRED",
                        ":pending": "PENDING",
                        ":now": iso_now(),
                    },
                ),
                self._stats_tx({"pending_approvals": -1}),
            ]
            self._client.transact_write_items(
                TransactItems=[action for action in actions if action is not None]
            )
        except Exception:
            # A concurrent approver/rejector may already have moved the state.
            pass

    def approve(self, approval_id: str, approver_id: str) -> str:
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        approval = self._get_item(f"APPROVAL#{approval_id}")
        if approval is None:
            raise StoreError("Approval not found")
        if approval.get("status") != "PENDING":
            raise StoreError("Approval is not pending")
        if approval.get("expires_at", "") <= iso_now():
            self._mark_expired(approval)
            raise StoreError("Approval has expired")

        now = iso_now()
        event = self._audit_item(
            event_type="APPROVAL_GRANTED",
            trace_id=approval.get("trace_id") or approval["refund_request_id"],
            request_id=approval.get("request_id") or approval["refund_request_id"],
            actor_id=approver_id,
            tenant_id=approval["tenant_id"],
            resource_id=approval["refund_request_id"],
            action_digest=approval["action_digest"],
            policy_id=approval["policy_id"],
            policy_version=approval["policy_version"],
            details={"approval_id": approval_id, "token_issued": True},
        )
        actions = [
            self._tx_update(
                {"PK": approval["PK"], "SK": approval["SK"]},
                update_expression=(
                    "SET #status = :approved, approver_id = :approver, "
                    "approved_at = :now, token_hash = :token_hash"
                ),
                condition_expression="#status = :pending AND expires_at > :now",
                names={"#status": "status"},
                values={
                    ":approved": "APPROVED",
                    ":pending": "PENDING",
                    ":approver": approver_id,
                    ":now": now,
                    ":token_hash": token_hash,
                },
            ),
            self._tx_put(event),
            self._stats_tx(
                {"pending_approvals": -1, "approved_approvals": 1, "audit_events": 1}
            ),
        ]
        try:
            self._client.transact_write_items(
                TransactItems=[action for action in actions if action is not None]
            )
        except Exception as exc:
            latest = self._get_item(f"APPROVAL#{approval_id}")
            if latest is not None and latest.get("status") == "PENDING":
                if latest.get("expires_at", "") <= iso_now():
                    self._mark_expired(latest)
                    raise StoreError("Approval has expired") from exc
            raise StoreError("Approval is no longer pending or has expired") from exc
        return raw_token

    def reject(self, approval_id: str, approver_id: str, reason: str) -> None:
        approval = self._get_item(f"APPROVAL#{approval_id}")
        if approval is None:
            raise StoreError("Approval not found")
        if approval.get("status") != "PENDING":
            raise StoreError("Approval is not pending")
        if approval.get("expires_at", "") <= iso_now():
            self._mark_expired(approval)
            raise StoreError("Approval has expired")

        refund_request_id = approval["refund_request_id"]
        now = iso_now()
        event = self._audit_item(
            event_type="APPROVAL_REJECTED",
            decision="DENY",
            reason_code="HUMAN_REJECTED",
            trace_id=approval.get("trace_id") or refund_request_id,
            request_id=approval.get("request_id") or refund_request_id,
            actor_id=approver_id,
            tenant_id=approval["tenant_id"],
            resource_id=refund_request_id,
            action_digest=approval["action_digest"],
            policy_id=approval["policy_id"],
            policy_version=approval["policy_version"],
            details={"approval_id": approval_id, "reason": reason[:300]},
        )
        actions = [
            self._tx_update(
                {"PK": approval["PK"], "SK": approval["SK"]},
                update_expression="SET #status = :rejected, approver_id = :approver",
                condition_expression="#status = :pending AND expires_at > :now",
                names={"#status": "status"},
                values={
                    ":rejected": "REJECTED",
                    ":pending": "PENDING",
                    ":approver": approver_id,
                    ":now": now,
                },
            ),
            self._tx_update(
                {"PK": f"REFUND#{refund_request_id}", "SK": "META"},
                update_expression="SET #status = :rejected",
                condition_expression="#status = :pending_approval",
                names={"#status": "status"},
                values={
                    ":rejected": "REJECTED",
                    ":pending_approval": "PENDING_APPROVAL",
                },
            ),
            self._tx_put(event),
            self._stats_tx({"pending_approvals": -1, "audit_events": 1}),
        ]
        try:
            self._client.transact_write_items(
                TransactItems=[action for action in actions if action is not None]
            )
        except Exception as exc:
            latest = self._get_item(f"APPROVAL#{approval_id}")
            if latest is not None and latest.get("status") == "PENDING":
                if latest.get("expires_at", "") <= iso_now():
                    self._mark_expired(latest)
                    raise StoreError("Approval has expired") from exc
            raise StoreError("Approval is no longer pending or has expired") from exc

    def _approval_for_refund(self, refund_request_id: str) -> dict[str, Any] | None:
        pointer = self._get_item(f"REFUND#{refund_request_id}", "APPROVAL")
        if pointer is None:
            return None
        return self._get_item(f"APPROVAL#{pointer['approval_id']}")

    @staticmethod
    def _replay_result(
        refund: Mapping[str, Any] | None,
        approval: Mapping[str, Any] | None,
        *,
        token_hash: str,
        operator_id: str,
        refund_request_id: str,
    ) -> dict[str, Any] | None:
        if (
            refund is not None
            and approval is not None
            and refund.get("status") == "EXECUTED"
            and refund.get("executed_by") == operator_id
            and approval.get("status") == "CONSUMED"
            and secrets.compare_digest(
                str(approval.get("consumed_token_hash") or ""),
                token_hash,
            )
        ):
            return {
                "refund_request_id": refund_request_id,
                "status": "EXECUTED",
                "executed_at": refund.get("executed_at"),
                "executed_by": refund.get("executed_by"),
                "idempotent_replay": True,
            }
        return None

    def execute_refund(
        self,
        *,
        refund_request_id: str,
        approval_token: str,
        operator_id: str,
        policy_id: str,
        policy_version: str,
    ) -> dict[str, Any]:
        if not isinstance(approval_token, str) or not approval_token:
            raise StoreError("A valid approval token is required")
        token_hash = hashlib.sha256(approval_token.encode("utf-8")).hexdigest()
        refund = self.get_refund_request(refund_request_id)
        if refund is None:
            raise StoreError("Refund request not found")
        approval = self._approval_for_refund(refund_request_id)
        if approval is None:
            raise StoreError("Approval record not found")

        replay = self._replay_result(
            refund,
            approval,
            token_hash=token_hash,
            operator_id=operator_id,
            refund_request_id=refund_request_id,
        )
        if replay is not None:
            return replay

        if approval.get("status") != "APPROVED":
            raise StoreError("Refund execution requires an unused approved capability")
        if approval.get("policy_id") != policy_id or approval.get("policy_version") != policy_version:
            raise StoreError("Policy changed after approval; a new approval is required")
        if approval.get("expires_at", "") <= iso_now():
            raise StoreError("Approval has expired")
        if not secrets.compare_digest(str(approval.get("token_hash") or ""), token_hash):
            raise StoreError("Approval token is invalid")
        if (
            approval.get("action_digest") != refund.get("action_digest")
            or approval.get("principal_id") != refund.get("principal_id")
            or approval.get("policy_version") != refund.get("policy_version")
        ):
            raise StoreError("Approval does not match the original refund action")
        if refund.get("status") != "PENDING_APPROVAL":
            raise StoreError("Refund request is not executable")

        order = self._get_item(f"ORDER#{refund['order_id']}")
        if order is None:
            raise StoreError("Order no longer exists")
        if (
            order.get("tenant_id") != refund.get("tenant_id")
            or order.get("customer_id") != refund.get("customer_id")
            or order.get("currency") != refund.get("currency")
            or order.get("refund_eligible") is not True
        ):
            raise StoreError("Order authorization or eligibility changed")
        amount = int(refund["amount_minor"])
        if int(order["refundable_minor"]) < amount:
            raise StoreError("Remaining refundable amount changed")

        now = iso_now()
        event = self._audit_item(
            event_type="REFUND_EXECUTED",
            decision="ALLOW",
            reason_code="APPROVED_REFUND_EXECUTED",
            trace_id=approval.get("trace_id") or refund_request_id,
            request_id=approval.get("request_id") or refund_request_id,
            actor_id=operator_id,
            tenant_id=refund["tenant_id"],
            resource_id=refund["order_id"],
            action_digest=refund["action_digest"],
            policy_id=refund["policy_id"],
            policy_version=refund["policy_version"],
            details={
                "refund_request_id": refund_request_id,
                "amount_minor": amount,
                "currency": refund["currency"],
                "ledger": "dynamodb_demo",
            },
        )
        actions = [
            self._tx_update(
                {"PK": f"ORDER#{refund['order_id']}", "SK": "META"},
                update_expression=(
                    "SET refundable_minor = refundable_minor - :amount, updated_at = :now"
                ),
                condition_expression=(
                    "refundable_minor >= :amount AND tenant_id = :tenant "
                    "AND customer_id = :customer AND currency = :currency "
                    "AND refund_eligible = :eligible"
                ),
                values={
                    ":amount": amount,
                    ":now": now,
                    ":tenant": refund["tenant_id"],
                    ":customer": refund["customer_id"],
                    ":currency": refund["currency"],
                    ":eligible": True,
                },
            ),
            self._tx_update(
                {"PK": f"REFUND#{refund_request_id}", "SK": "META"},
                update_expression=(
                    "SET #status = :executed, executed_at = :now, executed_by = :operator"
                ),
                condition_expression="#status = :pending",
                names={"#status": "status"},
                values={
                    ":executed": "EXECUTED",
                    ":pending": "PENDING_APPROVAL",
                    ":now": now,
                    ":operator": operator_id,
                },
            ),
            self._tx_update(
                {"PK": approval["PK"], "SK": approval["SK"]},
                update_expression=(
                    "SET #status = :consumed, consumed_token_hash = :token, "
                    "consumed_at = :now REMOVE token_hash"
                ),
                condition_expression=(
                    "#status = :approved AND token_hash = :token "
                    "AND expires_at > :now AND action_digest = :digest "
                    "AND principal_id = :principal AND policy_version = :stored_policy"
                ),
                names={"#status": "status"},
                values={
                    ":consumed": "CONSUMED",
                    ":approved": "APPROVED",
                    ":token": token_hash,
                    ":now": now,
                    ":digest": refund["action_digest"],
                    ":principal": refund["principal_id"],
                    ":stored_policy": refund["policy_version"],
                },
            ),
            self._tx_put(event),
            self._stats_tx(
                {"approved_approvals": -1, "executed_refunds": 1, "audit_events": 1}
            ),
        ]
        try:
            self._client.transact_write_items(
                TransactItems=[action for action in actions if action is not None]
            )
        except Exception as exc:
            latest_refund = self.get_refund_request(refund_request_id)
            latest_approval = self._approval_for_refund(refund_request_id)
            replay = self._replay_result(
                latest_refund,
                latest_approval,
                token_hash=token_hash,
                operator_id=operator_id,
                refund_request_id=refund_request_id,
            )
            if replay is not None:
                return replay
            raise StoreError(
                "Refund state or balance changed during execution; reload and reauthorize"
            ) from exc
        return {
            "refund_request_id": refund_request_id,
            "status": "EXECUTED",
            "executed_at": now,
            "executed_by": operator_id,
            "idempotent_replay": False,
            "ledger": "dynamodb_demo",
        }

    def append_audit(
        self,
        *,
        event_type: str,
        trace_id: str,
        request_id: str,
        decision: str | None = None,
        reason_code: str | None = None,
        actor_id: str | None = None,
        tenant_id: str | None = None,
        resource_id: str | None = None,
        action_digest: str | None = None,
        policy_id: str | None = None,
        policy_version: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        event = self._audit_item(
            event_type=event_type,
            trace_id=trace_id,
            request_id=request_id,
            decision=decision,
            reason_code=reason_code,
            actor_id=actor_id,
            tenant_id=tenant_id,
            resource_id=resource_id,
            action_digest=action_digest,
            policy_id=policy_id,
            policy_version=policy_version,
            details=details,
        )
        actions = [
            self._tx_put(event),
            self._stats_tx({"audit_events": 1}),
        ]
        try:
            self._client.transact_write_items(
                TransactItems=[action for action in actions if action is not None]
            )
        except Exception as exc:
            raise StoreError("Could not append audit event") from exc

    def list_audit(self, limit: int = 100) -> list[dict[str, Any]]:
        from boto3.dynamodb.conditions import Key

        response = self._table.query(
            IndexName="GSI1",
            KeyConditionExpression=Key("GSI1PK").eq("AUDIT"),
            ScanIndexForward=False,
            Limit=limit,
        )
        return [self._public(item) or {} for item in response.get("Items", [])]

    def list_approvals(self, limit: int = 100) -> list[dict[str, Any]]:
        from boto3.dynamodb.conditions import Key

        response = self._table.query(
            IndexName="GSI1",
            KeyConditionExpression=Key("GSI1PK").eq("APPROVALS"),
            ScanIndexForward=False,
            Limit=limit,
        )
        return [self._public(item) or {} for item in response.get("Items", [])]

    def overview(self) -> dict[str, int]:
        row = self._get_item(self._STATS_KEY["PK"], self._STATS_KEY["SK"]) or {}
        names = (
            "refund_requests",
            "pending_approvals",
            "approved_approvals",
            "executed_refunds",
            "audit_events",
        )
        return {name: int(row.get(name, 0)) for name in names}

    def get_refund_request(self, refund_request_id: str) -> dict[str, Any] | None:
        return self._public(self._get_item(f"REFUND#{refund_request_id}"))

    def get_refund_trace(self, refund_request_id: str) -> dict[str, str] | None:
        pointer = self._get_item(f"REFUND#{refund_request_id}", "APPROVAL")
        if pointer is None:
            return None
        return {
            "trace_id": pointer.get("trace_id") or refund_request_id,
            "request_id": pointer.get("request_id") or refund_request_id,
        }

    def get_trace_events(
        self,
        trace_id: str,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        from boto3.dynamodb.conditions import Key

        response = self._table.query(
            KeyConditionExpression=(
                Key("PK").eq(f"TRACE#{trace_id}") & Key("SK").begins_with("EVENT#")
            ),
            ScanIndexForward=True,
            Limit=limit,
        )
        return [self._public(item) or {} for item in response.get("Items", [])]
