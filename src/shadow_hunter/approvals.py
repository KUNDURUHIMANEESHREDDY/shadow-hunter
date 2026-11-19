"""Human approval workflow for sensitive refund execution."""
from __future__ import annotations

from .store import SQLiteStore, StoreError


class ApprovalService:
    """Coordinates parameter-bound approvals and one-time execution capabilities."""

    def __init__(self, store: SQLiteStore, *, ttl_seconds: int = 600) -> None:
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds < 30:
            raise ValueError("approval TTL must be at least 30 seconds")
        self.store = store
        self.ttl_seconds = ttl_seconds

    def request(
        self,
        refund_request_id: str,
        *,
        trace_id: str | None = None,
        request_id: str | None = None,
    ) -> str:
        return self.store.create_approval(
            refund_request_id,
            self.ttl_seconds,
            trace_id=trace_id,
            request_id=request_id,
        )

    def approve(self, approval_id: str, approver_id: str) -> str:
        if not approver_id or approver_id.strip() != approver_id:
            raise StoreError("Authenticated approver identity is required")
        return self.store.approve(approval_id, approver_id)

    def reject(self, approval_id: str, approver_id: str, reason: str) -> None:
        if not approver_id or approver_id.strip() != approver_id:
            raise StoreError("Authenticated approver identity is required")
        self.store.reject(approval_id, approver_id, reason)

    def execute(
        self,
        refund_request_id: str,
        approval_token: str,
        operator_id: str,
        *,
        policy_id: str,
        policy_version: str,
    ) -> dict:
        if not operator_id or operator_id.strip() != operator_id:
            raise StoreError("Authenticated operator identity is required")
        return self.store.execute_refund(
            refund_request_id=refund_request_id,
            approval_token=approval_token,
            operator_id=operator_id,
            policy_id=policy_id,
            policy_version=policy_version,
        )
