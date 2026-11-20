"""SQLite persistence for refund state, approvals, and correlated audit evidence.

SQLite is the local/demo adapter. It is not presented as a multi-AZ production
store; production deployment should replace it with a transactional AWS store
while preserving the repository contract.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from .policy import OrderSnapshot, Principal


class StoreError(RuntimeError):
    """A safe, expected persistence or state-transition failure."""


class IdempotencyConflict(StoreError):
    """An idempotency key was reused with different canonical parameters."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat(timespec="microseconds")


class SQLiteStore:
    """Transactional SQLite adapter.

    Each state transition uses BEGIN IMMEDIATE so concurrent callers cannot
    both consume one approval or debit the same refundable balance.
    """

    def __init__(self, database_path: str | Path) -> None:
        self.database_path = str(database_path)
        if self.database_path != ":memory:":
            Path(self.database_path).expanduser().resolve().parent.mkdir(
                parents=True, exist_ok=True
            )
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.database_path, timeout=15, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 15000")
        if self.database_path != ":memory:":
            conn.execute("PRAGMA journal_mode = WAL")
        return conn

    @contextmanager
    def _reader(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _initialize(self) -> None:
        with self._reader() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS orders (
                    order_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    customer_id TEXT NOT NULL,
                    currency TEXT NOT NULL CHECK(length(currency) = 3),
                    refundable_minor INTEGER NOT NULL CHECK(refundable_minor >= 0),
                    refund_eligible INTEGER NOT NULL CHECK(refund_eligible IN (0, 1)),
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS refund_requests (
                    refund_request_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    customer_id TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    order_id TEXT NOT NULL REFERENCES orders(order_id),
                    amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),
                    currency TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    action_digest TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    policy_decision TEXT NOT NULL CHECK(policy_decision IN ('ALLOW', 'ESCALATE')),
                    policy_reason_code TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('PENDING_APPROVAL', 'EXECUTED', 'REJECTED')),
                    created_at TEXT NOT NULL,
                    executed_at TEXT,
                    executed_by TEXT,
                    UNIQUE(tenant_id, idempotency_key)
                );

                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY,
                    refund_request_id TEXT NOT NULL UNIQUE REFERENCES refund_requests(refund_request_id),
                    trace_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    action_digest TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    token_hash TEXT,
                    consumed_token_hash TEXT,
                    status TEXT NOT NULL CHECK(status IN ('PENDING', 'APPROVED', 'REJECTED', 'CONSUMED', 'EXPIRED')),
                    approver_id TEXT,
                    created_at TEXT NOT NULL,
                    approved_at TEXT,
                    consumed_at TEXT
                );

                CREATE TABLE IF NOT EXISTS a2a_nonces (
                    nonce TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    expires_at_epoch INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_a2a_nonce_expiry
                    ON a2a_nonces(expires_at_epoch);

                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    trace_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    decision TEXT,
                    reason_code TEXT,
                    actor_id TEXT,
                    tenant_id TEXT,
                    resource_id TEXT,
                    action_digest TEXT,
                    policy_id TEXT,
                    policy_version TEXT,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_audit_trace
                    ON audit_events(trace_id, sequence);
                CREATE INDEX IF NOT EXISTS idx_audit_created
                    ON audit_events(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_approvals_status
                    ON approvals(status, expires_at);
                CREATE INDEX IF NOT EXISTS idx_refunds_tenant
                    ON refund_requests(tenant_id, created_at DESC);
                """
            )
            approval_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(approvals)")
            }
            if "trace_id" not in approval_columns:
                conn.execute(
                    "ALTER TABLE approvals ADD COLUMN trace_id TEXT NOT NULL DEFAULT ''"
                )
            if "request_id" not in approval_columns:
                conn.execute(
                    "ALTER TABLE approvals ADD COLUMN request_id TEXT NOT NULL DEFAULT ''"
                )

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
        with self._transaction() as conn:
            conn.execute(
                """
                INSERT INTO orders (
                    order_id, tenant_id, customer_id, currency,
                    refundable_minor, refund_eligible, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(order_id) DO UPDATE SET
                    tenant_id = excluded.tenant_id,
                    customer_id = excluded.customer_id,
                    currency = excluded.currency,
                    refundable_minor = excluded.refundable_minor,
                    refund_eligible = excluded.refund_eligible,
                    updated_at = excluded.updated_at
                """,
                (
                    order_id, tenant_id, customer_id, currency,
                    refundable_minor, int(refund_eligible), iso_now(),
                ),
            )

    def get_order(self, order_id: str) -> OrderSnapshot | None:
        with self._reader() as conn:
            row = conn.execute(
                "SELECT * FROM orders WHERE order_id = ?", (order_id,)
            ).fetchone()
        if row is None:
            return None
        return OrderSnapshot(
            order_id=row["order_id"],
            tenant_id=row["tenant_id"],
            customer_id=row["customer_id"],
            currency=row["currency"],
            refundable_minor=row["refundable_minor"],
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
        with self._transaction() as conn:
            existing = conn.execute(
                """
                SELECT * FROM refund_requests
                WHERE tenant_id = ? AND idempotency_key = ?
                """,
                (principal.tenant_id, idempotency_key),
            ).fetchone()
            if existing is not None:
                if (
                    existing["action_digest"] != action_digest
                    or existing["principal_id"] != principal.subject_id
                ):
                    raise IdempotencyConflict(
                        "Idempotency key already belongs to a different action"
                    )
                return dict(existing)

            refund_request_id = str(uuid.uuid4())
            conn.execute(
                """
                INSERT INTO refund_requests (
                    refund_request_id, tenant_id, customer_id, principal_id,
                    order_id, amount_minor, currency, reason, idempotency_key,
                    action_digest, policy_id, policy_version, policy_decision,
                    policy_reason_code, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING_APPROVAL', ?)
                """,
                (
                    refund_request_id, principal.tenant_id, principal.customer_id,
                    principal.subject_id, order.order_id, amount_minor, currency,
                    reason, idempotency_key, action_digest, policy_id, policy_version,
                    policy_decision, policy_reason_code, iso_now(),
                ),
            )
            created = conn.execute(
                "SELECT * FROM refund_requests WHERE refund_request_id = ?",
                (refund_request_id,),
            ).fetchone()
            return dict(created)

    def create_approval(
        self,
        refund_request_id: str,
        ttl_seconds: int,
        *,
        trace_id: str | None = None,
        request_id: str | None = None,
    ) -> str:
        with self._transaction() as conn:
            existing = conn.execute(
                "SELECT approval_id FROM approvals WHERE refund_request_id = ?",
                (refund_request_id,),
            ).fetchone()
            if existing is not None:
                return str(existing["approval_id"])

            refund = conn.execute(
                "SELECT * FROM refund_requests WHERE refund_request_id = ?",
                (refund_request_id,),
            ).fetchone()
            if refund is None or refund["status"] != "PENDING_APPROVAL":
                raise StoreError("Refund request is not awaiting approval")

            now = utc_now()
            approval_id = str(uuid.uuid4())
            expires_at = (now + timedelta(seconds=ttl_seconds)).isoformat(
                timespec="microseconds"
            )
            conn.execute(
                """
                INSERT INTO approvals (
                    approval_id, refund_request_id, trace_id, request_id,
                    tenant_id, principal_id, action_digest, policy_id, policy_version,
                    expires_at, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?)
                """,
                (
                    approval_id, refund_request_id, trace_id or refund_request_id,
                    request_id or refund_request_id, refund["tenant_id"],
                    refund["principal_id"], refund["action_digest"], refund["policy_id"],
                    refund["policy_version"], expires_at, iso_now(),
                ),
            )
            self._insert_audit(
                conn,
                event_type="APPROVAL_REQUESTED",
                trace_id=trace_id or refund_request_id,
                request_id=request_id or refund_request_id,
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
            return approval_id

    def approve(self, approval_id: str, approver_id: str) -> str:
        """Approve once and return a random capability token exactly once."""
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        expired = False
        with self._transaction() as conn:
            row = conn.execute(
                "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
            if row is None:
                raise StoreError("Approval not found")
            if row["status"] != "PENDING":
                raise StoreError("Approval is not pending")
            if row["expires_at"] <= iso_now():
                conn.execute(
                    "UPDATE approvals SET status = 'EXPIRED' WHERE approval_id = ?",
                    (approval_id,),
                )
                expired = True
            else:
                conn.execute(
                    """
                    UPDATE approvals SET
                        status = 'APPROVED', approver_id = ?, approved_at = ?, token_hash = ?
                    WHERE approval_id = ? AND status = 'PENDING'
                    """,
                    (approver_id, iso_now(), token_hash, approval_id),
                )
                self._insert_audit(
                    conn,
                    event_type="APPROVAL_GRANTED",
                    trace_id=row["trace_id"] or row["refund_request_id"],
                    request_id=row["request_id"] or row["refund_request_id"],
                    actor_id=approver_id,
                    tenant_id=row["tenant_id"],
                    resource_id=row["refund_request_id"],
                    action_digest=row["action_digest"],
                    policy_id=row["policy_id"],
                    policy_version=row["policy_version"],
                    details={"approval_id": approval_id, "token_issued": True},
                )
        if expired:
            raise StoreError("Approval has expired")
        return raw_token

    def reject(self, approval_id: str, approver_id: str, reason: str) -> None:
        with self._transaction() as conn:
            row = conn.execute(
                "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
            if row is None:
                raise StoreError("Approval not found")
            if row["status"] != "PENDING":
                raise StoreError("Approval is not pending")
            if row["expires_at"] <= iso_now():
                conn.execute(
                    "UPDATE approvals SET status = 'EXPIRED' WHERE approval_id = ?",
                    (approval_id,),
                )
                expired = True
            else:
                expired = False
                conn.execute(
                    "UPDATE approvals SET status = 'REJECTED', approver_id = ? WHERE approval_id = ?",
                    (approver_id, approval_id),
                )
                conn.execute(
                    "UPDATE refund_requests SET status = 'REJECTED' WHERE refund_request_id = ?",
                    (row["refund_request_id"],),
                )
                self._insert_audit(
                    conn,
                    event_type="APPROVAL_REJECTED",
                    decision="DENY",
                    reason_code="HUMAN_REJECTED",
                    trace_id=row["trace_id"] or row["refund_request_id"],
                    request_id=row["request_id"] or row["refund_request_id"],
                    actor_id=approver_id,
                    tenant_id=row["tenant_id"],
                    resource_id=row["refund_request_id"],
                    action_digest=row["action_digest"],
                    policy_id=row["policy_id"],
                    policy_version=row["policy_version"],
                    details={"approval_id": approval_id, "reason": reason[:300]},
                )
        if expired:
            raise StoreError("Approval has expired")

    def execute_refund(
        self,
        *,
        refund_request_id: str,
        approval_token: str,
        operator_id: str,
        policy_id: str,
        policy_version: str,
    ) -> dict[str, Any]:
        """Consume an approved token and apply the local demo ledger atomically.

        Replaying the same token by the original executor returns the prior
        result without a second debit. No payment-provider call is made here.
        """
        if not isinstance(approval_token, str) or not approval_token:
            raise StoreError("A valid approval token is required")
        token_hash = hashlib.sha256(approval_token.encode("utf-8")).hexdigest()

        with self._transaction() as conn:
            refund = conn.execute(
                "SELECT * FROM refund_requests WHERE refund_request_id = ?",
                (refund_request_id,),
            ).fetchone()
            if refund is None:
                raise StoreError("Refund request not found")
            approval = conn.execute(
                "SELECT * FROM approvals WHERE refund_request_id = ?",
                (refund_request_id,),
            ).fetchone()
            if approval is None:
                raise StoreError("Approval record not found")

            if (
                refund["status"] == "EXECUTED"
                and refund["executed_by"] == operator_id
                and approval["status"] == "CONSUMED"
                and secrets.compare_digest(
                    approval["consumed_token_hash"] or "", token_hash
                )
            ):
                return {
                    "refund_request_id": refund_request_id,
                    "status": "EXECUTED",
                    "executed_at": refund["executed_at"],
                    "executed_by": refund["executed_by"],
                    "idempotent_replay": True,
                }

            if approval["status"] != "APPROVED":
                raise StoreError("Refund execution requires an unused approved capability")
            if (
                approval["policy_id"] != policy_id
                or approval["policy_version"] != policy_version
            ):
                raise StoreError("Policy changed after approval; a new approval is required")
            if approval["expires_at"] <= iso_now():
                raise StoreError("Approval has expired")
            if not secrets.compare_digest(approval["token_hash"] or "", token_hash):
                raise StoreError("Approval token is invalid")
            if (
                approval["action_digest"] != refund["action_digest"]
                or approval["principal_id"] != refund["principal_id"]
                or approval["policy_version"] != refund["policy_version"]
            ):
                raise StoreError("Approval does not match the original refund action")
            if refund["status"] != "PENDING_APPROVAL":
                raise StoreError("Refund request is not executable")

            order = conn.execute(
                "SELECT * FROM orders WHERE order_id = ?", (refund["order_id"],)
            ).fetchone()
            if order is None:
                raise StoreError("Order no longer exists")
            if (
                order["tenant_id"] != refund["tenant_id"]
                or order["customer_id"] != refund["customer_id"]
                or order["currency"] != refund["currency"]
                or order["refund_eligible"] != 1
            ):
                raise StoreError("Order authorization or eligibility changed")
            if order["refundable_minor"] < refund["amount_minor"]:
                raise StoreError("Remaining refundable amount changed")

            updated = conn.execute(
                """
                UPDATE orders
                SET refundable_minor = refundable_minor - ?, updated_at = ?
                WHERE order_id = ? AND refundable_minor >= ?
                """,
                (
                    refund["amount_minor"], iso_now(), refund["order_id"],
                    refund["amount_minor"],
                ),
            )
            if updated.rowcount != 1:
                raise StoreError("Refund balance changed during execution")

            executed_at = iso_now()
            conn.execute(
                """
                UPDATE refund_requests
                SET status = 'EXECUTED', executed_at = ?, executed_by = ?
                WHERE refund_request_id = ? AND status = 'PENDING_APPROVAL'
                """,
                (executed_at, operator_id, refund_request_id),
            )
            conn.execute(
                """
                UPDATE approvals
                SET status = 'CONSUMED', consumed_token_hash = token_hash,
                    consumed_at = ?, token_hash = NULL
                WHERE approval_id = ? AND status = 'APPROVED'
                """,
                (executed_at, approval["approval_id"]),
            )
            self._insert_audit(
                conn,
                event_type="REFUND_EXECUTED",
                decision="ALLOW",
                reason_code="APPROVED_REFUND_EXECUTED",
                trace_id=approval["trace_id"] or refund_request_id,
                request_id=approval["request_id"] or refund_request_id,
                actor_id=operator_id,
                tenant_id=refund["tenant_id"],
                resource_id=refund["order_id"],
                action_digest=refund["action_digest"],
                policy_id=refund["policy_id"],
                policy_version=refund["policy_version"],
                details={
                    "refund_request_id": refund_request_id,
                    "amount_minor": refund["amount_minor"],
                    "currency": refund["currency"],
                    "ledger": "local_demo",
                },
            )
            return {
                "refund_request_id": refund_request_id,
                "status": "EXECUTED",
                "executed_at": executed_at,
                "executed_by": operator_id,
                "idempotent_replay": False,
                "ledger": "local_demo",
            }

    def claim_a2a_nonce(
        self,
        *,
        nonce: str,
        agent_id: str,
        message_id: str,
        expires_at_epoch: int,
    ) -> bool:
        """Atomically claim a signed A2A nonce once, shared across API workers."""
        if (
            not isinstance(nonce, str)
            or not nonce
            or len(nonce) > 128
            or not isinstance(agent_id, str)
            or not agent_id
            or len(agent_id) > 128
            or not isinstance(message_id, str)
            or not message_id
            or len(message_id) > 128
            or isinstance(expires_at_epoch, bool)
            or not isinstance(expires_at_epoch, int)
        ):
            raise ValueError("Invalid A2A replay-guard record")
        now_epoch = int(utc_now().timestamp())
        if expires_at_epoch <= now_epoch:
            return False
        with self._transaction() as conn:
            conn.execute(
                "DELETE FROM a2a_nonces WHERE expires_at_epoch < ?",
                (now_epoch,),
            )
            try:
                conn.execute(
                    """
                    INSERT INTO a2a_nonces (
                        nonce, agent_id, message_id, expires_at_epoch
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (nonce, agent_id, message_id, expires_at_epoch),
                )
            except sqlite3.IntegrityError:
                return False
        return True

    def latest_agent_evaluation(self) -> dict[str, Any]:
        """Return the latest redacted aggregate and case outcomes, if present."""
        with self._reader() as conn:
            row = conn.execute(
                """
                SELECT * FROM audit_events
                WHERE event_type = 'AGENT_EVALUATION_RUN'
                ORDER BY sequence DESC LIMIT 1
                """
            ).fetchone()
        if row is None:
            return {"run": None, "results": []}
        run = dict(row)
        run["details"] = json.loads(run.pop("details_json"))
        results = self.list_agent_evaluation_results(run["trace_id"])
        return {"run": run, "results": results}

    def list_agent_evaluation_results(
        self, run_id: str
    ) -> list[dict[str, Any]]:
        with self._reader() as conn:
            rows = conn.execute(
                """
                SELECT * FROM audit_events
                WHERE event_type = 'AGENT_EVALUATION_RESULT'
                  AND trace_id = ?
                ORDER BY sequence ASC
                """,
                (run_id,),
            ).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json"))
            results.append(item)
        return results

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
        with self._transaction() as conn:
            self._insert_audit(
                conn,
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
                details=details or {},
            )

    def _insert_audit(
        self,
        conn: sqlite3.Connection,
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
        details: dict[str, Any],
    ) -> None:
        conn.execute(
            """
            INSERT INTO audit_events (
                event_id, trace_id, request_id, event_type, decision, reason_code,
                actor_id, tenant_id, resource_id, action_digest, policy_id,
                policy_version, details_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()), trace_id, request_id, event_type, decision,
                reason_code, actor_id, tenant_id, resource_id, action_digest,
                policy_id, policy_version,
                json.dumps(details, sort_keys=True, separators=(",", ":")),
                iso_now(),
            ),
        )

    def list_audit(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._reader() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_events ORDER BY sequence DESC LIMIT ?",
                (limit,),
            ).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json"))
            results.append(item)
        return results

    def list_approvals(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._reader() as conn:
            rows = conn.execute(
                """
                SELECT a.approval_id, a.refund_request_id, a.tenant_id,
                       a.principal_id, a.action_digest, a.policy_id,
                       a.policy_version, a.expires_at, a.status, a.approver_id,
                       a.created_at, a.approved_at, a.consumed_at,
                       r.order_id, r.amount_minor, r.currency, r.reason,
                       r.policy_decision, r.policy_reason_code
                FROM approvals a
                JOIN refund_requests r USING (refund_request_id)
                ORDER BY a.created_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def overview(self) -> dict[str, int]:
        with self._reader() as conn:
            refunds = conn.execute(
                "SELECT status, COUNT(*) AS count FROM refund_requests GROUP BY status"
            ).fetchall()
            approvals = conn.execute(
                "SELECT status, COUNT(*) AS count FROM approvals GROUP BY status"
            ).fetchall()
            events = conn.execute("SELECT COUNT(*) AS count FROM audit_events").fetchone()
        return {
            "refund_requests": sum(row["count"] for row in refunds),
            "pending_approvals": next(
                (row["count"] for row in approvals if row["status"] == "PENDING"), 0
            ),
            "approved_approvals": next(
                (row["count"] for row in approvals if row["status"] == "APPROVED"), 0
            ),
            "executed_refunds": next(
                (row["count"] for row in refunds if row["status"] == "EXECUTED"), 0
            ),
            "audit_events": int(events["count"]),
        }

    def get_refund_request(self, refund_request_id: str) -> dict[str, Any] | None:
        with self._reader() as conn:
            row = conn.execute(
                "SELECT * FROM refund_requests WHERE refund_request_id = ?",
                (refund_request_id,),
            ).fetchone()
        return dict(row) if row is not None else None

    def get_refund_trace(self, refund_request_id: str) -> dict[str, str] | None:
        with self._reader() as conn:
            row = conn.execute(
                "SELECT trace_id, request_id FROM approvals WHERE refund_request_id = ?",
                (refund_request_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "trace_id": row["trace_id"] or refund_request_id,
            "request_id": row["request_id"] or refund_request_id,
        }

    def get_trace_events(self, trace_id: str, limit: int = 200) -> list[dict[str, Any]]:
        with self._reader() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_events WHERE trace_id = ? ORDER BY sequence ASC LIMIT ?",
                (trace_id, limit),
            ).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json"))
            results.append(item)
        return results
