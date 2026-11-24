"""Durable, account-scoped queue for explicitly approved read-only jobs.

Dispatch requires a fresh authenticated request. No bearer token, free-form
prompt, model response, or business result is persisted in this queue.
Expired running leases are interrupted, never replayed implicitly.
"""
from __future__ import annotations

import time
from types import MappingProxyType
from uuid import uuid4

from . import local_runtime as rt
from .policy import Principal
from .store import SQLiteStore

CAPABILITIES = MappingProxyType({
    "order_summary": "order_details",
    "refund_status": "refund_eligibility",
    "order_and_refund_review": "both",
})
TERMINAL = ("completed", "denied", "failed", "interrupted", "cancelled")


class QueueBusy(RuntimeError):
    pass


class DurableScheduler:
    def __init__(self, store: SQLiteStore):
        self.store = store
        with store._transaction() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS local_jobs (
                job_id TEXT PRIMARY KEY, subject TEXT NOT NULL,
                tenant TEXT NOT NULL, customer TEXT NOT NULL,
                capability TEXT NOT NULL, resource TEXT NOT NULL,
                state TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL,
                claim TEXT, lease REAL, trace TEXT
            )""")
            conn.execute("""CREATE INDEX IF NOT EXISTS local_jobs_owner
                ON local_jobs(subject,tenant,customer,state,created)""")

    @staticmethod
    def owner(principal: Principal) -> tuple[str, str, str]:
        owner = (principal.subject_id, principal.tenant_id, principal.customer_id)
        if principal.authenticated is not True or not all(isinstance(x, str) and x for x in owner):
            raise ValueError("Authenticated customer required")
        return owner

    @staticmethod
    def _expire(conn, now):
        conn.execute("""UPDATE local_jobs SET state='interrupted',updated=?,claim=NULL,lease=NULL
            WHERE state='running' AND lease<=?""", (now, now))

    def enqueue(self, principal: Principal, capability: str, resource: str) -> str:
        owner = self.owner(principal)
        if (not isinstance(capability, str) or capability not in CAPABILITIES
                or not isinstance(resource, str) or not resource.strip()
                or resource != resource.strip() or len(resource)>128):
            raise ValueError("Invalid job")
        now, job = time.time(), str(uuid4())
        with self.store._transaction() as conn:
            self._expire(conn, now)
            # Bound storage and pending work. No eviction of running work.
            conn.execute("""DELETE FROM local_jobs WHERE state IN
                ('completed','denied','failed','interrupted','cancelled') AND updated<?""",
                (now-7*86400,))
            count = conn.execute("SELECT count(*) FROM local_jobs").fetchone()[0]
            active = conn.execute("""SELECT count(*) FROM local_jobs
                WHERE subject=? AND tenant=? AND customer=? AND state IN ('queued','running')""",
                owner).fetchone()[0]
            if count>=1000 or active>=8:
                raise QueueBusy("Job queue capacity reached")
            conn.execute("""INSERT INTO local_jobs
                (job_id,subject,tenant,customer,capability,resource,state,created,updated)
                VALUES (?,?,?,?,?,?,'queued',?,?)""", (job,*owner,capability,resource,now,now))
        return job

    def list(self, principal: Principal) -> list[dict]:
        owner = self.owner(principal)
        with self.store._transaction() as conn:
            self._expire(conn,time.time())
            rows = conn.execute("""SELECT job_id,capability,state,created,updated,trace
                FROM local_jobs WHERE subject=? AND tenant=? AND customer=?
                ORDER BY created DESC LIMIT 100""",owner).fetchall()
        return [dict(row) for row in rows]

    def cancel(self, principal: Principal, job: str) -> bool:
        owner = self.owner(principal)
        with self.store._transaction() as conn:
            return conn.execute("""UPDATE local_jobs SET state='cancelled',updated=?
                WHERE job_id=? AND subject=? AND tenant=? AND customer=? AND state='queued'""",
                (time.time(),job,*owner)).rowcount == 1

    def claim_next(self, principal: Principal):
        owner = self.owner(principal)
        now, claim = time.time(), str(uuid4())
        with self.store._transaction() as conn:
            self._expire(conn,now)
            if conn.execute("SELECT count(*) FROM local_jobs WHERE state='running'").fetchone()[0]>=4:
                raise QueueBusy("Job execution capacity reached")
            row = conn.execute("""SELECT job_id,capability,resource FROM local_jobs
                WHERE subject=? AND tenant=? AND customer=? AND state='queued'
                ORDER BY created,job_id LIMIT 1""",owner).fetchone()
            if row is None:
                return None
            conn.execute("""UPDATE local_jobs SET state='running',claim=?,lease=?,updated=?
                WHERE job_id=? AND state='queued'""",(claim,now+120,now,row["job_id"]))
            return dict(row),claim

    def finish(self, principal: Principal, job: str, claim: str, status: str, trace: str | None):
        owner = self.owner(principal)
        if status not in TERMINAL:
            raise ValueError("Invalid terminal state")
        now = time.time()
        with self.store._transaction() as conn:
            self._expire(conn,now)
            return conn.execute("""UPDATE local_jobs SET state=?,trace=?,updated=?,claim=NULL,lease=NULL
                WHERE job_id=? AND subject=? AND tenant=? AND customer=?
                AND state='running' AND claim=?""",(status,trace,now,job,*owner,claim)).rowcount == 1

    def dispatch_next(self, principal: Principal, gateway):
        entry = self.claim_next(principal)
        if entry is None:
            return None
        job, claim = entry
        trace = None
        status = "failed"
        result = None
        try:
            # Registry selection cannot grant new permissions or accept arbitrary tool names.
            intent = CAPABILITIES[job["capability"]]
            for event in rt._iter_readonly_task(gateway,principal,prompt="Approved scheduled read",
                                               order_id=job["resource"],approved_intent=intent):
                if event["type"] == "progress":
                    trace = event["trace_id"]
                elif event["type"] == "result":
                    result = event["result"]
                    status = result["status"]
            if status not in ("completed","denied"):
                status = "failed"
        except Exception:
            status = "failed"
        if not self.finish(principal,job["job_id"],claim,status,trace):
            status = "interrupted"
        return {"job_id":job["job_id"],"status":status,"trace_id":trace,
                "result":result if status in ("completed","denied") else None}

    def dispatch_batch(self, principal: Principal, gateway, limit: int = 4):
        from concurrent.futures import ThreadPoolExecutor
        if type(limit) is not int or not 1 <= limit <= 4:
            raise ValueError("Invalid batch size")
        self.owner(principal)
        def run():
            try:
                return self.dispatch_next(principal, gateway)
            except QueueBusy:
                return {"status": "busy"}
        with ThreadPoolExecutor(max_workers=limit) as pool:
            results = [future.result() for future in
                       [pool.submit(run) for _ in range(limit)]]
        return [result for result in results if result is not None]
