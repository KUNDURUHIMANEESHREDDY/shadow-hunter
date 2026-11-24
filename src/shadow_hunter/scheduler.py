"""Durable, account-scoped queue for explicitly approved read-only jobs.

Manual dispatch requires fresh authentication; one-shot automatic jobs are explicitly granted and revalidated against local identities. No bearer token, free-form
prompt, model response, or business result is persisted in this queue.
Expired running leases are interrupted, never replayed implicitly.
"""
from __future__ import annotations

import time
import re
from decimal import Decimal
from types import MappingProxyType
from uuid import uuid4

from . import local_runtime as rt
from .policy import Principal
from .store import SQLiteStore

CAPABILITIES = MappingProxyType({
    "order_summary": "order_details",
    "refund_status": "refund_eligibility",
    "order_and_refund_review": "both",
    "model_readiness": None,
    "numeric_summary": None,
    "public_repo_metadata": None,
    "unit_conversion": None,
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
            columns = {row[1] for row in conn.execute("PRAGMA table_info(local_jobs)")}
            for name in ("due", "expires", "repeat_interval", "runs_remaining", "runs_completed"):
                if name not in columns:
                    conn.execute("ALTER TABLE local_jobs ADD COLUMN " + name + " REAL")
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
        conn.execute("""UPDATE local_jobs SET state='interrupted',updated=?
            WHERE state='queued' AND expires IS NOT NULL AND expires<=?""", (now, now))

    def enqueue(self, principal: Principal, capability: str, resource: str,
                *, delay_seconds: int | None = None, repeat_interval: int | None = None,
                run_count: int | None = None) -> str:
        owner = self.owner(principal)
        if (not isinstance(capability, str) or capability not in CAPABILITIES
                or not isinstance(resource, str) or not resource.strip()
                or resource != resource.strip() or len(resource)>128):
            raise ValueError("Invalid job")
        validate_resource(capability,resource)
        if delay_seconds is not None and (type(delay_seconds) is not int or not 0 <= delay_seconds <= 3600):
            raise ValueError("Invalid schedule delay")
        if repeat_interval is not None:
            if (delay_seconds is None or type(repeat_interval) is not int
                    or not 60 <= repeat_interval <= 86400 or type(run_count) is not int
                    or not 2 <= run_count <= 20 or repeat_interval*(run_count-1)>7*86400):
                raise ValueError("Invalid bounded recurrence")
        elif run_count is not None:
            raise ValueError("Repeat interval required")
        now, job = time.time(), str(uuid4())
        due = now + delay_seconds if delay_seconds is not None else None
        expires = due + 300 if due is not None else None
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
                (job_id,subject,tenant,customer,capability,resource,state,created,updated,due,expires,repeat_interval,runs_remaining,runs_completed)
                VALUES (?,?,?,?,?,?,'queued',?,?,?,?,?,?,0)""", (job,*owner,capability,resource,now,now,due,expires,repeat_interval,run_count))
        return job

    def list(self, principal: Principal) -> list[dict]:
        owner = self.owner(principal)
        with self.store._transaction() as conn:
            self._expire(conn,time.time())
            rows = conn.execute("""SELECT job_id,capability,state,created,updated,trace,due,expires,repeat_interval,runs_remaining,runs_completed
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
                AND due IS NULL ORDER BY created,job_id LIMIT 1""",owner).fetchone()
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
            row=conn.execute("""SELECT due,repeat_interval,runs_remaining FROM local_jobs
                WHERE job_id=? AND subject=? AND tenant=? AND customer=? AND state='running' AND claim=?""",
                (job,*owner,claim)).fetchone()
            if row is None:
                return False
            remaining=int(row["runs_remaining"] or 0)
            if status=="completed" and row["repeat_interval"] and remaining>1:
                due=max(now,row["due"])+row["repeat_interval"]
                conn.execute("""UPDATE local_jobs SET state='queued',trace=?,updated=?,claim=NULL,lease=NULL,
                    due=?,expires=?,runs_remaining=?,runs_completed=COALESCE(runs_completed,0)+1 WHERE job_id=?""",
                    (trace,now,due,due+300,remaining-1,job))
            else:
                conn.execute("""UPDATE local_jobs SET state=?,trace=?,updated=?,claim=NULL,lease=NULL,
                    runs_remaining=?,runs_completed=COALESCE(runs_completed,0)+? WHERE job_id=?""",
                    (status,trace,now,max(0,remaining-1),int(status=="completed"),job))
            return True

    def dispatch_next(self, principal: Principal, gateway):
        entry = self.claim_next(principal)
        if entry is None:
            return None
        return self.execute_claim(principal, gateway, entry)

    def execute_claim(self, principal: Principal, gateway, entry):
        job, claim = entry
        trace = None
        status = "failed"
        result = None
        try:
            result = execute_capability(principal,gateway,job["capability"],job["resource"])
            trace = result.get("trace_id")
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

    def claim_due(self, authorize):
        now = time.time()
        with self.store._transaction() as conn:
            self._expire(conn, now)
            if conn.execute("SELECT count(*) FROM local_jobs WHERE state='running'").fetchone()[0]>=4:
                return None
            rows = conn.execute("""SELECT job_id,subject,tenant,customer,capability,resource
                FROM local_jobs WHERE state='queued' AND due<=? AND expires>?
                ORDER BY due,created,job_id LIMIT 8""",(now,now)).fetchall()
            for row in rows:
                owner=(row["subject"],row["tenant"],row["customer"])
                principal=authorize(owner)
                if principal is None or self.owner(principal)!=owner:
                    conn.execute("UPDATE local_jobs SET state='denied',updated=? WHERE job_id=?",(now,row["job_id"]))
                    continue
                claim=str(uuid4())
                conn.execute("""UPDATE local_jobs SET state='running',claim=?,lease=?,updated=?
                    WHERE job_id=? AND state='queued'""",(claim,now+120,now,row["job_id"]))
                return principal,(dict(row),claim)
        return None

    def dispatch_due(self, gateway, authorize):
        from concurrent.futures import ThreadPoolExecutor
        entries=[]
        for _ in range(4):
            item=self.claim_due(authorize)
            if item is None:
                break
            entries.append(item)
        if not entries:
            return []
        with ThreadPoolExecutor(max_workers=len(entries)) as pool:
            return [future.result() for future in [
                pool.submit(self.execute_claim,principal,gateway,entry)
                for principal,entry in entries]]


def numeric_values(value: str):
    parts=value.split(",")
    if not 1<=len(parts)<=16 or any(not re.fullmatch(r"-?\d{1,8}(?:\.\d{1,4})?",p.strip()) for p in parts):
        raise ValueError("Provide up to 16 bounded decimal values")
    return [Decimal(p.strip()) for p in parts]


def run_utility(capability: str, resource: str):
    if capability=="numeric_summary":
        values=numeric_values(resource)
        return {"status":"completed","count":len(values),"sum":str(sum(values)),
                "min":str(min(values)),"max":str(max(values)),
                "mean":str(sum(values)/len(values))}
    if capability=="model_readiness" and resource=="local":
        return {"status":"completed","readiness":rt.model_readiness()}
    if capability=="unit_conversion":
        value,unit=resource.split(":")
        factors={"km_to_m":Decimal(1000),"m_to_km":Decimal("0.001"),"kg_to_g":Decimal(1000),"g_to_kg":Decimal("0.001")}
        return {"status":"completed","value":str(Decimal(value)*factors[unit]),"conversion":unit}
    if capability=="public_repo_metadata":
        return public_repo_metadata(resource)
    raise ValueError("Unknown utility capability")


PUBLIC_REPOSITORIES=frozenset({"python/cpython","pallets/flask","fastapi/fastapi"})
CONVERSIONS=frozenset({"km_to_m","m_to_km","kg_to_g","g_to_kg"})


def validate_resource(capability,resource):
    if not isinstance(capability,str) or capability not in CAPABILITIES or not isinstance(resource,str) or not resource.strip() or resource.strip()!=resource or len(resource)>128:
        raise ValueError("Invalid capability input")
    if capability=="model_readiness" and resource!="local":
        raise ValueError("Invalid fixed resource")
    if capability=="numeric_summary":
        numeric_values(resource)
    if capability=="public_repo_metadata" and resource not in PUBLIC_REPOSITORIES:
        raise ValueError("Repository not approved")
    if capability=="unit_conversion":
        parts=resource.split(":")
        if len(parts)!=2 or parts[1] not in CONVERSIONS or len(numeric_values(parts[0]))!=1:
            raise ValueError("Invalid conversion")


def public_repo_metadata(resource):
    import json
    import httpx2
    if resource not in PUBLIC_REPOSITORIES:
        raise ValueError("Repository not approved")
    # Fixed HTTPS origin, exact public allowlist, no credentials or redirects.
    with httpx2.Client(trust_env=False,follow_redirects=False,timeout=5) as client:
        with client.stream("GET","https://api.github.com/repos/"+resource,
                           headers={"Accept":"application/vnd.github+json","User-Agent":"Shadow-Hunter"}) as response:
            response.raise_for_status()
            data=bytearray()
            for chunk in response.iter_bytes():
                data.extend(chunk[:65537-len(data)])
                if len(data)>65536:
                    raise ValueError("Oversized response")
    payload=json.loads(data)
    if payload.get("full_name")!=resource or payload.get("private") is not False:
        raise ValueError("Unverified repository")
    return {"status":"completed","repository":resource,"stars":int(payload["stargazers_count"]),
            "forks":int(payload["forks_count"]),"default_branch":str(payload["default_branch"])[:128]}


def execute_capability(principal,gateway,capability,resource):
    DurableScheduler.owner(principal)
    validate_resource(capability,resource)
    intent=CAPABILITIES[capability]
    if intent is None:
        return run_utility(capability,resource)
    for event in rt._iter_readonly_task(gateway,principal,prompt="Approved workflow read",
                                       order_id=resource,approved_intent=intent):
        if event["type"]=="result":
            return event["result"]
    raise RuntimeError("No verified result")


def validate_graph(nodes):
    """Validate the complete graph without performing any action."""
    from .orchestration import DependencyLedger
    if not isinstance(nodes,list) or not 1<=len(nodes)<=8:
        raise ValueError("Invalid graph size")
    by_id={}
    for node in nodes:
        if not isinstance(node,dict) or set(node)!={"id","capability","resource","depends_on"}:
            raise ValueError("Invalid node")
        name=node["id"]
        if not isinstance(name,str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,32}",name) or name in by_id:
            raise ValueError("Invalid node identity")
        validate_resource(node["capability"],node["resource"])
        by_id[name]=node
    ledger=DependencyLedger.compile([{"id":n["id"],"depends_on":n["depends_on"]} for n in nodes],
                                    allowed=frozenset(by_id),max_nodes=8)
    return by_id,ledger


def execute_graph(principal,gateway,nodes):
    """Execute explicit bounded DAGs; dependencies never override authorization."""
    from concurrent.futures import ThreadPoolExecutor
    DurableScheduler.owner(principal)
    by_id,ledger=validate_graph(nodes)
    results={}
    def run(name):
        n=by_id[name]
        try:
            return execute_capability(principal,gateway,n["capability"],n["resource"])
        except Exception:
            return {"status":"failed"}
    with ThreadPoolExecutor(max_workers=2) as pool:
        while True:
            ready=[name for name in ledger.ready() if name not in results]
            if not ready:
                break
            # All graph nodes are validated before any execution.
            futures={name:pool.submit(run,name) for name in ready[:2]}
            for name,future in futures.items():
                result=future.result()
                results[name]=result
                if result.get("status")=="completed":
                    ledger.mark_verified(name)
    for name in by_id:
        results.setdefault(name,{"status":"blocked"})
    return {"status":"completed" if all(r.get("status")=="completed" for r in results.values()) else "incomplete",
            "nodes":results}
