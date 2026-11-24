"""Opt-in, account-scoped workflow memory.

Only sanitized outcomes and explicitly public metadata are retained. Raw prompts,
private order IDs, numeric inputs, business results and model text are excluded.
Remembered data is historical context, never authorization or current evidence.
"""
from __future__ import annotations
import json
import re
import time
from uuid import uuid4
from .scheduler import DurableScheduler, CAPABILITIES

TTL=30*86400
PER_OWNER=30
TOTAL=3000
PUBLIC_REPOS=frozenset({"python/cpython","pallets/flask","fastapi/fastapi"})
PUBLIC_PACKAGES=frozenset({"requests","httpx","fastapi"})
STATES=frozenset({"completed","failed","denied","blocked","interrupted"})


def public_finding(capability,resource,result):
    if result.get("status")!="completed":
        return None
    if capability in {"public_repo_metadata","mcp_repo_metadata"}:
        if resource not in PUBLIC_REPOS or result.get("repository")!=resource:
            return None
        stars,forks,branch=(result.get(k) for k in ("stars","forks","default_branch"))
        if any(type(v) is not int or not 0<=v<=10**12 for v in (stars,forks)):
            return None
        if not isinstance(branch,str) or not re.fullmatch(r"[A-Za-z0-9._/-]{1,128}",branch):
            return None
        return {"repository":resource,"stars":stars,"forks":forks,"default_branch":branch}
    if capability=="mcp_public_package":
        version=result.get("version")
        if resource in PUBLIC_PACKAGES and result.get("package")==resource and isinstance(version,str) and re.fullmatch(r"[A-Za-z0-9.+!_-]{1,80}",version):
            return {"package":resource,"version":version}
    if capability=="model_readiness":
        readiness=result.get("readiness")
        if isinstance(readiness,dict) and readiness.get("status") in {"ready","model_missing","unavailable"}:
            return {"model_status":readiness["status"]}
    return None


def summarize(nodes,result):
    if not isinstance(result,dict) or not isinstance(result.get("nodes"),dict):
        raise ValueError("Missing workflow outcome")
    records=[]
    for node in nodes:
        name,capability=node["id"],node["capability"]
        outcome=result["nodes"].get(name,{})
        if capability not in CAPABILITIES or not isinstance(outcome,dict) or outcome.get("status") not in STATES:
            raise ValueError("Invalid workflow outcome")
        # Generated ordinal IDs prevent user-supplied identifiers from being persisted.
        finding=public_finding(capability,node["resource"],outcome)
        item={"capability":capability,"status":outcome["status"]}
        if finding is not None:
            item["finding"]=finding
        records.append(item)
    status="completed" if all(item["status"]=="completed" for item in records) else "incomplete"
    retries=result.get("recovery",{}).get("retries",0)
    return {"status":status,"steps":records,"retries":retries if type(retries) is int and 0<=retries<=4 else 0}


class AgentMemory:
    def __init__(self,store):
        self.store=store
        with store._transaction() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS workflow_memory (
                id TEXT PRIMARY KEY,subject TEXT NOT NULL,tenant TEXT NOT NULL,
                customer TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,
                summary TEXT NOT NULL)""")
            conn.execute("CREATE INDEX IF NOT EXISTS workflow_memory_owner ON workflow_memory(subject,tenant,customer,created)")
            conn.execute("""CREATE TABLE IF NOT EXISTS workflow_memory_epoch (
                subject TEXT NOT NULL,tenant TEXT NOT NULL,customer TEXT NOT NULL,
                epoch TEXT NOT NULL,PRIMARY KEY(subject,tenant,customer))""")

            columns={row[1] for row in conn.execute("PRAGMA table_info(workflow_memory_epoch)")}
            if "expires" not in columns:
                conn.execute("ALTER TABLE workflow_memory_epoch ADD COLUMN expires REAL NOT NULL DEFAULT 0")

    @staticmethod
    def _prune(conn,now):
        conn.execute("DELETE FROM workflow_memory WHERE expires<=?",(now,))
        conn.execute("DELETE FROM workflow_memory_epoch WHERE expires<=?",(now,))

    def begin(self,principal):
        owner=DurableScheduler.owner(principal)
        with self.store._transaction() as conn:
            self._prune(conn,time.time())
            # Epoch prevents an in-flight run from restoring cleared memory.
            row=conn.execute("SELECT epoch FROM workflow_memory_epoch WHERE subject=? AND tenant=? AND customer=?",owner).fetchone()
            if row is not None:
                conn.execute("UPDATE workflow_memory_epoch SET expires=? WHERE subject=? AND tenant=? AND customer=?",(time.time()+TTL,*owner))
                return row["epoch"]
            if conn.execute("SELECT count(*) FROM workflow_memory_epoch").fetchone()[0]>=TOTAL:
                raise RuntimeError("Memory capacity reached")
            epoch=str(uuid4())
            conn.execute("INSERT INTO workflow_memory_epoch(subject,tenant,customer,epoch,expires) VALUES (?,?,?,?,?)",(*owner,epoch,time.time()+TTL))
            return epoch

    def remember(self,principal,epoch,nodes,result):
        owner=DurableScheduler.owner(principal)
        summary=json.dumps(summarize(nodes,result),separators=(",",":"))
        if len(summary)>8192:
            raise ValueError("Oversized summary")
        now=time.time()
        memory_id=str(uuid4())
        with self.store._transaction() as conn:
            self._prune(conn,now)
            row=conn.execute("SELECT epoch FROM workflow_memory_epoch WHERE subject=? AND tenant=? AND customer=?",owner).fetchone()
            if row is None or row["epoch"]!=epoch:
                return None
            conn.execute("INSERT INTO workflow_memory VALUES (?,?,?,?,?,?,?)",(memory_id,*owner,now,now+TTL,summary))
            conn.execute("""DELETE FROM workflow_memory WHERE subject=? AND tenant=? AND customer=? AND id NOT IN
                (SELECT id FROM workflow_memory WHERE subject=? AND tenant=? AND customer=? ORDER BY created DESC,rowid DESC LIMIT ?)""",(*owner,*owner,PER_OWNER))
            conn.execute("""DELETE FROM workflow_memory WHERE id NOT IN
                (SELECT id FROM workflow_memory ORDER BY created DESC,rowid DESC LIMIT ?)""",(TOTAL,))
        return memory_id

    def list(self,principal):
        owner=DurableScheduler.owner(principal)
        with self.store._transaction() as conn:
            self._prune(conn,time.time())
            rows=conn.execute("""SELECT id,created,expires,summary FROM workflow_memory
                WHERE subject=? AND tenant=? AND customer=? ORDER BY created DESC,rowid DESC LIMIT ?""",(*owner,PER_OWNER)).fetchall()
        return [{"id":r["id"],"created":r["created"],"expires":r["expires"],"historical":True,**json.loads(r["summary"])} for r in rows]

    def delete(self,principal,memory_id):
        owner=DurableScheduler.owner(principal)
        with self.store._transaction() as conn:
            self._prune(conn,time.time())
            return conn.execute("DELETE FROM workflow_memory WHERE id=? AND subject=? AND tenant=? AND customer=?",(memory_id,*owner)).rowcount==1

    def clear(self,principal):
        owner=DurableScheduler.owner(principal)
        with self.store._transaction() as conn:
            count=conn.execute("DELETE FROM workflow_memory WHERE subject=? AND tenant=? AND customer=?",owner).rowcount
            conn.execute("DELETE FROM workflow_memory_epoch WHERE subject=? AND tenant=? AND customer=?",owner)
            return count

    def relevant(self,principal,nodes):
        # Only capability-name matching; no free-form stored text or stale-result reuse.
        names={node["capability"] for node in nodes}
        matches=[]
        for entry in self.list(principal):
            if any(step["capability"] in names for step in entry["steps"]):
                matches.append({"id":entry["id"],"created":entry["created"],"status":entry["status"],
                                "capabilities":sorted({s["capability"] for s in entry["steps"] if s["capability"] in names}),
                                "historical":True})
            if len(matches)>=3:
                break
        return matches
