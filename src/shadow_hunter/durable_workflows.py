"""Explicit, account-scoped checkpointed execution of bounded read-only graphs.

Private business capabilities are deliberately excluded: a durable graph stores
its exact inputs and verified outputs. No credentials or free-form objectives
are retained. An expired running claim is uncertain and is never replayed.
"""
from __future__ import annotations
import json
import time
from uuid import uuid4
from .scheduler import DurableScheduler, validate_graph, validate_resource, execute_verified_capability
from .result_verifier import verify

ALLOWED=frozenset({"numeric_summary","unit_conversion","model_readiness",
                   "public_repo_metadata","mcp_repo_metadata","mcp_public_package"})
TTL=7*86400
LEASE=120
PER_OWNER=12
TOTAL=500
FINAL=frozenset({"completed","failed","denied","blocked","interrupted"})

class WorkflowBusy(RuntimeError):
    pass

class WorkflowNotFound(LookupError):
    pass

def encode(value):
    raw=json.dumps(value,separators=(",",":"),allow_nan=False)
    if len(raw)>65536:
        raise ValueError("Checkpoint exceeds storage limit")
    return raw

def propagate(nodes,states):
    changed=True
    while changed:
        changed=False
        for node in nodes:
            name=node["id"]
            if states[name]["status"]!="pending":
                continue
            bad=[dep for dep in node["depends_on"] if states[dep]["status"] in FINAL-{"completed"}]
            if bad:
                states[name]={"status":"blocked","blocked_by":bad}
                changed=True

def overall(states):
    statuses={v["status"] for v in states.values()}
    if "running" in statuses: return "running"
    if "pending" in statuses: return "paused"
    if statuses=={"completed"}: return "completed"
    return "incomplete"

class WorkflowStore:
    def __init__(self,store):
        self.store=store
        with store._transaction() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS durable_workflows (
                id TEXT PRIMARY KEY,subject TEXT NOT NULL,tenant TEXT NOT NULL,customer TEXT NOT NULL,
                created REAL NOT NULL,expires REAL NOT NULL,nodes TEXT NOT NULL,states TEXT NOT NULL,
                claim TEXT,lease REAL,active TEXT)""")
            conn.execute("CREATE INDEX IF NOT EXISTS durable_workflow_owner ON durable_workflows(subject,tenant,customer,created)")

    @staticmethod
    def _prune(conn,now):
        conn.execute("DELETE FROM durable_workflows WHERE expires<=? AND (claim IS NULL OR lease<=?)",(now,now))

    def create(self,principal,nodes):
        owner=DurableScheduler.owner(principal)
        validate_graph(nodes)
        if any(node["capability"] not in ALLOWED for node in nodes):
            raise ValueError("Capability not approved for persistence")
        # Store only server-normalized node fields, not arbitrary extra text.
        nodes=[{"id":f"n{i+1}","capability":n["capability"],"resource":n["resource"],
                "depends_on":[f"n{j+1}" for j,other in enumerate(nodes) if other["id"] in n["depends_on"]]}
               for i,n in enumerate(nodes)]
        states={node["id"]:{"status":"pending"} for node in nodes}
        now=time.time()
        workflow_id=str(uuid4())
        with self.store._transaction() as conn:
            self._prune(conn,now)
            count=conn.execute("SELECT count(*) FROM durable_workflows WHERE subject=? AND tenant=? AND customer=?",owner).fetchone()[0]
            if count>=PER_OWNER or conn.execute("SELECT count(*) FROM durable_workflows").fetchone()[0]>=TOTAL:
                raise WorkflowBusy("Saved workflow capacity reached")
            conn.execute("INSERT INTO durable_workflows VALUES (?,?,?,?,?,?,?,?,NULL,NULL,NULL)",
                         (workflow_id,*owner,now,now+TTL,encode(nodes),encode(states)))
        return workflow_id

    def _get(self,conn,owner,workflow_id):
        row=conn.execute("SELECT * FROM durable_workflows WHERE id=? AND subject=? AND tenant=? AND customer=?",(workflow_id,*owner)).fetchone()
        if row is None:
            raise WorkflowNotFound
        return row

    def _load(self,conn,row,now):
        nodes=json.loads(row["nodes"])
        states=json.loads(row["states"])
        if row["claim"] and row["lease"]<=now:
            states[row["active"]]={"status":"interrupted","reason":"uncertain_prior_attempt"}
            propagate(nodes,states)
            conn.execute("UPDATE durable_workflows SET states=?,claim=NULL,lease=NULL,active=NULL WHERE id=?",(encode(states),row["id"]))
        return nodes,states

    def list(self,principal):
        owner=DurableScheduler.owner(principal)
        with self.store._transaction() as conn:
            now=time.time()
            self._prune(conn,now)
            rows=conn.execute("SELECT * FROM durable_workflows WHERE subject=? AND tenant=? AND customer=? ORDER BY created DESC LIMIT ?",(*owner,PER_OWNER)).fetchall()
            output=[]
            for row in rows:
                nodes,states=self._load(conn,row,now)
                output.append({"id":row["id"],"created":row["created"],"expires":row["expires"],
                               "status":overall(states),"nodes":nodes,"states":states,"historical_checkpoints":True})
            return output

    def delete(self,principal,workflow_id):
        owner=DurableScheduler.owner(principal)
        with self.store._transaction() as conn:
            now=time.time()
            self._prune(conn,now)
            row=self._get(conn,owner,workflow_id)
            _,states=self._load(conn,row,now)
            if overall(states)=="running":
                raise WorkflowBusy("Workflow running")
            conn.execute("DELETE FROM durable_workflows WHERE id=?",(workflow_id,))

    def claim(self,principal,workflow_id):
        owner=DurableScheduler.owner(principal)
        with self.store._transaction() as conn:
            now=time.time()
            self._prune(conn,now)
            row=self._get(conn,owner,workflow_id)
            nodes,states=self._load(conn,row,now)
            if overall(states)=="running":
                raise WorkflowBusy("Workflow already running")
            propagate(nodes,states)
            ready=next((n for n in nodes if states[n["id"]]["status"]=="pending"
                        and all(states[d]["status"]=="completed" for d in n["depends_on"])),None)
            if ready is None:
                conn.execute("UPDATE durable_workflows SET states=? WHERE id=?",(encode(states),workflow_id))
                return None
            if row["expires"]<=now:
                raise WorkflowNotFound
            claim=str(uuid4())
            states[ready["id"]]={"status":"running"}
            conn.execute("UPDATE durable_workflows SET states=?,claim=?,lease=?,active=? WHERE id=?",
                         (encode(states),claim,now+LEASE,ready["id"],workflow_id))
            return claim,ready,nodes,states

    def finish(self,principal,workflow_id,claim,node_id,result):
        owner=DurableScheduler.owner(principal)
        if not isinstance(result,dict) or result.get("status") not in {"completed","failed","denied"}:
            raise ValueError("Invalid checkpoint")
        if result["status"]=="completed" and result.get("verification",{}).get("status")!="verified":
            raise ValueError("Missing verified result")
        with self.store._transaction() as conn:
            now=time.time()
            row=self._get(conn,owner,workflow_id)
            if row["claim"]!=claim or row["active"]!=node_id or row["lease"]<=now or row["expires"]<=now:
                return False
            nodes=json.loads(row["nodes"])
            states=json.loads(row["states"])
            states[node_id]=result
            propagate(nodes,states)
            conn.execute("UPDATE durable_workflows SET states=?,claim=NULL,lease=NULL,active=NULL WHERE id=?",
                         (encode(states),workflow_id))
            return True

    def advance(self,principal,gateway,workflow_id):
        claim_data=self.claim(principal,workflow_id)
        if claim_data is not None:
            claim,node,nodes,states=claim_data
            by_id={n["id"]:n for n in nodes}
            # Revalidate every ancestor's evidence and capability policy. A
            # checkpoint is historical, not authority to use stale evidence.
            ancestors=set()
            def visit(name):
                for dep in by_id[name]["depends_on"]:
                    if dep not in ancestors:
                        ancestors.add(dep)
                        visit(dep)
            visit(node["id"])
            try:
                validate_resource(node["capability"],node["resource"])
                for dep in sorted(ancestors):
                    previous=by_id[dep]
                    candidate={k:v for k,v in states[dep].items() if k!="verification"}
                    verify(principal,gateway,previous["capability"],previous["resource"],candidate)
                result=execute_verified_capability(principal,gateway,node["capability"],node["resource"])
                if result.get("status") not in {"completed","denied"}:
                    result={"status":"failed","reason":"unverified_execution"}
            except Exception:
                result={"status":"failed","reason":"execution_or_checkpoint_verification_failed"}
            if not self.finish(principal,workflow_id,claim,node["id"],result):
                raise WorkflowBusy("Checkpoint lease expired; outcome uncertain")
        return next((r for r in self.list(principal) if r["id"]==workflow_id),None)
