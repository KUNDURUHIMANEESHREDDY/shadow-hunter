"""Reproducible bounded orchestration benchmark; synthetic accounts only.

Default mode is offline and deterministic. --live-model and --live-mcp add
real opt-in checks, reported separately. No production database is accessed.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
from shadow_hunter import scheduler as sc, result_verifier as rv, workflow_planner as planner, recovery
from shadow_hunter import durable_workflows as dw
from shadow_hunter.agent_memory import AgentMemory
from shadow_hunter.store import SQLiteStore
from shadow_hunter.policy import Principal, PolicyEngine
from shadow_hunter.gateway import ToolGateway
from shadow_hunter.approvals import ApprovalService
from shadow_hunter import mcp_client

A=Principal("synthetic-a","tenant-a","customer-a",True)
B=Principal("synthetic-b","tenant-b","customer-b",True)
ORDER="synthetic-order"
REPO={"repository":"python/cpython","stars":10,"forks":2,"default_branch":"main"}

def require(condition,message):
    if not condition: raise AssertionError(message)

def node(i,cap,resource,deps=()):
    return {"id":i,"capability":cap,"resource":resource,"depends_on":list(deps)}

def run_benchmark(*,live_model=False,live_mcp=False):
    report=[]
    def case(name,mode,fn):
        start=time.perf_counter()
        try:
            fn()
            status="passed";reason=None
        except Exception as exc:
            status="failed";reason=type(exc).__name__+": "+str(exc)[:200]
        row={"case":name,"mode":mode,"status":status,"elapsed_ms":round((time.perf_counter()-start)*1000)}
        if reason:row["reason"]=reason
        report.append(row)
        print(json.dumps(row),flush=True)

    with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ,{"SHADOW_HUNTER_MCP_COMPANION_ENABLED":"false"}):
        os.environ.pop("SHADOW_HUNTER_ENABLED_CAPABILITIES",None)
        db=Path(tmp)/"synthetic.sqlite"
        store=SQLiteStore(db)
        store.add_order(order_id=ORDER,tenant_id=A.tenant_id,customer_id=A.customer_id,currency="USD",refundable_minor=12500)
        gateway=ToolGateway(store,PolicyEngine(),ApprovalService(store,ttl_seconds=60))
        def execute(nodes,p=A):
            return sc.execute_graph(p,gateway,nodes)
        def plan(q,expected,order=""):
            result=planner.plan_workflow(q,order)
            require(result["status"]=="preview","Expected supported preview")
            require([n["capability"] for n in result["nodes"]]==expected,"Incorrect capability selection")
            return result["nodes"]
        def reject(q,order=""):
            result=planner.plan_workflow(q,order)
            require(result["status"]=="clarify" and not result["nodes"],"Unsupported request was partially planned")
        def verified(result):
            require(result["status"]=="completed","Workflow did not complete")
            require(all(n.get("verification",{}).get("status")=="verified" for n in result["nodes"].values()),"Missing verification")
        def compute(q,expected,value):
            nodes=plan(q,expected)
            result=execute(nodes);verified(result)
            require(list(result["nodes"].values())[-1].get("value")==value,"Unexpected conversion")
        case("decimal conversion and dependency barrier","offline",lambda:compute("Analyze -2, 0.5, 7 then convert 1.25 kg to g",["numeric_summary","unit_conversion"],"1250.00"))
        def parallel():
            nodes=plan("Summarize 3, 7, 11 and convert 500 g to kg then convert 4 km to m",["numeric_summary","unit_conversion","unit_conversion"])
            require(set(nodes[2]["depends_on"])=={nodes[0]["id"],nodes[1]["id"]},"Missing parallel prerequisites")
            verified(execute(nodes))
        case("parallel branches and join","offline",parallel)
        def support():
            nodes=plan("Show my order currency and check refund eligibility",["order_summary","refund_status"],ORDER)
            result=execute(nodes);verified(result)
            require(result["nodes"][nodes[0]["id"]]["steps"][0]["result"]["order"]["refundable_minor"]==12500,"Incorrect balance")
        case("authorized support with audit verification","offline",support)
        def isolation():
            result=execute([node("a","order_summary",ORDER),node("b","unit_conversion","2:km_to_m",["a"]),node("c","numeric_summary","3,4")],B)
            require(result["status"]=="incomplete" and result["nodes"]["a"]["status"]=="denied" and result["nodes"]["b"]["status"]=="blocked" and result["nodes"]["c"]["status"]=="completed","Isolation/dependency failure")
        case("foreign order denial and independent continuation","offline",isolation)
        for q in ("Summarize 1,2,3 and write a story","Get repository metadata for unknown/project","Delete my order","Do not show my order details","Don't check refund eligibility"):
            case("reject: "+q,"offline",lambda q=q:reject(q,ORDER))
        def disabled():
            with patch.dict(os.environ,{"SHADOW_HUNTER_ENABLED_CAPABILITIES":"numeric_summary"}):
                reject("Summarize 1,2,3 then convert 2 km to m")
        case("disabled capability fails closed","offline",disabled)
        def retry():
            original=sc.execute_capability;calls=[]
            def adapter(p,g,c,r):
                if c=="public_repo_metadata":
                    calls.append(r)
                    if len(calls)==1:raise recovery.TransientReadError("controlled")
                    return {"status":"completed",**REPO}
                return original(p,g,c,r)
            with patch.object(sc,"execute_capability",adapter),patch.object(rv,"repository_evidence",lambda r:dict(REPO)):
                result=execute([node("a","public_repo_metadata","python/cpython"),node("b","unit_conversion","2:km_to_m",["a"])])
            verified(result);require(len(calls)==2 and result["recovery"]["retries"]==1,"Retry count mismatch")
        case("transient failure recovery (injected)","offline",retry)
        def corrupted():
            original=sc.execute_capability
            def adapter(p,g,c,r):
                return {"status":"completed","value":"7","conversion":"km_to_m"} if c=="unit_conversion" else original(p,g,c,r)
            with patch.object(sc,"execute_capability",adapter):
                result=execute([node("a","unit_conversion","2:km_to_m"),node("b","numeric_summary","1,2",["a"])])
            require(result["nodes"]["a"].get("reason")=="independent_verification_failed" and result["nodes"]["b"]["status"]=="blocked","False completion accepted")
        case("false success rejected (injected)","offline",corrupted)
        def memory():
            nodes=[node("a","numeric_summary","1,2,3")]
            memory=AgentMemory(store);result=execute(nodes);verified(result)
            epoch=memory.begin(A);mid=memory.remember(A,epoch,nodes,result)
            reopened=AgentMemory(SQLiteStore(db))
            require(reopened.relevant(A,nodes)[0]["id"]==mid and not reopened.list(B),"Memory isolation/retrieval failure")
            reopened.clear(A)
            require(not reopened.list(A) and reopened.remember(A,epoch,nodes,result) is None,"Cleared memory restored")
        case("persistent memory recall and clear","offline",memory)
        def checkpoint():
            nodes=[node("a","numeric_summary","1,2,3"),node("b","unit_conversion","2:km_to_m",["a"])]
            saved=dw.WorkflowStore(store);wid=saved.create(A,nodes);first=saved.advance(A,gateway,wid)
            reopened=dw.WorkflowStore(SQLiteStore(db))
            original=dw.execute_verified_capability;calls=[]
            def record(*args):calls.append(args[-2]);return original(*args)
            with patch.object(dw,"execute_verified_capability",record):
                final=reopened.advance(A,gateway,wid)
            require(final["status"]=="completed" and final["states"]["n1"]==first["states"]["n1"] and calls==["unit_conversion"],"Checkpoint replay or loss")
        case("durable checkpoint resume without adapter replay","offline",checkpoint)
        def stream():
            events=[]
            result=sc.execute_graph(A,gateway,[node("a","numeric_summary","3,4"),node("b","unit_conversion","2:km_to_m",["a"])],progress=events.append)
            verified(result)
            seq=[(e["node"],e["state"]) for e in events if e["type"]=="node"]
            require(seq==[("a","running"),("a","verifying"),("a","completed"),("b","running"),("b","verifying"),("b","completed")],"Wrong event sequence")
        case("streamed verification and dependency ordering","offline",stream)
        if live_model:
            for q,cap in [("Please retrieve my purchase.","order_summary"),("Could I get a refund for this purchase?","refund_status"),("What can you tell me about my purchase?","order_summary")]:
                def model(q=q,cap=cap):
                    nodes=plan(q,[cap],ORDER)
                    verified(execute(nodes))
                case("Qwen: "+q,"live_model",model)
            def readiness():
                result=execute([node("a","model_readiness","local")]);verified(result)
                require(result["nodes"]["a"]["readiness"]["ready"] is True,"Local model is not ready")
            case("local model readiness with independent probe","live_model",readiness)
        if live_mcp:
            def mcp():
                # Do not attach to an unknown existing process on this port.
                with socket.socket() as sock:sock.bind(("127.0.0.1",8766))
                env=os.environ.copy();env["SHADOW_HUNTER_MCP_COMPANION_ENABLED"]="true"
                env["PYTHONPATH"]=str(Path(__file__).resolve().parents[1]/"src")
                with patch.dict(os.environ,{"SHADOW_HUNTER_MCP_COMPANION_ENABLED":"true"}):
                    child=subprocess.Popen([sys.executable,"-m","shadow_hunter.mcp_companion"],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                    try:
                        for _ in range(60):
                            require(child.poll() is None,"Companion exited")
                            try:
                                with socket.create_connection(("127.0.0.1",8766),.2):break
                            except OSError:time.sleep(.2)
                        require(mcp_client.discover()==["mcp_public_package","mcp_repo_metadata"],"MCP discovery mismatch")
                        nodes=plan("Get PyPI version for httpx and get GitHub stars for pallets/flask via MCP then convert 5 kg to g",["mcp_public_package","mcp_repo_metadata","unit_conversion"])
                        result=execute(nodes);verified(result)
                        require(result["nodes"][nodes[-1]["id"]]["value"]=="5000","Incorrect conversion")
                    finally:
                        child.terminate();child.wait(timeout=10)
            case("live MCP discovery, fresh-source verification and local join","live_mcp",mcp)
    return {"cases":report,"passed":sum(r["status"]=="passed" for r in report),"total":len(report),"scope":"bounded approved read-only workflows; offline fault injection separated from live services"}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live-model",action="store_true");parser.add_argument("--live-mcp",action="store_true")
    parser.add_argument("--output",type=Path)
    args=parser.parse_args()
    result=run_benchmark(live_model=args.live_model,live_mcp=args.live_mcp)
    if args.output:args.output.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print("BENCHMARK",result["passed"],"/",result["total"],flush=True)
    return int(result["passed"]!=result["total"])

if __name__=="__main__":raise SystemExit(main())
