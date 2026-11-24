"""Bounded recovery for approved read-only workflow graphs.

A retry preserves the original capability, resource and prerequisite set.
A revised residual graph may discard only verified dependencies. Failed
prerequisites block their descendants; independent nodes continue.
"""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import time
from .result_verifier import VerificationError


class TransientReadError(RuntimeError):
    """An adapter explicitly identified a temporary read failure."""


MAX_ATTEMPTS=2
MAX_RETRIES=4
BACKOFF_SECONDS=0.25
RETRYABLE_CAPABILITIES=frozenset({"public_repo_metadata"})


def run_graph(by_id, ledger, invoke, validate):
    results={}
    attempts={name:0 for name in by_id}
    ready_after={}
    timeline=[]
    revisions=[]
    inflight={}
    retries=0

    def event(name,state,**detail):
        timeline.append({"node":name,"state":state,"attempt":attempts[name],**detail})

    def snapshot():
        # Remove verified prerequisites only. Never weaken the original graph.
        remaining={name:sorted(dep for dep in node["depends_on"]
                               if results.get(dep,{}).get("status")!="completed")
                   for name,node in by_id.items() if name not in results}
        revisions.append({"revision":len(revisions)+1,"remaining":remaining})

    def execute(name):
        node=by_id[name]
        try:
            validate(node["capability"],node["resource"])
            result=invoke(node["capability"],node["resource"])
            if not isinstance(result,dict) or result.get("status") not in {"completed","denied"}:
                return {"status":"failed","reason":"invalid_or_unverified_result"}
            return result
        except VerificationError:
            return {"status":"failed","reason":"independent_verification_failed"}
        except TransientReadError:
            if node["capability"] in RETRYABLE_CAPABILITIES:
                return {"status":"retryable","reason":"temporary_read_failure"}
            return {"status":"failed","reason":"retry_not_allowed"}
        except ValueError:
            return {"status":"failed","reason":"invalid_or_disabled_capability"}
        except Exception:
            # A policy, audit or unknown failure is never assumed transient.
            return {"status":"failed","reason":"unverified_execution"}

    snapshot()
    with ThreadPoolExecutor(max_workers=2) as pool:
        while len(results)<len(by_id):
            changed=True
            while changed:
                changed=False
                for name,node in by_id.items():
                    if name in results or name in inflight:
                        continue
                    blocked=[dep for dep in node["depends_on"] if dep in results
                             and results[dep].get("status")!="completed"]
                    if blocked:
                        results[name]={"status":"blocked","blocked_by":blocked}
                        event(name,"blocked",blocked_by=blocked)
                        changed=True
                        snapshot()
            now=time.monotonic()
            for name in ledger.ready():
                if len(inflight)>=2:
                    break
                if name in results or name in inflight or ready_after.get(name,0)>now:
                    continue
                attempts[name]+=1
                event(name,"running")
                inflight[name]=pool.submit(execute,name)
                ready_after.pop(name,None)
            if not inflight:
                if ready_after:
                    time.sleep(max(0,min(ready_after.values())-time.monotonic()))
                    continue
                break
            timeout=min((max(0,t-time.monotonic()) for t in ready_after.values()),default=None) if len(inflight)<2 else None
            done,_=wait(tuple(inflight.values()),timeout=timeout,return_when=FIRST_COMPLETED)
            for name,future in list(inflight.items()):
                if future not in done:
                    continue
                del inflight[name]
                result=future.result()
                if result["status"]=="retryable" and attempts[name]<MAX_ATTEMPTS and retries<MAX_RETRIES:
                    retries+=1
                    ready_after[name]=time.monotonic()+BACKOFF_SECONDS
                    event(name,"retry_scheduled",reason=result["reason"])
                    snapshot()
                    continue
                if result["status"]=="retryable":
                    result={"status":"failed","reason":"retry_budget_exhausted"}
                results[name]=result
                event(name,result["status"])
                if result["status"]=="completed":
                    ledger.mark_verified(name)
                snapshot()
    for name in by_id:
        if name not in results:
            results[name]={"status":"blocked","reason":"unresolved_dependencies"}
            event(name,"blocked")
    return {"status":"completed" if all(r["status"]=="completed" for r in results.values()) else "incomplete",
            "nodes":{name:results[name] for name in by_id},
            "recovery":{"attempts":attempts,"retries":retries,"timeline":timeline,"revisions":revisions}}
