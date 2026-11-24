"""Preview-only local natural-language workflow compiler.

The model may classify an objective into grounded, server-issued candidate IDs.
It cannot supply resources, choose arbitrary tools, or execute anything. Explicit
"then" clauses establish dependency barriers; users review the graph before run.
"""
from __future__ import annotations
import re
import threading
import time
from . import local_runtime as rt
from .scheduler import PUBLIC_REPOSITORIES, validate_graph, validate_resource

# Ground numeric resources in literal user input; never take numbers from model.
NUMBER=r"-?[0-9]{1,8}(?:\.[0-9]{1,4})?"
UNIT={"km":"km","kilometer":"km","kilometers":"km","kilometre":"km","kilometres":"km",
      "m":"m","meter":"m","meters":"m","metre":"m","metres":"m",
      "kg":"kg","kilogram":"kg","kilograms":"kg","g":"g","gram":"g","grams":"g"}
UNIT_PATTERN="|".join(sorted(UNIT,key=len,reverse=True))
CONVERSION=re.compile(r"(?<![\w.])("+NUMBER+r")\s*("+UNIT_PATTERN+r")\s+(?:to|into|in)\s+("+UNIT_PATTERN+r")\b",re.I)
LIST=re.compile(r"(?<![\w.])"+NUMBER+r"(?:\s*,\s*"+NUMBER+r"){1,15}(?![\w.,])")
CHANGE=re.compile(r"\b(?:submit|approve|issue|execute|process|create)\s+(?:(?:a|the|my)\s+)?refund\b|\bcancel\s+(?:(?:my|the|this)\s+)?order\b|\b(?:delete|modify|change|send|book|buy|install|write|generate|create|download|upload|run code)\b",re.I)

def candidate_phases(objective,order_id=""):
    if not isinstance(objective,str) or not objective.strip() or len(objective)>1000:
        raise ValueError("Invalid objective")
    if not isinstance(order_id,str) or len(order_id)>128 or order_id!=order_id.strip():
        raise ValueError("Invalid order ID")
    if CHANGE.search(objective) or re.search(r"\b(?:ignore|override|bypass|pretend|instead|except|unless)\b",objective,re.I):
        return []
    phases=re.split(r"\b(?:and\s+then|then|afterwards|after that)\b",objective,flags=re.I)
    if len(phases)>8:
        raise ValueError("Too many phases")
    output=[]
    index=0
    for phase in phases:
        clauses=re.split(r"\band\b",phase,flags=re.I)
        if len(clauses)>8:
            raise ValueError("Too many clauses")
        group=[]
        for clause in clauses:
            clause=clause.strip(" ,;.")
            candidates=[]
            def add(capability,resource):
                nonlocal index
                validate_resource(capability,resource)
                if any(c["capability"]==capability and c["resource"]==resource for c in candidates):
                    return
                index+=1
                candidates.append({"id":f"n{index}","capability":capability,"resource":resource})
            if not clause:
                return []
            # Clear utility commands use exact, validated inputs and recognized operation words.
            for match in CONVERSION.finditer(clause):
                value,source,target=match.groups()
                key=UNIT[source.lower()]+"_to_"+UNIT[target.lower()]
                if key in {"km_to_m","m_to_km","kg_to_g","g_to_kg"} and re.search(r"\b(convert|express|change units)\b",clause,re.I):
                    add("unit_conversion",value+":"+key)
            if re.search(r"\b(summarize|summarise|summary|average|mean|statistics|stats|sum|minimum|maximum|analyze|analyse)\b",clause,re.I):
                for match in LIST.finditer(clause):
                    add("numeric_summary",",".join(p.strip() for p in match.group().split(",")))
            if re.search(r"\b(ollama|model|inference)\b",clause,re.I) and re.search(r"\b(health|ready|readiness|available|status|working)\b",clause,re.I):
                add("model_readiness","local")
            if re.search(r"\b(metadata|stars|forks|default branch|repository info|repository details)\b",clause,re.I):
                for repo in sorted(PUBLIC_REPOSITORIES):
                    if re.search(r"(?<![\w/.-])"+re.escape(repo)+r"(?![\w/.-])",clause,re.I):
                        add("public_repo_metadata",repo)
            if candidates:
                # Never silently approve ambiguous mixed input with unrecognized requests.
                if len(candidates)!=1 or re.search(r"\b(?:also|or|but|except|instead|not|without|if)\b",clause,re.I):
                    return []
                group.append((clause,candidates,True))
                continue
            if order_id and re.search(r"\b(order|purchase|refund|refundable|eligib)",clause,re.I):
                # Explicit read vocabulary provides grounded coverage without model omissions.
                details=bool(re.search(r"\b(?:order|purchase)\s+(?:details|information|currency)\b|\b(?:remaining|left)\s+(?:refundable|refund)\b|\b(?:currency|balance)\b",clause,re.I))
                eligibility=bool(re.search(r"\b(?:eligibility|eligible|qualify|qualifies|can be refunded|can .*?be refunded|refund is possible|refund is available)\b",clause,re.I))
                if details or eligibility:
                    if details: add("order_summary",order_id)
                    if eligibility: add("refund_status",order_id)
                    group.append((clause,candidates,True))
                else:
                    add("order_summary",order_id)
                    add("refund_status",order_id)
                    group.append((clause,candidates,False))
                continue
            return []
        output.append(group)
    if index>16:
        raise ValueError("Too many candidate operations")
    return output

def _select(phase,candidates,deadline):
    # Reuse the already tested proposal/review contract for ambiguous support
    # intent, while retaining the shared planner admission and deadline.
    token=rt._INFERENCE_CANCELLATION.set(threading.Event())
    try:
        proposal=rt._classify(phase,review=False,deadline=deadline)
        review=rt._classify(phase,review=True,deadline=deadline)
    finally:
        rt._INFERENCE_CANCELLATION.reset(token)
    if proposal!=review or (rt._obvious_compound_read(phase) and proposal!="both"):
        return []
    allowed={"order_details":{"order_summary"},"refund_eligibility":{"refund_status"},
             "both":{"order_summary","refund_status"}}.get(proposal,set())
    return [c["id"] for c in candidates if c["capability"] in allowed]


def plan_workflow(objective,order_id=""):
    phases=candidate_phases(objective,order_id)
    if not phases:
        return {"status":"clarify","nodes":[],"message":"No fully grounded supported workflow. Specify supported operations and inputs."}
    needs_model=any(not grounded for group in phases for _,_,grounded in group)
    if needs_model and not rt._ADMISSION.acquire(blocking=False):
        raise rt.PlannerBusy("Planning queue full")
    acquired=False
    try:
        if needs_model:
            acquired=rt._LOCK.acquire(timeout=rt.QUEUE_TIMEOUT)
            if not acquired:
                raise rt.PlannerBusy("Planning queue busy")
        deadline=time.monotonic()+rt.PLAN_TIMEOUT
        nodes=[]
        previous=[]
        used_model=False
        for group in phases:
            current=[]
            seen=set()
            for clause,candidates,grounded in group:
                if grounded:
                    selected=[c["id"] for c in candidates]
                else:
                    used_model=True
                    selected=_select(clause,candidates,deadline)
                if not selected:
                    return {"status":"clarify","nodes":[],"message":"The planner could not map all clauses to supported operations."}
                for c in candidates:
                    identity=(c["capability"],c["resource"])
                    if c["id"] in selected and identity not in seen:
                        nodes.append({**c,"depends_on":list(previous)})
                        current.append(c["id"])
                        seen.add(identity)
            previous=current
        validate_graph(nodes)
        return {"status":"preview","model":rt.MODEL if used_model else None,"source":"hybrid" if used_model else "grounded","nodes":nodes,"message":"Review this proposal before running it. No tools were executed."}
    finally:
        if acquired:
            rt._LOCK.release()
        if needs_model:
            rt._ADMISSION.release()
