"""Independent, deterministic evidence checks at workflow completion boundaries.

A verifier failure is not retryable, does not authorize a substitute action, and
does not return the candidate payload. Public metadata is corroborated through a
fresh fixed-origin HTTPS read, not a second model or the same MCP response.
"""
from __future__ import annotations
import json
import re
from decimal import Decimal, localcontext
from fractions import Fraction
from datetime import datetime, timezone

class VerificationError(RuntimeError):
    pass

def check(condition):
    if not condition:
        raise VerificationError("Result evidence did not match")

def exact_decimal(value):
    check(isinstance(value,str) and len(value)<=100 and re.fullmatch(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[Ee][+-]?[0-9]{1,2})?",value) is not None)
    number=Decimal(value)
    check(number.is_finite() and abs(number.as_tuple().exponent)<=80)
    return number

def fields(result,expected):
    check(set(result)==set(expected)|{"status"})
    for key,value in expected.items():
        check(type(result.get(key)) is type(value) and result[key]==value)

def fresh_json(url,limit):
    import httpx2
    # Callers construct URLs exclusively from server-owned public allowlists.
    with httpx2.Client(trust_env=False,follow_redirects=False,timeout=5) as client:
        with client.stream("GET",url,headers={"Accept":"application/json","User-Agent":"Shadow-Hunter-Verifier"}) as response:
            response.raise_for_status()
            raw=bytearray()
            for chunk in response.iter_bytes():
                raw.extend(chunk[:limit+1-len(raw)])
                check(len(raw)<=limit)
    data=json.loads(raw)
    check(isinstance(data,dict))
    return data

def repository_evidence(resource):
    from .scheduler import PUBLIC_REPOSITORIES
    check(resource in PUBLIC_REPOSITORIES)
    data=fresh_json("https://api.github.com/repos/"+resource,65536)
    check(data.get("full_name")==resource and data.get("private") is False)
    stars,forks,branch=(data.get(k) for k in ("stargazers_count","forks_count","default_branch"))
    check(all(type(n) is int and 0<=n<=10**12 for n in (stars,forks)))
    check(isinstance(branch,str) and re.fullmatch(r"[A-Za-z0-9._/-]{1,128}",branch) is not None)
    return {"repository":resource,"stars":stars,"forks":forks,"default_branch":branch}

def package_evidence(resource):
    from .mcp_client import PACKAGES
    check(resource in PACKAGES)
    data=fresh_json("https://pypi.org/pypi/"+resource+"/json",2097152)
    info=data.get("info")
    check(isinstance(info,dict) and isinstance(info.get("name"),str) and info["name"].lower()==resource)
    version=info.get("version")
    check(isinstance(version,str) and re.fullmatch(r"[A-Za-z0-9.+!_-]{1,80}",version) is not None)
    return {"package":resource,"version":version}

def model_evidence():
    from .local_runtime import MODEL
    # Independent direct probe of the configured loopback service. Unavailable
    # is a valid health observation, not evidence that the model is operational.
    try:
        payload=fresh_json("http://127.0.0.1:11434/api/tags",262144)
        models=payload.get("models")
        check(isinstance(models,list))
        ready=any(isinstance(item,dict) and (item.get("name")==MODEL or item.get("model")==MODEL) for item in models)
        return {"model":MODEL,"status":"ready" if ready else "model_missing","ready":ready}
    except Exception:
        return {"model":MODEL,"status":"unavailable","ready":False}

def support_evidence(principal,gateway,capability,resource,result):
    from .local_runtime import AGENT_ID
    expected={"order_summary":["get_order"],"refund_status":["check_refund_eligibility"],
              "order_and_refund_review":["get_order","check_refund_eligibility"]}[capability]
    check(gateway is not None)
    trace=result.get("trace_id")
    check(isinstance(trace,str) and len(trace)<=128)
    steps=result.get("steps")
    check(isinstance(steps,list) and result.get("plan")==expected and type(result.get("verified_steps")) is int and result["verified_steps"]==len(steps))
    denied=result["status"]=="denied"
    check(1<=len(steps)<=len(expected))
    check([s.get("tool") for s in steps]==expected[:len(steps)])
    check(denied or len(steps)==len(expected))
    events=gateway.store.get_trace_events(trace)
    order=None if denied else gateway.store.get_order(resource)
    if not denied:
        check(order is not None and order.tenant_id==principal.tenant_id and order.customer_id==principal.customer_id)
    requests=set()
    for index,step in enumerate(steps):
        tool=step["tool"]
        decision="DENY" if denied and index==len(steps)-1 else "ALLOW"
        candidate=step.get("result")
        check(isinstance(candidate,dict) and candidate.get("decision")==decision and candidate.get("trace_id")==trace)
        request=candidate.get("request_id")
        check(isinstance(request,str) and request not in requests)
        requests.add(request)
        matches=[e for e in events if e.get("event_type")=="POLICY_DECISION" and e.get("request_id")==request]
        check(len(matches)==1)
        event=matches[0]
        expected_event={"actor_id":principal.subject_id,"tenant_id":principal.tenant_id,"resource_id":resource,
                        "trace_id":trace,"decision":decision,"details":{"tool_name":tool,"agent_id":AGENT_ID}}
        from .gateway import public_tool_result
        expected_event.update({k:candidate.get(k) for k in ("policy_id","policy_version","action_digest")})
        check(all(event.get(k)==v for k,v in expected_event.items()))
        check(public_tool_result(event).get("reason_code")==candidate.get("reason_code"))
        if denied:
            # A denied workflow does not expose any candidate business payload.
            continue
        if tool=="get_order":
            key="order"
            expected_data={"order_id":resource,"currency":order.currency,"refundable_minor":order.refundable_minor,
                           "refund_eligible":order.refund_eligible}
        else:
            key="eligibility"
            expected_data={"currency":order.currency,"refundable_minor":order.refundable_minor,
                           "eligible":order.refund_eligible and order.refundable_minor>0}
        actual=candidate.get(key)
        check(isinstance(actual,dict) and set(actual)==set(expected_data))
        check(all(type(actual[k]) is type(v) and actual[k]==v for k,v in expected_data.items()))
    return "audit_denial" if denied else "audit_and_current_store"

def verify(principal,gateway,capability,resource,result):
    """Return the original result plus verifier-owned evidence classification.

    Denials are never converted into success. For success, every capability
    needs a concrete verification method. No model-authored evidence is trusted.
    """
    try:
        from .scheduler import validate_resource
        validate_resource(capability,resource)
        check(isinstance(result,dict))
        if result.get("status")=="denied":
            if capability in {"order_summary","refund_status","order_and_refund_review"}:
                support_evidence(principal,gateway,capability,resource,result)
                return {"status":"denied","trace_id":result["trace_id"],
                        "verified_steps":len(result["steps"]),
                        "steps":[{"tool":step["tool"],"result":{"decision":step["result"]["decision"]}} for step in result["steps"]],
                        "answer":"The requested resource is not available to this account."}
            return {"status":"denied"}
        check(result.get("status")=="completed")
        if capability=="numeric_summary":
            values=[Fraction(part.strip()) for part in resource.split(",")]
            check(set(result)=={"status","count","sum","min","max","mean"})
            check(type(result["count"]) is int and result["count"]==len(values))
            for key,value in (("sum",sum(values)),("min",min(values)),("max",max(values))):
                check(Fraction(exact_decimal(result[key]))==value)
            with localcontext() as ctx:
                ctx.prec=28
                mean=sum(values)/len(values)
                check(exact_decimal(result["mean"])==Decimal(mean.numerator)/Decimal(mean.denominator))
            method="independent_rational_recalculation"
        elif capability=="unit_conversion":
            value,unit=resource.split(":")
            scale=Fraction(1000) if unit in {"km_to_m","kg_to_g"} else Fraction(1,1000)
            check(set(result)=={"status","value","conversion"} and result["conversion"]==unit)
            check(Fraction(exact_decimal(result["value"]))==Fraction(value)*scale)
            method="independent_rational_recalculation"
        elif capability=="model_readiness":
            fields(result,{"readiness":model_evidence()})
            ready=result["readiness"]
            check(type(ready.get("ready")) is bool)
            method="fresh_loopback_probe"
        elif capability in {"public_repo_metadata","mcp_repo_metadata"}:
            evidence=dict(repository_evidence(resource))
            if capability.startswith("mcp_"):
                evidence["provider"]="mcp_companion"
            fields(result,evidence)
            method="fresh_public_source"
        elif capability=="mcp_public_package":
            fields(result,{**package_evidence(resource),"provider":"mcp_companion"})
            method="fresh_public_source"
        elif capability in {"order_summary","refund_status","order_and_refund_review"}:
            method=support_evidence(principal,gateway,capability,resource,result)
        else:
            raise VerificationError("No approved verifier")
        return {**result,"verification":{"status":"verified","method":method,
                    "checked_at":datetime.now(timezone.utc).isoformat()}}
    except VerificationError:
        raise
    except Exception:
        raise VerificationError("Independent evidence unavailable or invalid") from None
