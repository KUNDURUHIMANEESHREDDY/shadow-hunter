import copy
import pytest
from shadow_hunter import scheduler
from shadow_hunter import result_verifier as verifier
from shadow_hunter.policy import Principal, PolicyEngine
from shadow_hunter.store import SQLiteStore
from shadow_hunter.gateway import ToolGateway
from shadow_hunter.approvals import ApprovalService

P=Principal("subject","tenant","customer",True)

def node(i,capability,resource,deps=()):
    return {"id":i,"capability":capability,"resource":resource,"depends_on":list(deps)}

@pytest.fixture(autouse=True)
def config(monkeypatch):
    monkeypatch.delenv("SHADOW_HUNTER_ENABLED_CAPABILITIES",raising=False)
    monkeypatch.setenv("SHADOW_HUNTER_MCP_COMPANION_ENABLED","true")

@pytest.fixture
def gateway(tmp_path):
    store=SQLiteStore(tmp_path/"verify.sqlite")
    store.add_order(order_id="owned",tenant_id="tenant",customer_id="customer",currency="USD",refundable_minor=1000)
    return ToolGateway(store,PolicyEngine(),ApprovalService(store,ttl_seconds=60))

@pytest.mark.parametrize("resource",["1,2,3","1,2,2","-2,0.125,9.0025","99999999,0.0001","0,0"])
def test_exact_numeric_recalculation(resource):
    result=scheduler.execute_verified_capability(P,None,"numeric_summary",resource)
    assert result["verification"]["method"]=="independent_rational_recalculation"

@pytest.mark.parametrize("key,value",[("count",True),("sum","99"),("mean","3"),("min","NaN"),("max","Infinity")])
def test_fabricated_numeric_result_rejected(key,value):
    result=scheduler.run_utility("numeric_summary","1,2,3")
    result[key]=value
    with pytest.raises(verifier.VerificationError):
        verifier.verify(P,None,"numeric_summary","1,2,3",result)

def test_false_completion_blocks_dependents(monkeypatch):
    original=scheduler.execute_capability
    calls=[]
    def fake(principal,gateway,capability,resource):
        calls.append(resource)
        if resource=="1,2,3":
            return {"status":"completed"}
        return original(principal,gateway,capability,resource)
    monkeypatch.setattr(scheduler,"execute_capability",fake)
    result=scheduler.execute_graph(P,None,[node("a","numeric_summary","1,2,3"),node("b","unit_conversion","2:km_to_m",["a"]),node("c","numeric_summary","4,5")])
    assert result["status"]=="incomplete"
    assert result["nodes"]["a"]=={"status":"failed","reason":"independent_verification_failed"}
    assert result["nodes"]["b"]["status"]=="blocked"
    assert result["nodes"]["c"]["verification"]["status"]=="verified"
    assert "2:km_to_m" not in calls and result["recovery"]["retries"]==0

def test_queue_cannot_persist_false_completion(tmp_path,monkeypatch):
    queue=scheduler.DurableScheduler(SQLiteStore(tmp_path/"jobs.sqlite"))
    queue.enqueue(P,"unit_conversion","2:km_to_m")
    monkeypatch.setattr(scheduler,"execute_capability",lambda *a:{"status":"completed","value":"42","conversion":"km_to_m"})
    result=queue.dispatch_next(P,None)
    assert result["status"]=="failed" and result["result"] is None
    assert queue.list(P)[0]["state"]=="failed"

def test_support_matches_audit_and_store(gateway):
    result=scheduler.execute_verified_capability(P,gateway,"order_and_refund_review","owned")
    assert result["verification"]["method"]=="audit_and_current_store"

def test_support_rejects_altered_business_result(gateway):
    result=scheduler.execute_capability(P,gateway,"order_summary","owned")
    result["steps"][0]["result"]["order"]["refundable_minor"]=99
    with pytest.raises(verifier.VerificationError):
        verifier.verify(P,gateway,"order_summary","owned",result)

def test_support_rejects_wrong_account_and_trace(gateway):
    result=scheduler.execute_capability(P,gateway,"order_summary","owned")
    with pytest.raises(verifier.VerificationError):
        verifier.verify(Principal("other","tenant","customer",True),gateway,"order_summary","owned",result)
    result["trace_id"]="fake"
    with pytest.raises(verifier.VerificationError):
        verifier.verify(P,gateway,"order_summary","owned",result)

def test_public_mcp_independent_source(monkeypatch):
    expected={"repository":"python/cpython","stars":10,"forks":2,"default_branch":"main"}
    monkeypatch.setattr(verifier,"repository_evidence",lambda resource:expected)
    candidate={"status":"completed",**expected,"provider":"mcp_companion"}
    assert verifier.verify(P,None,"mcp_repo_metadata","python/cpython",candidate)["verification"]["method"]=="fresh_public_source"
    candidate["stars"]=11
    with pytest.raises(verifier.VerificationError):
        verifier.verify(P,None,"mcp_repo_metadata","python/cpython",candidate)

def test_package_source_mismatch(monkeypatch):
    monkeypatch.setattr(verifier,"package_evidence",lambda resource:{"package":resource,"version":"2.0"})
    with pytest.raises(verifier.VerificationError):
        verifier.verify(P,None,"mcp_public_package","requests",{"status":"completed","package":"requests","version":"1.0","provider":"mcp_companion"})

def test_source_unavailable_fails_closed(monkeypatch):
    def fail(resource): raise RuntimeError("private upstream error")
    monkeypatch.setattr(verifier,"repository_evidence",fail)
    monkeypatch.setattr(scheduler,"execute_capability",lambda *a:{"status":"completed","repository":"python/cpython","stars":10,"forks":2,"default_branch":"main"})
    result=scheduler.execute_graph(P,None,[node("repo","public_repo_metadata","python/cpython")])
    assert result["nodes"]["repo"]["reason"]=="independent_verification_failed"
    assert "private upstream error" not in repr(result)
    assert result["recovery"]["retries"]==0

def test_model_health_false_claim(monkeypatch):
    from shadow_hunter.local_runtime import MODEL
    monkeypatch.setattr(verifier,"model_evidence",lambda:{"model":MODEL,"status":"unavailable","ready":False})
    with pytest.raises(verifier.VerificationError):
        verifier.verify(P,None,"model_readiness","local",{"status":"completed","readiness":{"model":MODEL,"status":"ready","ready":True}})
    result=verifier.verify(P,None,"model_readiness","local",{"status":"completed","readiness":{"model":MODEL,"status":"unavailable","ready":False}})
    assert result["verification"]["status"]=="verified" and result["readiness"]["ready"] is False


def test_denied_result_never_discloses_candidate_payload(gateway):
    outsider=Principal("other","other","other",True)
    result=scheduler.execute_capability(outsider,gateway,"order_summary","owned")
    result["steps"][0]["result"]["order"]={"secret":"private data"}
    checked=verifier.verify(outsider,gateway,"order_summary","owned",result)
    assert checked["status"]=="denied"
    assert "private data" not in repr(checked)

def test_oversized_decimal_exponent_rejected():
    result=scheduler.run_utility("numeric_summary","1,2")
    result["sum"]="1e999999999"
    with pytest.raises(verifier.VerificationError):
        verifier.verify(P,None,"numeric_summary","1,2",result)
