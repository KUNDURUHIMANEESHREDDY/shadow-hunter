import threading
from concurrent.futures import ThreadPoolExecutor
import pytest
from shadow_hunter import durable_workflows as dw, scheduler
from shadow_hunter.store import SQLiteStore
from shadow_hunter.policy import Principal

A=Principal("a","t","c",True)
B=Principal("b","t","c",True)
C=Principal("a","other","c",True)

def node(name,capability,resource,deps=()):
    return {"id":name,"capability":capability,"resource":resource,"depends_on":list(deps)}

def graph():
    return [node("first","numeric_summary","1,2,3"),node("second","unit_conversion","2:km_to_m",["first"]),node("other","numeric_summary","4,5")]

@pytest.fixture
def workflows(tmp_path,monkeypatch):
    monkeypatch.delenv("SHADOW_HUNTER_ENABLED_CAPABILITIES",raising=False)
    return dw.WorkflowStore(SQLiteStore(tmp_path/"workflows.sqlite"))

def test_resume_after_reopen_without_reexecution(workflows,monkeypatch):
    calls=[]
    original=dw.execute_verified_capability
    def record(*args):
        calls.append(args[-2:])
        return original(*args)
    monkeypatch.setattr(dw,"execute_verified_capability",record)
    wid=workflows.create(A,graph())
    first=workflows.advance(A,None,wid)
    assert first["status"]=="paused"
    assert first["states"]["n1"]["verification"]["status"]=="verified"
    reopened=dw.WorkflowStore(SQLiteStore(workflows.store.database_path))
    assert reopened.list(A)[0]["states"]==first["states"]
    second=reopened.advance(A,None,wid)
    assert second["states"]["n2"]["value"]=="2000"
    done=reopened.advance(A,None,wid)
    assert done["status"]=="completed"
    assert reopened.advance(A,None,wid)==done
    assert calls==[("numeric_summary","1,2,3"),("unit_conversion","2:km_to_m"),("numeric_summary","4,5")]

def test_account_and_tenant_isolation(workflows):
    wid=workflows.create(A,graph())
    for other in (B,C):
        assert workflows.list(other)==[]
        with pytest.raises(dw.WorkflowNotFound): workflows.advance(other,None,wid)
        with pytest.raises(dw.WorkflowNotFound): workflows.delete(other,wid)
    assert workflows.list(A)[0]["status"]=="paused"
    workflows.delete(A,wid)
    assert workflows.list(A)==[]

def test_concurrent_claim_is_exclusive(workflows):
    wid=workflows.create(A,graph())
    def claim():
        try:return workflows.claim(A,wid)
        except dw.WorkflowBusy:return None
    with ThreadPoolExecutor(max_workers=4) as pool:
        claims=list(pool.map(lambda _:claim(),range(4)))
    assert sum(c is not None for c in claims)==1
    assert workflows.list(A)[0]["status"]=="running"
    with pytest.raises(dw.WorkflowBusy): workflows.delete(A,wid)

def test_expired_inflight_never_replayed(workflows,monkeypatch):
    now=10000
    monkeypatch.setattr(dw.time,"time",lambda:now)
    wid=workflows.create(A,graph())
    claim,n,*_=workflows.claim(A,wid)
    now+=dw.LEASE+1
    reopened=dw.WorkflowStore(SQLiteStore(workflows.store.database_path))
    record=reopened.list(A)[0]
    assert record["states"]["n1"]["status"]=="interrupted"
    assert record["states"]["n2"]["status"]=="blocked"
    assert not reopened.finish(A,wid,claim,n["id"],{"status":"failed"})
    resumed=reopened.advance(A,None,wid)
    assert resumed["states"]["n3"]["status"]=="completed"
    assert resumed["status"]=="incomplete"

def test_revalidate_disabled_prerequisite(workflows,monkeypatch):
    wid=workflows.create(A,graph())
    workflows.advance(A,None,wid)
    monkeypatch.setenv("SHADOW_HUNTER_ENABLED_CAPABILITIES","unit_conversion")
    result=workflows.advance(A,None,wid)
    assert result["states"]["n2"]["status"]=="failed"

def test_stale_public_checkpoint_blocks_dependent(workflows,monkeypatch):
    from shadow_hunter import result_verifier
    evidence={"repository":"python/cpython","stars":12,"forks":3,"default_branch":"main"}
    monkeypatch.setattr(scheduler,"public_repo_metadata",lambda resource:{"status":"completed",**evidence})
    monkeypatch.setattr(result_verifier,"repository_evidence",lambda resource:dict(evidence))
    wid=workflows.create(A,[node("public","public_repo_metadata","python/cpython"),node("next","unit_conversion","2:km_to_m",["public"])])
    assert workflows.advance(A,None,wid)["states"]["n1"]["status"]=="completed"
    monkeypatch.setattr(result_verifier,"repository_evidence",lambda resource:{**evidence,"stars":13})
    result=workflows.advance(A,None,wid)
    assert result["states"]["n2"]["status"]=="failed"
    assert result["status"]=="incomplete"

def test_no_private_graph_or_invalid_graph(workflows):
    with pytest.raises(ValueError): workflows.create(A,[node("order","order_summary","private")])
    with pytest.raises(ValueError): workflows.create(A,[node("a","numeric_summary","1,2",["a"])])
    assert workflows.list(A)==[]

def test_capacity_expiry_and_normalized_ids(workflows,monkeypatch):
    now=1000
    monkeypatch.setattr(dw.time,"time",lambda:now)
    monkeypatch.setattr(dw,"PER_OWNER",1)
    wid=workflows.create(A,graph())
    assert workflows.list(A)[0]["nodes"][1]["depends_on"]==["n1"]
    with pytest.raises(dw.WorkflowBusy): workflows.create(A,graph())
    now+=dw.TTL+1
    assert workflows.list(A)==[]
    with pytest.raises(dw.WorkflowNotFound): workflows.advance(A,None,wid)
    assert workflows.create(A,graph())

def test_finish_requires_verification_and_matching_claim(workflows):
    wid=workflows.create(A,graph())
    claim,n,*_=workflows.claim(A,wid)
    with pytest.raises(ValueError): workflows.finish(A,wid,claim,n["id"],{"status":"completed"})
    assert not workflows.finish(A,wid,"wrong",n["id"],{"status":"failed"})
    assert workflows.list(A)[0]["status"]=="running"

def test_api_resume(tmp_path,monkeypatch):
    from fastapi.testclient import TestClient
    from shadow_hunter.api import create_app
    from shadow_hunter.auth import TokenAuthenticator
    monkeypatch.setenv("SHADOW_HUNTER_LOCAL_READONLY_ENABLED","true")
    monkeypatch.setenv("SHADOW_HUNTER_AUTH_MODE","local")
    monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME",raising=False)
    auth=TokenAuthenticator(customer_tokens={"a":{"subject_id":"a","tenant_id":"t","customer_id":"c"},"b":{"subject_id":"b","tenant_id":"t","customer_id":"c"}})
    ha={"Authorization":"Bearer a"}; hb={"Authorization":"Bearer b"}
    path="/v1/agent/local-checkpoints"
    db=tmp_path/"api.sqlite"
    with TestClient(create_app(store=SQLiteStore(db),authenticator=auth)) as api:
        assert api.get(path).status_code==401
        created=api.post(path,headers=ha,json={"nodes":graph()})
        assert created.status_code==200
        wid=created.json()["id"]
        assert api.post(path+"/"+wid+"/advance",headers=hb).status_code==404
        assert api.post(path+"/"+wid+"/advance",headers=ha).json()["status"]=="paused"
    with TestClient(create_app(store=SQLiteStore(db),authenticator=auth)) as api:
        assert api.get(path,headers=ha).json()["workflows"][0]["states"]["n1"]["status"]=="completed"
        assert api.post(path+"/"+wid+"/advance",headers=ha).json()["states"]["n2"]["value"]=="2000"
        assert api.post(path+"/"+wid+"/advance",headers=ha).json()["status"]=="completed"
        assert api.delete(path+"/"+wid,headers=hb).status_code==404
        assert api.delete(path+"/"+wid,headers=ha).status_code==200
