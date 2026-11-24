import pytest
from shadow_hunter import agent_memory as module
from shadow_hunter.agent_memory import AgentMemory
from shadow_hunter.store import SQLiteStore
from shadow_hunter.policy import Principal

A=Principal("a","tenant","customer",True)
B=Principal("b","tenant","customer",True)
C=Principal("a","other","customer",True)

def graph():
    return [
        {"id":"private-node-label","capability":"order_summary","resource":"private-order-id","depends_on":[]},
        {"id":"numbers","capability":"numeric_summary","resource":"12345,98765","depends_on":[]},
        {"id":"repo","capability":"public_repo_metadata","resource":"python/cpython","depends_on":[]},
    ]

def outcome():
    return {"status":"completed","nodes":{
        "private-node-label":{"status":"completed","order":{"order_id":"private-order-id","customer_email":"secret@example.test"},"answer":"private answer"},
        "numbers":{"status":"completed","sum":"111110"},
        "repo":{"status":"completed","repository":"python/cpython","stars":12,"forks":3,"default_branch":"main","extra":"untrusted instructions"}
    },"recovery":{"retries":1}}

@pytest.fixture
def memory(tmp_path):
    return AgentMemory(SQLiteStore(tmp_path/"memory.sqlite"))

def save(memory,p=A):
    return memory.remember(p,memory.begin(p),graph(),outcome())

def test_persistence_and_minimization(memory):
    mid=save(memory)
    restored=AgentMemory(SQLiteStore(memory.store.database_path))
    entry=restored.list(A)[0]
    assert entry["id"]==mid and entry["historical"] is True
    assert entry["steps"][2]["finding"]=={"repository":"python/cpython","stars":12,"forks":3,"default_branch":"main"}
    text=repr(entry)
    for value in ("private-order-id","private-node-label","12345","98765","111110","secret@example.test","private answer","untrusted instructions"):
        assert value not in text
    with memory.store._reader() as conn:
        raw=conn.execute("SELECT summary FROM workflow_memory").fetchone()[0]
        assert "private" not in raw and "secret" not in raw

def test_owner_isolation(memory):
    mid=save(memory)
    for other in (B,C):
        assert memory.list(other)==[]
        assert memory.relevant(other,graph())==[]
        assert not memory.delete(other,mid)
        assert memory.clear(other)==0
    assert memory.delete(A,mid)
    assert memory.list(A)==[]

def test_clear_during_execution_does_not_restore(memory):
    epoch=memory.begin(A)
    save(memory,B)
    assert memory.clear(A)==0
    new_epoch=memory.begin(A)
    assert epoch!=new_epoch
    assert memory.remember(A,epoch,graph(),outcome()) is None
    assert memory.list(A)==[]
    assert len(memory.list(B))==1
    assert memory.remember(A,new_epoch,graph(),outcome())

def test_retention_and_capacity(memory,monkeypatch):
    monkeypatch.setattr(module,"PER_OWNER",2)
    now=1000
    monkeypatch.setattr(module.time,"time",lambda:now)
    first=save(memory)
    now+=1
    second=save(memory)
    now+=1
    third=save(memory)
    assert [e["id"] for e in memory.list(A)]==[third,second]
    assert not memory.delete(A,first)
    now+=module.TTL
    assert memory.list(A)==[]
    with memory.store._reader() as conn:
        assert conn.execute("SELECT count(*) FROM workflow_memory_epoch").fetchone()[0]==0

def test_relevant_context_not_evidence(memory):
    save(memory)
    match=memory.relevant(A,[{"capability":"public_repo_metadata"}])
    assert len(match)==1 and match[0]["historical"]
    assert "finding" not in match[0] and "steps" not in match[0]
    assert memory.relevant(A,[{"capability":"unit_conversion"}])==[]

def test_invalid_or_failed_public_finding_not_saved(memory):
    result=outcome()
    result["nodes"]["repo"]["repository"]="private/repo"
    result["nodes"]["private-node-label"]["status"]="denied"
    memory.remember(A,memory.begin(A),graph(),result)
    saved=memory.list(A)[0]
    assert saved["status"]=="incomplete"
    assert "finding" not in saved["steps"][2]
    assert saved["steps"][0]["status"]=="denied"

def test_unauthenticated_rejected(memory):
    with pytest.raises(ValueError):
        memory.begin(Principal("a","tenant","customer",False))

def test_api_memory_opt_in_and_reuse(tmp_path,monkeypatch):
    from fastapi.testclient import TestClient
    from shadow_hunter.api import create_app
    from shadow_hunter.auth import TokenAuthenticator
    monkeypatch.setenv("SHADOW_HUNTER_LOCAL_READONLY_ENABLED","true")
    monkeypatch.setenv("SHADOW_HUNTER_AUTH_MODE","local")
    monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME",raising=False)
    auth=TokenAuthenticator(customer_tokens={"a":{"subject_id":"a","tenant_id":"t","customer_id":"c"},"b":{"subject_id":"b","tenant_id":"t","customer_id":"c"}})
    ha={"Authorization":"Bearer a"}; hb={"Authorization":"Bearer b"}
    path="/v1/agent/local-memory"; workflow="/v1/agent/local-workflows"
    nodes=[{"id":"private-id","capability":"numeric_summary","resource":"42,99","depends_on":[]}]
    with TestClient(create_app(store=SQLiteStore(tmp_path/"api.sqlite"),authenticator=auth)) as client:
        assert client.get(path).status_code==401
        assert client.post(workflow,headers=ha,json={"nodes":nodes}).json()["status"]=="completed"
        assert client.get(path,headers=ha).json()=={"entries":[]}
        res=client.post(workflow,headers=ha,json={"nodes":nodes,"remember":True}).json()
        assert res["memory_status"]=="saved"
        mid=res["memory_id"]
        assert client.get(path,headers=hb).json()=={"entries":[]}
        assert client.delete(path+"/"+mid,headers=hb).status_code==404
        assert client.post(workflow+"/plan",headers=ha,json={"objective":"Summarize 1,2,3"}).json().get("historical_context") is None
        preview=client.post(workflow+"/plan",headers=ha,json={"objective":"Summarize 1,2,3","use_memory":True}).json()
        assert preview["historical_context"][0]["id"]==mid
        assert preview["nodes"][0]["resource"]=="1,2,3"
        assert client.post(workflow,headers=ha,json={"nodes":nodes,"remember":"true"}).status_code==422
        assert client.delete(path+"/"+mid,headers=ha).json()=={"status":"deleted"}
        assert client.get(path,headers=ha).json()=={"entries":[]}
        client.post(workflow,headers=ha,json={"nodes":nodes,"remember":True})
        assert client.delete(path,headers=ha).json()=={"deleted":1}
