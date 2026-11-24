import threading
from collections import Counter
import pytest
from shadow_hunter import scheduler
from shadow_hunter import recovery
from shadow_hunter.policy import Principal

P=Principal("s","t","c",True)

def node(name,capability,resource,deps=()):
    return {"id":name,"capability":capability,"resource":resource,"depends_on":list(deps)}

def graph():
    return [node("repo","public_repo_metadata","python/cpython"),
            node("independent","numeric_summary","1,2,3"),
            node("dependent","unit_conversion","2:km_to_m",["repo"]),
            node("other_branch","unit_conversion","3:kg_to_g",["independent"])]

@pytest.fixture(autouse=True)
def settings(monkeypatch):
    monkeypatch.delenv("SHADOW_HUNTER_ENABLED_CAPABILITIES",raising=False)
    monkeypatch.setattr(recovery,"BACKOFF_SECONDS",.03)

def test_transient_recovery_preserves_dependencies(monkeypatch):
    calls=[]
    def invoke(principal,gateway,capability,resource):
        calls.append((capability,resource))
        if capability=="public_repo_metadata" and calls.count((capability,resource))==1:
            raise recovery.TransientReadError("temporary")
        return {"status":"completed"}
    monkeypatch.setattr(scheduler,"execute_capability",invoke)
    result=scheduler.execute_graph(P,None,graph())
    assert result["status"]=="completed"
    assert result["recovery"]["attempts"]=={"repo":2,"independent":1,"dependent":1,"other_branch":1}
    assert result["recovery"]["retries"]==1
    timeline=result["recovery"]["timeline"]
    assert any(e["state"]=="retry_scheduled" for e in timeline)
    verified=next(i for i,e in enumerate(timeline) if e["node"]=="repo" and e["state"]=="completed")
    dependent=next(i for i,e in enumerate(timeline) if e["node"]=="dependent" and e["state"]=="running")
    assert dependent>verified
    assert result["recovery"]["revisions"][-1]["remaining"]=={}

def test_independent_branch_progresses_during_retry(monkeypatch):
    monkeypatch.setattr(recovery,"BACKOFF_SECONDS",.2)
    calls=Counter()
    def invoke(principal,gateway,capability,resource):
        calls[(capability,resource)]+=1
        if capability=="public_repo_metadata" and calls[(capability,resource)]==1:
            raise recovery.TransientReadError("temporary")
        return {"status":"completed"}
    monkeypatch.setattr(scheduler,"execute_capability",invoke)
    result=scheduler.execute_graph(P,None,graph())
    events=result["recovery"]["timeline"]
    independent=next(i for i,e in enumerate(events) if e["node"]=="other_branch" and e["state"]=="completed")
    retry=next(i for i,e in enumerate(events) if e["node"]=="repo" and e["state"]=="running" and e["attempt"]==2)
    assert independent<retry

def test_persistent_failure_blocks_transitive_descendants(monkeypatch):
    def invoke(principal,gateway,capability,resource):
        if capability=="public_repo_metadata":
            raise recovery.TransientReadError("temporary")
        return {"status":"completed"}
    monkeypatch.setattr(scheduler,"execute_capability",invoke)
    nodes=graph()+[node("last","numeric_summary","1,2",["dependent"])]
    result=scheduler.execute_graph(P,None,nodes)
    assert result["status"]=="incomplete"
    assert result["nodes"]["repo"]=={"status":"failed","reason":"retry_budget_exhausted"}
    assert result["nodes"]["dependent"]["blocked_by"]==["repo"]
    assert result["nodes"]["last"]["blocked_by"]==["dependent"]
    assert result["nodes"]["other_branch"]["status"]=="completed"
    assert result["recovery"]["attempts"]["last"]==0

@pytest.mark.parametrize("failure",["denied","unknown","invalid","transient"])
def test_no_retry_on_denied_or_unverified_support(monkeypatch,failure):
    def invoke(principal,gateway,capability,resource):
        if failure=="denied": return {"status":"denied"}
        if failure=="unknown": raise RuntimeError("secret audit error")
        if failure=="invalid": return {"status":"unexpected"}
        raise recovery.TransientReadError("not approved for retry")
    monkeypatch.setattr(scheduler,"execute_capability",invoke)
    result=scheduler.execute_graph(P,None,[node("a","order_summary","owned"),node("b","numeric_summary","1,2",["a"])])
    assert result["status"]=="incomplete"
    assert result["recovery"]["attempts"]=={"a":1,"b":0}
    assert result["nodes"]["b"]["status"]=="blocked"
    assert "secret audit error" not in repr(result)

def test_disable_during_recovery(monkeypatch):
    calls=[]
    def invoke(principal,gateway,capability,resource):
        calls.append(capability)
        monkeypatch.setenv("SHADOW_HUNTER_ENABLED_CAPABILITIES","numeric_summary")
        raise recovery.TransientReadError("temporary")
    monkeypatch.setattr(scheduler,"execute_capability",invoke)
    result=scheduler.execute_graph(P,None,[node("repo","public_repo_metadata","python/cpython")])
    assert calls==["public_repo_metadata"]
    assert result["nodes"]["repo"]["reason"]=="invalid_or_disabled_capability"
    assert result["status"]=="incomplete"

def test_global_retry_budget(monkeypatch):
    monkeypatch.setattr(recovery,"MAX_RETRIES",2)
    monkeypatch.setattr(scheduler,"execute_capability",lambda *a: (_ for _ in ()).throw(recovery.TransientReadError("temporary")))
    result=scheduler.execute_graph(P,None,[node(str(i),"public_repo_metadata","python/cpython") for i in range(8)])
    assert result["recovery"]["retries"]==2
    assert sum(result["recovery"]["attempts"].values())==10
    assert result["status"]=="incomplete"

def test_completed_does_not_wait_for_unrelated_slow_branch(monkeypatch):
    release=threading.Event()
    def invoke(principal,gateway,capability,resource):
        if capability=="public_repo_metadata":
            assert release.wait(3)
        if resource=="3:kg_to_g":
            release.set()
        return {"status":"completed"}
    monkeypatch.setattr(scheduler,"execute_capability",invoke)
    result=scheduler.execute_graph(P,None,graph())
    assert result["status"]=="completed"
    assert release.is_set()

@pytest.mark.parametrize("code,retry_after,retryable",[(502,None,True),(503,None,True),(504,None,True),(503,"10",False),(429,None,False),(403,None,False),(404,None,False)])
def test_real_adapter_http_classification(monkeypatch,code,retry_after,retryable):
    import httpx2
    from contextlib import contextmanager
    class Client:
        def __init__(self,**kwargs):
            assert kwargs["follow_redirects"] is False and kwargs["trust_env"] is False
        def __enter__(self): return self
        def __exit__(self,*args): pass
        @contextmanager
        def stream(self,method,url,headers):
            assert url=="https://api.github.com/repos/python/cpython"
            yield httpx2.Response(code,headers={"Retry-After":retry_after} if retry_after else {},
                                 request=httpx2.Request("GET",url))
    monkeypatch.setattr(httpx2,"Client",Client)
    with pytest.raises(recovery.TransientReadError if retryable else httpx2.HTTPStatusError):
        scheduler.public_repo_metadata("python/cpython")
