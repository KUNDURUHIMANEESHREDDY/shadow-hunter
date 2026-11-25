import json
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import pytest
from fastapi.testclient import TestClient
from shadow_hunter.api import create_app
from shadow_hunter.auth import TokenAuthenticator
from shadow_hunter.store import SQLiteStore
from shadow_hunter import scheduler,recovery
from shadow_hunter.policy import Principal

PATH="/v1/agent/local-workflows/stream"
HEADERS={"Authorization":"Bearer synthetic"}
P=Principal("subject","tenant","customer",True)

def graph():
    return [{"id":"a","capability":"numeric_summary","resource":"1,2,3","depends_on":[]},
            {"id":"b","capability":"unit_conversion","resource":"2:km_to_m","depends_on":["a"]}]

@pytest.fixture
def app(tmp_path,monkeypatch):
    monkeypatch.setenv("SHADOW_HUNTER_LOCAL_READONLY_ENABLED","true")
    monkeypatch.setenv("SHADOW_HUNTER_AUTH_MODE","local")
    monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME",raising=False)
    monkeypatch.delenv("SHADOW_HUNTER_ENABLED_CAPABILITIES",raising=False)
    auth=TokenAuthenticator(customer_tokens={"synthetic":{"subject_id":"subject","tenant_id":"tenant","customer_id":"customer"}})
    return create_app(store=SQLiteStore(tmp_path/"stream.sqlite"),authenticator=auth)

def parse(response):
    assert response.status_code==200
    assert response.headers["content-type"].startswith("application/x-ndjson")
    events=[json.loads(line) for line in response.text.splitlines()]
    assert [e["sequence"] for e in events]==list(range(1,len(events)+1))
    assert [e["elapsed_ms"] for e in events]==sorted(e["elapsed_ms"] for e in events)
    return events

def test_stream_auth_and_invalid_graph(app):
    with TestClient(app) as client:
        assert client.post(PATH,json={"nodes":graph()}).status_code==401
        invalid=graph();invalid[0]["depends_on"]=["b"]
        assert client.post(PATH,json={"nodes":invalid},headers=HEADERS).status_code==422

def test_stream_matches_actual_result_and_memory(app):
    with TestClient(app) as client:
        events=parse(client.post(PATH,json={"nodes":graph(),"remember":True},headers=HEADERS))
        assert events[0]["type"]=="graph"
        assert all(set(n)=={"id","capability","depends_on"} for n in events[0]["nodes"])
        states=[(e["node"],e["state"]) for e in events if e["type"]=="node"]
        assert states==[("a","running"),("a","verifying"),("a","completed"),("b","running"),("b","verifying"),("b","completed")]
        assert events[-1]["type"]=="result"
        result=events[-1]["result"]
        assert result["status"]=="completed" and result["memory_status"]=="saved"
        assert result["nodes"]["b"]["value"]=="2000"
        assert result["nodes"]["a"]["verification"]["status"]=="verified"
        assert [e["revision"] for e in events if e["type"]=="revision"]==[1,2,3]

def test_stream_recovery_and_verification_failure(app,monkeypatch):
    from shadow_hunter import result_verifier
    evidence={"repository":"python/cpython","stars":10,"forks":2,"default_branch":"main"}
    calls=[]
    original=scheduler.execute_capability
    def adapter(p,g,c,r):
        if c=="public_repo_metadata":
            calls.append(r)
            if len(calls)==1: raise recovery.TransientReadError("temporary")
            return {"status":"completed",**evidence}
        if c=="unit_conversion":
            return {"status":"completed","conversion":"km_to_m","value":"999"}
        return original(p,g,c,r)
    monkeypatch.setattr(scheduler,"execute_capability",adapter)
    monkeypatch.setattr(result_verifier,"repository_evidence",lambda r:dict(evidence))
    monkeypatch.setattr(recovery,"BACKOFF_SECONDS",.01)
    nodes=[{"id":"repo","capability":"public_repo_metadata","resource":"python/cpython","depends_on":[]},
           {"id":"bad","capability":"unit_conversion","resource":"2:km_to_m","depends_on":["repo"]},
           {"id":"child","capability":"numeric_summary","resource":"1,2","depends_on":["bad"]}]
    with TestClient(app) as client:
        events=parse(client.post(PATH,json={"nodes":nodes},headers=HEADERS))
    assert any(e.get("state")=="retry_scheduled" for e in events)
    assert any(e.get("state")=="failed" and e.get("reason")=="independent_verification_failed" for e in events)
    result=events[-1]["result"]
    assert result["status"]=="incomplete"
    assert result["nodes"]["child"]["status"]=="blocked"
    assert result["recovery"]["retries"]==1

def test_cancel_stops_new_nodes(monkeypatch):
    stop=threading.Event()
    original=scheduler.execute_capability
    calls=[]
    def adapter(*args):
        calls.append(args[-1])
        stop.set()
        return original(*args)
    monkeypatch.setattr(scheduler,"execute_capability",adapter)
    result=scheduler.execute_graph(P,None,graph(),progress=lambda e:None,cancellation=stop)
    assert calls==["1,2,3"]
    assert result["status"]=="incomplete"
    assert result["nodes"]["b"]["reason"]=="stream_disconnected"

@pytest.fixture
def live_server(app):
    import uvicorn
    sock=socket.socket()
    sock.bind(("127.0.0.1",0));sock.listen(16)
    port=sock.getsockname()[1]
    server=uvicorn.Server(uvicorn.Config(app,log_level="error",access_log=False))
    thread=threading.Thread(target=server.run,kwargs={"sockets":[sock]},daemon=True)
    thread.start()
    try:
        for _ in range(100):
            if server.started:break
            time.sleep(.02)
        assert server.started
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit=True
        thread.join(10);sock.close()
        assert not thread.is_alive()

def test_real_http_events_before_completion(live_server,monkeypatch):
    import httpx2
    entered=threading.Event();release=threading.Event()
    original=scheduler.execute_capability
    def adapter(*args):
        if args[-1]=="1,2,3":
            entered.set()
            assert release.wait(5)
        return original(*args)
    monkeypatch.setattr(scheduler,"execute_capability",adapter)
    try:
        with httpx2.Client(timeout=5,trust_env=False) as client:
            with client.stream("POST",live_server+PATH,headers=HEADERS,json={"nodes":graph()}) as response:
                lines=response.iter_lines()
                first=json.loads(next(lines))
                assert first["type"]=="graph"
                assert entered.wait(2)
                assert not release.is_set()
                while True:
                    event=json.loads(next(lines))
                    if event.get("state")=="running":break
                assert event["node"]=="a"
                release.set()
                rest=[json.loads(line) for line in lines]
                assert rest[-1]["result"]["status"]=="completed"
    finally:
        release.set()

def test_real_http_disconnect_stops_dependents(live_server,monkeypatch):
    import httpx2
    entered=threading.Event();release=threading.Event();finished=threading.Event();calls=[]
    original=scheduler.execute_capability
    original_graph=scheduler.execute_graph
    def adapter(*args):
        calls.append(args[-1])
        if args[-1]=="1,2,3":
            entered.set()
            assert release.wait(5)
        return original(*args)
    def graph_runner(*args,**kwargs):
        try:return original_graph(*args,**kwargs)
        finally:finished.set()
    monkeypatch.setattr(scheduler,"execute_capability",adapter)
    monkeypatch.setattr(scheduler,"execute_graph",graph_runner)
    try:
        with httpx2.Client(timeout=5,trust_env=False) as client:
            with client.stream("POST",live_server+PATH,headers=HEADERS,json={"nodes":graph()}) as response:
                lines=response.iter_lines()
                for line in lines:
                    if json.loads(line).get("state")=="running":break
                assert entered.wait(2)
            # Let the ASGI disconnect notification reach the generator.
            time.sleep(.3)
            release.set()
            assert finished.wait(5)
            assert calls==["1,2,3"]
    finally:release.set()
