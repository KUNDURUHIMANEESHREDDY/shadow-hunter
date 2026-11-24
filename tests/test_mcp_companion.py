import os
import socket
import threading
import time
from types import SimpleNamespace
import pytest
from shadow_hunter import mcp_client as client, scheduler, mcp_companion as companion
from shadow_hunter.capability_catalog import discover_capabilities
from shadow_hunter.policy import Principal
from shadow_hunter.workflow_planner import plan_workflow

P=Principal("synthetic","demo","demo",True)

@pytest.fixture(autouse=True)
def settings(monkeypatch):
    monkeypatch.delenv("SHADOW_HUNTER_ENABLED_CAPABILITIES",raising=False)
    monkeypatch.setenv("SHADOW_HUNTER_MCP_COMPANION_ENABLED","true")

def tool(name,arg):
    return SimpleNamespace(name=name,input_schema={"type":"object","properties":{arg:{"type":"string"}},"required":[arg]})

def listing(*tools,next_cursor=None):
    return SimpleNamespace(tools=list(tools),next_cursor=next_cursor)

def test_discovery_pins_names_and_schema():
    good=tool("public_package","package")
    unknown=tool("arbitrary_command","command")
    wrong=tool("public_repository","url")
    assert client.approved_discovery(listing(good,unknown,wrong))=={"mcp_public_package":("public_package","package")}
    good.input_schema["properties"]["extra"]={"type":"string"}
    assert client.approved_discovery(listing(good))=={}

def test_discovery_rejects_duplicate_and_unbounded_pages():
    good=tool("public_package","package")
    with pytest.raises(ValueError):
        client.approved_discovery(listing(good,good))
    with pytest.raises(ValueError):
        client.approved_discovery(listing(good,next_cursor="next"))

@pytest.mark.parametrize("payload",[
    {"status":"completed","package":"wrong","version":"1.0"},
    {"status":"completed","package":"requests","version":"1.0","command":"extra"},
    {"status":"completed","package":"requests","version":"unexpected text"},
    {"status":"failed","package":"requests","version":"1.0"},
])
def test_unverified_result_rejected(payload):
    with pytest.raises(ValueError):
        client.verify_result("mcp_public_package","requests",SimpleNamespace(is_error=False,structured_content=payload))

def test_unstructured_and_error_results_rejected():
    for result in (SimpleNamespace(is_error=False,structured_content=None),
                   SimpleNamespace(is_error=True,structured_content={"status":"completed","package":"requests","version":"1.0"})):
        with pytest.raises(ValueError):
            client.verify_result("mcp_public_package","requests",result)

def test_package_result_identity_and_types():
    result=SimpleNamespace(is_error=False,structured_content={"status":"completed","package":"requests","version":"1.0"})
    assert client.verify_result("mcp_public_package","requests",result)["provider"]=="mcp_companion"
    repo=SimpleNamespace(is_error=False,structured_content={"status":"completed","repository":"python/cpython","stars":True,"forks":1,"default_branch":"main"})
    with pytest.raises(ValueError):
        client.verify_result("mcp_repo_metadata","python/cpython",repo)

def test_companion_opt_in_and_capability_restrictions(monkeypatch):
    assert len(discover_capabilities())==9
    assert plan_workflow("Get PyPI version for requests")["nodes"][0]["capability"]=="mcp_public_package"
    assert plan_workflow("Get GitHub stars for python/cpython via MCP")["nodes"][0]["capability"]=="mcp_repo_metadata"
    assert plan_workflow("Get GitHub stars for python/cpython")["nodes"][0]["capability"]=="public_repo_metadata"
    monkeypatch.setenv("SHADOW_HUNTER_MCP_COMPANION_ENABLED","false")
    assert len(discover_capabilities())==7
    assert plan_workflow("Get PyPI version for requests")["status"]=="clarify"
    with pytest.raises(ValueError): client.invoke("mcp_public_package","requests")

def test_reject_unapproved_inputs(monkeypatch):
    def fail(*args): pytest.fail("Unapproved input reached MCP transport")
    monkeypatch.setattr(client,"_run",fail)
    for cap,resource in [("mcp_public_package","https://example.com"),("mcp_repo_metadata","unknown/repo")]:
        with pytest.raises(ValueError): client.invoke(cap,resource)

def test_disabled_after_plan(monkeypatch):
    nodes=plan_workflow("Get PyPI version for requests")["nodes"]
    monkeypatch.setenv("SHADOW_HUNTER_ENABLED_CAPABILITIES","numeric_summary")
    with pytest.raises(ValueError):
        scheduler.execute_graph(P,None,nodes)

@pytest.fixture
def running_companion(monkeypatch):
    import uvicorn
    from shadow_hunter import result_verifier
    monkeypatch.setattr(result_verifier,"package_evidence",lambda package:{"package":package,"version":"1.2.3"})
    monkeypatch.setattr(result_verifier,"repository_evidence",lambda repo:{"repository":repo,"stars":10,"forks":2,"default_branch":"main"})
    monkeypatch.setattr(companion,"read_package",lambda package:{"status":"completed","package":package,"version":"1.2.3"})
    monkeypatch.setattr(scheduler,"public_repo_metadata",lambda repo:{"status":"completed","repository":repo,"stars":10,"forks":2,"default_branch":"main"})
    sock=socket.socket()
    sock.bind(("127.0.0.1",0))
    port=sock.getsockname()[1]
    sock.listen(16)
    monkeypatch.setattr(client,"ENDPOINT",f"http://127.0.0.1:{port}/mcp")
    _,app=companion.create_companion()
    server=uvicorn.Server(uvicorn.Config(app,log_level="error",access_log=False))
    thread=threading.Thread(target=server.run,kwargs={"sockets":[sock]},daemon=True)
    thread.start()
    try:
        for _ in range(100):
            if server.started: break
            time.sleep(.02)
        assert server.started
        yield
    finally:
        server.should_exit=True
        thread.join(5)
        sock.close()
        assert not thread.is_alive()

def test_real_mcp_transport_discovery_and_execution(running_companion):
    assert client.discover()==["mcp_public_package","mcp_repo_metadata"]
    plan=plan_workflow("Get PyPI package version for requests and get GitHub stars for python/cpython via MCP then convert 2 km to m")
    result=scheduler.execute_graph(P,None,plan["nodes"])
    assert result["status"]=="completed"
    assert result["nodes"]["n1"]["version"]=="1.2.3"
    assert result["nodes"]["n2"]["provider"]=="mcp_companion"
    assert result["nodes"]["n3"]["value"]=="2000"

def test_mcp_unavailable_blocks_dependents(monkeypatch):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1",0))
        port=sock.getsockname()[1]
        monkeypatch.setattr(client,"ENDPOINT",f"http://127.0.0.1:{port}/mcp")
        plan=plan_workflow("Get PyPI version for requests then convert 2 km to m")
        result=scheduler.execute_graph(P,None,plan["nodes"])
    assert result["status"]=="incomplete"
    assert result["nodes"]["n1"]["status"]=="failed"
    assert result["nodes"]["n2"]["status"]=="blocked"

def test_discovery_endpoint(tmp_path,monkeypatch,running_companion):
    from fastapi.testclient import TestClient
    from shadow_hunter.api import create_app
    from shadow_hunter.store import SQLiteStore
    from shadow_hunter.auth import TokenAuthenticator
    monkeypatch.setenv("SHADOW_HUNTER_LOCAL_READONLY_ENABLED","true")
    monkeypatch.setenv("SHADOW_HUNTER_AUTH_MODE","local")
    monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME",raising=False)
    auth=TokenAuthenticator(customer_tokens={"test":{"subject_id":"s","tenant_id":"t","customer_id":"c"}})
    with TestClient(create_app(store=SQLiteStore(tmp_path/"mcp.sqlite"),authenticator=auth)) as api:
        path="/v1/agent/local-mcp-tools"
        assert api.get(path).status_code==401
        res=api.get(path,headers={"Authorization":"Bearer test"})
        assert res.json()=={"status":"ready","capabilities":["mcp_public_package","mcp_repo_metadata"]}
        monkeypatch.setenv("SHADOW_HUNTER_MCP_COMPANION_ENABLED","false")
        assert api.get(path,headers={"Authorization":"Bearer test"}).json()["status"]=="disabled"
