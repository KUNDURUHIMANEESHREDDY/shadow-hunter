import pytest
from shadow_hunter.capability_catalog import discover_capabilities, matching_capabilities, enabled_names
from shadow_hunter.workflow_planner import plan_workflow
from shadow_hunter import workflow_planner as planner
from shadow_hunter.scheduler import DurableScheduler, execute_graph, validate_resource
from shadow_hunter.policy import Principal
from shadow_hunter.store import SQLiteStore


@pytest.fixture(autouse=True)
def default_catalog(monkeypatch):
    monkeypatch.delenv("SHADOW_HUNTER_ENABLED_CAPABILITIES",raising=False)


def test_catalog_metadata():
    catalog=discover_capabilities()
    assert len(catalog)==7
    assert all(item["read_only"] and item["input_kind"] for item in catalog)
    assert {item["name"] for item in catalog if item["external"]}=={"public_repo_metadata"}
    assert {item.name for item in matching_capabilities("Is Ollama online?")}=={"model_readiness"}


@pytest.mark.parametrize("objective,expected",[
    ("Is Ollama online?","model_readiness"),
    ("How many meters in 2 km?",None),
    ("Express 2 km in meters","unit_conversion"),
    ("Get star count for fastapi/fastapi","public_repo_metadata"),
    ("Analyze 1,2,3","numeric_summary"),
])
def test_catalog_driven_matching(objective,expected):
    result=plan_workflow(objective)
    assert [n["capability"] for n in result["nodes"]]==([expected] if expected else [])


def test_disabled_requested_tool_no_substitution(monkeypatch):
    monkeypatch.setenv("SHADOW_HUNTER_ENABLED_CAPABILITIES","numeric_summary")
    assert enabled_names()=={"numeric_summary"}
    assert [c["name"] for c in discover_capabilities()]==["numeric_summary"]
    assert plan_workflow("Summarize 1,2,3 then check Ollama status")["status"]=="clarify"
    assert plan_workflow("Summarize 1,2,3")["status"]=="preview"
    with pytest.raises(ValueError):
        validate_resource("model_readiness","local")


def test_model_intent_cannot_bypass_disable(monkeypatch):
    monkeypatch.setenv("SHADOW_HUNTER_ENABLED_CAPABILITIES","order_summary")
    monkeypatch.setattr(planner,"_select",lambda phase,candidates,deadline:[candidates[1]["id"]])
    result=plan_workflow("Could I get a refund for this purchase?","owned")
    assert result["status"]=="clarify" and result["nodes"]==[]


def test_invalid_configuration_fails_closed(monkeypatch):
    monkeypatch.setenv("SHADOW_HUNTER_ENABLED_CAPABILITIES","numeric_summary,arbitrary_shell")
    assert discover_capabilities()==[]
    assert plan_workflow("Summarize 1,2,3")["nodes"]==[]


def test_queued_job_and_graph_recheck_policy(tmp_path,monkeypatch):
    store=SQLiteStore(tmp_path/"catalog.sqlite")
    principal=Principal("s","t","c",True)
    queue=DurableScheduler(store)
    queue.enqueue(principal,"numeric_summary","1,2")
    graph=[{"id":"a","capability":"numeric_summary","resource":"1,2","depends_on":[]}]
    monkeypatch.setenv("SHADOW_HUNTER_ENABLED_CAPABILITIES","")
    assert queue.dispatch_next(principal,None)["status"]=="failed"
    with pytest.raises(ValueError):
        execute_graph(principal,None,graph)


def test_catalog_endpoint_authentication(tmp_path,monkeypatch):
    from fastapi.testclient import TestClient
    from shadow_hunter.api import create_app
    from shadow_hunter.auth import TokenAuthenticator
    monkeypatch.setenv("SHADOW_HUNTER_LOCAL_READONLY_ENABLED","true")
    monkeypatch.setenv("SHADOW_HUNTER_AUTH_MODE","local")
    monkeypatch.setenv("SHADOW_HUNTER_ENABLED_CAPABILITIES","numeric_summary")
    monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME",raising=False)
    auth=TokenAuthenticator(customer_tokens={"test":{"subject_id":"s","tenant_id":"t","customer_id":"c"}})
    with TestClient(create_app(store=SQLiteStore(tmp_path/"catalog.sqlite"),authenticator=auth)) as client:
        path="/v1/agent/local-capabilities"
        assert client.get(path).status_code==401
        result=client.get(path,headers={"Authorization":"Bearer test"})
        assert result.status_code==200
        assert [c["name"] for c in result.json()["capabilities"]]==["numeric_summary"]
