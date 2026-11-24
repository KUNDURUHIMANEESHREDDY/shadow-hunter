"""Explicit opt-in local-model test against a real isolated HTTP server."""
import json
import os
import urllib.request
import pytest
from .conftest import CUSTOMER_TOKEN, OWN_ORDER, OPERATOR_TOKEN

@pytest.fixture
def local_runtime_enabled(monkeypatch):
    monkeypatch.setenv("SHADOW_HUNTER_LOCAL_READONLY_ENABLED", "true")

def post(base, prompt):
    req = urllib.request.Request(
        base + "/v1/agent/local-readonly",
        data=json.dumps({"prompt": prompt, "order_id": OWN_ORDER}).encode(),
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + CUSTOMER_TOKEN},
    )
    with urllib.request.urlopen(req, timeout=45) as response:
        return json.load(response)

@pytest.mark.skipif(os.environ.get("RUN_LOCAL_QWEN_E2E") != "1", reason="Requires explicit local Ollama opt-in")
def test_local_runtime_live(local_runtime_enabled, local_server):
    for prompt, expected in [
        ("Show me the details of my order.", ["get_order"]),
        ("Check whether my order qualifies for a refund. Do not submit a refund.", ["check_refund_eligibility"]),
        ("Show my order details and check refund eligibility.", ["get_order", "check_refund_eligibility"]),
    ]:
        result = post(local_server, prompt)
        print(json.dumps({"prompt": prompt, "status": result["status"], "tools": [s["tool"] for s in result["steps"]]}), flush=True)
        assert result["model"] == "qwen3.5:0.8b"
        assert result["status"] == "completed"
        assert [s["tool"] for s in result["steps"]] == expected
        assert all(s["result"]["decision"] == "ALLOW" for s in result["steps"])
        audit_req = urllib.request.Request(local_server + "/v1/operator/audit", headers={"Authorization": "Bearer " + OPERATOR_TOKEN})
        with urllib.request.urlopen(audit_req, timeout=5) as response:
            audit = json.load(response)
        assert len([r for r in audit if r.get("trace_id") == result["trace_id"] and r.get("event_type") == "POLICY_DECISION"]) == len(expected)

@pytest.mark.skipif(os.environ.get("RUN_LOCAL_QWEN_E2E") != "1", reason="Requires explicit local Ollama opt-in")
def test_local_runtime_stream_live(local_runtime_enabled, local_server):
    tasks = [
        ("What are the details of my purchase?", ["get_order"]),
        ("Am I eligible to receive a refund? Just check.", ["check_refund_eligibility"]),
        ("Check my refund eligibility and show my order details.", ["get_order", "check_refund_eligibility"]),
    ]
    for prompt, expected in tasks:
        req=urllib.request.Request(local_server+"/v1/agent/local-readonly/stream",
            data=json.dumps({"prompt":prompt,"order_id":OWN_ORDER}).encode(),
            headers={"Content-Type":"application/json","Authorization":"Bearer "+CUSTOMER_TOKEN})
        with urllib.request.urlopen(req,timeout=60) as response:
            assert response.headers.get_content_type()=="application/x-ndjson"
            events=[json.loads(line) for line in response if line.strip()]
        assert events[0]["stage"]=="planning" and events[0]["status"]=="started"
        assert events[-1]["type"]=="result", events
        result=events[-1]["result"]
        print(json.dumps({"prompt":prompt,"status":result["status"],"tools":[s["tool"] for s in result["steps"]],"events":len(events)}),flush=True)
        assert result["status"]=="completed"
        assert [s["tool"] for s in result["steps"]]==expected
        assert result["verified_steps"]==len(expected)
        assert [e["tool"] for e in events if e.get("stage")=="tool" and e.get("status")=="verified"]==expected
        assert all(e.get("trace_id")==result["trace_id"] for e in events[:-1])


def test_local_runtime_stream_requires_auth(local_runtime_enabled, local_server):
    from urllib.error import HTTPError
    req=urllib.request.Request(local_server+"/v1/agent/local-readonly/stream",
        data=json.dumps({"prompt":"Show my order","order_id":OWN_ORDER}).encode(),
        headers={"Content-Type":"application/json"})
    with pytest.raises(HTTPError) as exc:
        urllib.request.urlopen(req, timeout=5)
    assert exc.value.code==401

def test_local_runtime_stream_validates_before_stream(local_runtime_enabled, local_server):
    from urllib.error import HTTPError
    req=urllib.request.Request(local_server+"/v1/agent/local-readonly/stream",
        data=json.dumps({"prompt":"","order_id":OWN_ORDER}).encode(),
        headers={"Content-Type":"application/json","Authorization":"Bearer "+CUSTOMER_TOKEN})
    with pytest.raises(HTTPError) as exc:
        urllib.request.urlopen(req, timeout=5)
    assert exc.value.code==422
"""Real browser checks for the local workspace. Opt-in requires local Qwen and Edge."""
import json
import os
import urllib.request
import pytest
from .conftest import CUSTOMER_TOKEN, FOREIGN_TOKEN, OWN_ORDER

@pytest.mark.skipif(os.environ.get("RUN_LOCAL_QWEN_E2E")!="1", reason="Explicit local Qwen opt-in")
def test_workspace_in_real_browser(page, local_runtime_enabled, local_server):
    from playwright.sync_api import expect
    page.goto(local_server+"/local-workspace")
    page.locator("#token").fill(CUSTOMER_TOKEN)
    page.locator("#connect").click()
    expect(page.locator("#status")).to_have_text("Connected to local account.")
    page.locator("#model-check").click()
    expect(page.locator("#model-status")).to_have_text("Local Qwen model detected.")
    expect(page.locator("#stop")).to_have_text("Request cancellation")
    expect(page.locator("#stop")).to_be_disabled()
    page.locator("#order").fill(OWN_ORDER)
    page.locator("#prompt").fill("Show my order details and check refund eligibility.")
    page.locator("#run").click()
    expect(page.locator("#activity")).to_contain_text("planning / started",timeout=10000)
    expect(page.locator("#status")).to_have_text("Task status: completed",timeout=60000)
    result=json.loads(page.locator("#result").inner_text())
    assert result["verified_steps"]==2
    expect(page.locator("#history")).to_contain_text(result["trace_id"],timeout=5000)
    expect(page.locator("#history")).to_contain_text("completed")
    assert page.evaluate("() => localStorage.length + sessionStorage.length")==0
    page.locator("#disconnect").click()
    expect(page.locator("#history")).to_be_empty()
    expect(page.locator("#result")).to_have_text("No result yet.")
    page.locator("#token").fill(FOREIGN_TOKEN)
    page.locator("#connect").click()
    expect(page.locator("#status")).to_have_text("Connected to local account.")
    expect(page.locator("#history")).to_be_empty()


@pytest.mark.skipif(os.environ.get("RUN_LOCAL_QWEN_E2E")!="1", reason="Explicit local Qwen opt-in")
def test_local_runtime_language_benchmark(local_runtime_enabled, local_server):
    cases = [
        ("Please show my order.", ["get_order"]),
        ("Which currency is my order in?", ["get_order"]),
        ("What is the remaining refundable balance on my order?", ["get_order"]),
        ("Can this order be refunded?", ["check_refund_eligibility"]),
        ("Check if a refund is available, without making changes.", ["check_refund_eligibility"]),
        ("Am I eligible for a refund on this purchase?", ["check_refund_eligibility"]),
        ("Please retrieve my order and confirm whether a refund is possible.", ["get_order","check_refund_eligibility"]),
        ("Show my purchase details and check if it can be refunded.", ["get_order","check_refund_eligibility"]),
        ("Show the order currency and check refund eligibility.", ["get_order","check_refund_eligibility"]),
        ("Explain what a prime number is.", []),
        ("Tell me a joke.", []),
        ("Write a poem about a tree.", []),
    ]
    outcomes=[]
    exact=[]
    for prompt, expected in cases:
        try:
            r=post(local_server,prompt)
            actual=[s["tool"] for s in r["steps"]]
            strict=(r["status"]=="completed" and actual==expected and r["verified_steps"]==len(expected)) if expected else (r["status"]=="unsupported" and not actual)
            ok=strict if expected else (r["status"] in {"unsupported","clarify"} and not actual and r["verified_steps"]==0)
            exact.append(strict)
            outcomes.append(ok)
            print(json.dumps({"task":prompt,"status":r["status"],"expected":expected,"actual":actual,"workflow_pass":ok,"exact_intent_pass":strict}),flush=True)
        except Exception as exc:
            outcomes.append(False)
            exact.append(False)
            print(json.dumps({"task":prompt,"error":type(exc).__name__,"pass":False}),flush=True)
    print("WORKFLOW BENCHMARK: "+str(sum(outcomes))+"/"+str(len(outcomes)),flush=True)
    print("EXACT INTENT BENCHMARK: "+str(sum(exact))+"/"+str(len(exact)),flush=True)
    assert all(outcomes)


@pytest.mark.skipif(os.environ.get("RUN_LOCAL_QWEN_E2E") != "1", reason="Explicit local Qwen opt-in")
def test_local_support_intent_boundary_live(local_runtime_enabled, local_server):
    cases = [
        ("Which currency was my purchase in?", ["get_order"]),
        ("How much is left to refund on my purchase?", ["get_order"]),
        ("Please retrieve my order information.", ["get_order"]),
        ("Does my purchase qualify for a refund?", ["check_refund_eligibility"]),
        ("Could this order be refunded? Only check.", ["check_refund_eligibility"]),
        ("Tell me if a refund is available.", ["check_refund_eligibility"]),
        ("Show my purchase details and whether a refund is possible.", ["get_order", "check_refund_eligibility"]),
        ("Which currency is my order in, and am I eligible for a refund?", ["get_order", "check_refund_eligibility"]),
        ("Explain photosynthesis.", []),
        ("Write a short poem.", []),
        ("Cancel my order.", []),
        ("Submit a refund now.", []),
    ]
    outcomes = []
    for prompt, expected in cases:
        result = post(local_server, prompt)
        actual = [step["tool"] for step in result["steps"]]
        ok = actual == expected and (result["status"] == "completed" if expected else
                                     result["status"] in {"unsupported", "clarify"})
        outcomes.append(ok)
        print(json.dumps({"prompt": prompt, "status": result["status"],
                          "expected": expected, "actual": actual, "pass": ok}), flush=True)
    print(f"SUPPORT BOUNDARY BENCHMARK: {sum(outcomes)}/{len(outcomes)}", flush=True)
    assert all(outcomes)


def test_model_readiness_requires_auth(local_runtime_enabled, local_server):
    from urllib.error import HTTPError
    req = urllib.request.Request(local_server + "/v1/agent/local-readonly/readiness")
    with pytest.raises(HTTPError) as exc:
        urllib.request.urlopen(req, timeout=5)
    assert exc.value.code == 401


@pytest.mark.skipif(os.environ.get("RUN_LOCAL_QWEN_E2E") != "1", reason="Explicit local Qwen opt-in")
def test_model_readiness_live(local_runtime_enabled, local_server):
    req = urllib.request.Request(
        local_server + "/v1/agent/local-readonly/readiness",
        headers={"Authorization": "Bearer " + CUSTOMER_TOKEN},
    )
    with urllib.request.urlopen(req, timeout=5) as response:
        assert response.headers.get("Cache-Control") == "no-store"
        assert json.load(response) == {"model": "qwen3.5:0.8b", "status": "ready", "ready": True}


def test_durable_queue_browser(page, local_runtime_enabled, local_server):
    from playwright.sync_api import expect
    page.goto(local_server+"/local-workspace")
    page.locator("#token").fill(CUSTOMER_TOKEN)
    page.locator("#connect").click()
    expect(page.locator("#status")).to_have_text("Connected to local account.")
    page.locator("#order").fill(OWN_ORDER)
    page.locator("#job-add").click()
    expect(page.locator("#jobs-list")).to_contain_text("queued")
    page.locator("#job-capability").select_option("refund_status")
    page.locator("#job-add").click()
    expect(page.locator("#jobs-list tr")).to_have_count(2)
    page.locator("#jobs-run").click()
    expect(page.locator("#jobs-list tr").filter(has_text="completed")).to_have_count(2)
    expect(page.locator("#jobs-result")).to_contain_text("verified_steps")
    page.locator("#disconnect").click()
    expect(page.locator("#jobs-list tr")).to_have_count(0)
    expect(page.locator("#jobs-result")).to_be_empty()


def test_automatic_utility_job_browser(page,local_runtime_enabled,local_server):
    from playwright.sync_api import expect
    page.goto(local_server+"/local-workspace")
    page.locator("#token").fill(CUSTOMER_TOKEN)
    page.locator("#connect").click()
    expect(page.locator("#status")).to_have_text("Connected to local account.")
    page.locator("#job-capability").select_option("numeric_summary")
    page.locator("#numeric-input").fill("1,2,3")
    page.locator("#job-delay").select_option("0")
    page.locator("#job-add").click()
    expect(page.locator("#jobs-list tr")).to_have_count(1)
    for _ in range(10):
        page.locator("#jobs-refresh").click()
        page.wait_for_timeout(300)
        if "completed" in page.locator("#jobs-list").inner_text(): break
    expect(page.locator("#jobs-list")).to_contain_text("completed")
    page.locator("#disconnect").click()
    expect(page.locator("#numeric-input")).to_have_value("")


def test_workflow_builder_browser(page,local_runtime_enabled,local_server):
    from playwright.sync_api import expect
    page.goto(local_server+"/local-workspace")
    page.locator("#token").fill(CUSTOMER_TOKEN)
    page.locator("#connect").click()
    expect(page.locator("#status")).to_have_text("Connected to local account.")
    page.locator("#workflow-example").click()
    page.locator("#workflow-run").click()
    expect(page.locator("#workflow-result")).to_contain_text('"value": "2000"')
    page.locator("#disconnect").click()
    expect(page.locator("#workflow-result")).to_be_empty()


def test_natural_language_workflow_preview_browser(page,local_runtime_enabled,local_server):
    from playwright.sync_api import expect
    page.goto(local_server+"/local-workspace")
    page.locator("#token").fill(CUSTOMER_TOKEN)
    page.locator("#connect").click()
    expect(page.locator("#status")).to_have_text("Connected to local account.")
    page.locator("#workflow-objective").fill("Summarize 1,2,3 then convert 2 km to m")
    page.locator("#workflow-plan").click()
    expect(page.locator("#workflow-plan-status")).to_contain_text("No tools were executed.")
    assert json.loads(page.locator("#workflow-nodes").input_value())[1]["depends_on"]==["n1"]
    expect(page.locator("#workflow-result")).to_be_empty()
    page.locator("#workflow-run").click()
    expect(page.locator("#workflow-result")).to_contain_text('"value": "2000"')
    page.locator("#disconnect").click()
    expect(page.locator("#workflow-objective")).to_have_value("")


def test_capability_catalog_browser(page,local_runtime_enabled,local_server):
    from playwright.sync_api import expect
    page.goto(local_server+"/local-workspace")
    page.locator("#token").fill(CUSTOMER_TOKEN)
    page.locator("#connect").click()
    expect(page.locator("#capability-summary")).to_contain_text("Numeric summary")
    expect(page.locator("#job-capability option")).to_have_count(7)
    expect(page.locator("#job-add")).to_be_enabled()
    page.locator("#disconnect").click()
    expect(page.locator("#job-capability option")).to_have_count(0)
    expect(page.locator("#job-add")).to_be_disabled()


def test_workflow_recovery_report_browser(page,local_runtime_enabled,local_server):
    from playwright.sync_api import expect
    page.goto(local_server+"/local-workspace")
    page.locator("#token").fill(CUSTOMER_TOKEN)
    page.locator("#connect").click()
    expect(page.locator("#status")).to_have_text("Connected to local account.")
    page.locator("#workflow-example").click()
    page.locator("#workflow-run").click()
    expect(page.locator("#workflow-result")).to_contain_text('"recovery"')
    result=json.loads(page.locator("#workflow-result").inner_text())
    assert result["status"]=="completed"
    assert result["recovery"]["retries"]==0
    assert all(value==1 for value in result["recovery"]["attempts"].values())
    assert result["recovery"]["revisions"][-1]["remaining"]=={}


def test_mcp_discovery_disabled_browser(page,local_runtime_enabled,local_server):
    from playwright.sync_api import expect
    page.goto(local_server+"/local-workspace")
    page.locator("#token").fill(CUSTOMER_TOKEN)
    page.locator("#connect").click()
    expect(page.locator("#status")).to_have_text("Connected to local account.")
    page.locator("#mcp-discover").click()
    expect(page.locator("#mcp-discovery-status")).to_have_text("MCP companion: disabled")
    page.locator("#disconnect").click()
    expect(page.locator("#mcp-discovery-status")).to_be_empty()
    expect(page.locator("#mcp-discover")).to_be_disabled()
