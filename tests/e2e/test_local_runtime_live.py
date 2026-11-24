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
