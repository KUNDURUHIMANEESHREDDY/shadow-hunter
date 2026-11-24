"""Regression coverage for bounded planning and independently verified reads."""
from unittest.mock import Mock
import pytest
from shadow_hunter import local_runtime as rt
from shadow_hunter.approvals import ApprovalService
from shadow_hunter.gateway import ToolGateway
from shadow_hunter.policy import PolicyEngine, Principal
from shadow_hunter.store import SQLiteStore

@pytest.fixture
def runtime(tmp_path):
    store = SQLiteStore(tmp_path / "readonly.sqlite3")
    store.add_order(order_id="sample-order", tenant_id="sample-tenant",
                    customer_id="sample-customer", currency="USD", refundable_minor=1000)
    gateway = ToolGateway(store, PolicyEngine(), ApprovalService(store, ttl_seconds=600))
    return gateway, Principal("sample-subject", "sample-tenant", "sample-customer", True)

def test_runtime_plan_allowlist():
    assert set(sum(rt.PLANS.values(), ())) == {"get_order", "check_refund_eligibility"}

def test_invalid_plan_stops_before_gateway(monkeypatch, runtime):
    gateway, principal = runtime
    invoke = Mock()
    monkeypatch.setattr(gateway, "invoke", invoke)
    monkeypatch.setattr(rt, "plan_readonly_task", lambda prompt: "write")
    with pytest.raises(rt.LocalRuntimeError):
        rt.run_readonly_task(gateway, principal, prompt="view", order_id="sample-order")
    invoke.assert_not_called()

def test_supported_plan_uses_explicit_order_and_shared_trace(monkeypatch, runtime):
    gateway, principal = runtime
    monkeypatch.setattr(rt, "plan_readonly_task", lambda prompt: "both")
    result = rt.run_readonly_task(gateway, principal, prompt="view and check", order_id="sample-order")
    assert result["status"] == "completed"
    assert result["verified_steps"] == 2
    assert [s["tool"] for s in result["steps"]] == list(rt.PLANS["both"])
    assert all(s["verified"] for s in result["steps"])
    events = [e for e in gateway.store.get_trace_events(result["trace_id"]) if e["event_type"]=="POLICY_DECISION"]
    assert len(events) == 2 and events[0]["request_id"] != events[1]["request_id"]
    assert all(e["resource_id"] == "sample-order" and e["actor_id"] == principal.subject_id for e in events)

def test_denied_step_stops_runtime(monkeypatch, runtime):
    gateway, principal = runtime
    monkeypatch.setattr(rt, "plan_readonly_task", lambda prompt: "both")
    result = rt.run_readonly_task(gateway, principal, prompt="view and check", order_id="missing-order")
    assert result["status"] == "denied"
    assert len(result["steps"]) == 1
    assert result["steps"][0]["result"]["reason_code"] == "RESOURCE_NOT_AVAILABLE"

@pytest.mark.parametrize("intent", ["unsupported", "clarify"])
def test_nonexecution_intent(monkeypatch, runtime, intent):
    gateway, principal = runtime
    invoke = Mock()
    monkeypatch.setattr(gateway, "invoke", invoke)
    monkeypatch.setattr(rt, "plan_readonly_task", lambda prompt: intent)
    result = rt.run_readonly_task(gateway, principal, prompt="unrelated task", order_id="sample-order")
    assert result["status"] == intent and result["verified_steps"] == 0
    invoke.assert_not_called()

def test_disagreement_stops_plan(monkeypatch):
    classifier = Mock(side_effect=["order_details", "both"])
    monkeypatch.setattr(rt, "_classify", classifier)
    assert rt.plan_readonly_task("ambiguous") == "clarify"
    assert classifier.call_count == 2

@pytest.mark.parametrize("mode", ["missing", "duplicate", "mismatch"])
def test_invalid_evidence_never_completes(monkeypatch, runtime, mode):
    gateway, principal = runtime
    real = gateway.store.get_trace_events
    def altered(trace):
        events = real(trace)
        if mode == "missing": return []
        if mode == "duplicate": return events + events
        return [{**event, "actor_id": "not-the-caller"} for event in events]
    monkeypatch.setattr(gateway.store, "get_trace_events", altered)
    monkeypatch.setattr(rt, "plan_readonly_task", lambda prompt: "both")
    with pytest.raises(rt.LocalRuntimeError, match="evidence"):
        rt.run_readonly_task(gateway, principal, prompt="view and check", order_id="sample-order")

def test_unauthenticated_does_not_call_model(monkeypatch, runtime):
    gateway, _ = runtime
    planner = Mock()
    monkeypatch.setattr(rt, "plan_readonly_task", planner)
    with pytest.raises(rt.LocalRuntimeError):
        rt.run_readonly_task(gateway, Principal(None,None,None,False), prompt="view", order_id="sample-order")
    planner.assert_not_called()


def test_model_invalid_json_retry(monkeypatch):
    import json
    import time
    from unittest.mock import MagicMock
    def response(content):
        obj = MagicMock()
        obj.__enter__.return_value.read.return_value = json.dumps({
            "model": rt.MODEL, "done": True, "message": {"content": content}
        }).encode()
        return obj
    opener = Mock()
    opener.open.side_effect = [response("not-json"), response('{"intent":"both"}')]
    monkeypatch.setattr(rt.urllib.request, "build_opener", lambda *args: opener)
    assert rt._classify("view both", review=False, deadline=time.monotonic()+30) == "both"
    assert opener.open.call_count == 2

def test_model_unavailable_does_not_retry(monkeypatch):
    import time
    opener = Mock()
    opener.open.side_effect = OSError("offline")
    monkeypatch.setattr(rt.urllib.request, "build_opener", lambda *args: opener)
    with pytest.raises(rt.LocalRuntimeError, match="unavailable"):
        rt._classify("view", review=False, deadline=time.monotonic()+30)
    assert opener.open.call_count == 1

def test_expired_plan_does_not_call_model(monkeypatch):
    import time
    build = Mock()
    monkeypatch.setattr(rt.urllib.request, "build_opener", build)
    with pytest.raises(rt.LocalRuntimeError, match="deadline"):
        rt._classify("view", review=False, deadline=time.monotonic()-1)
    build.assert_not_called()

def test_stream_progress_before_model_and_tools(monkeypatch, runtime):
    gateway, principal = runtime
    planner = Mock(return_value="both")
    monkeypatch.setattr(rt, "plan_readonly_task", planner)
    stream = rt.iter_readonly_task(gateway, principal, prompt="view and check", order_id="sample-order")
    first = next(stream)
    assert first["type"] == "progress" and first["status"] == "started"
    planner.assert_not_called()
    reviewed = next(stream)
    assert reviewed["plan"] == list(rt.PLANS["both"])
    first_tool = next(stream)
    assert first_tool["status"] == "started"
    assert not gateway.store.get_trace_events(first["trace_id"])
    done = next(stream)
    assert done["status"] == "verified"
    rest = list(stream)
    result = rest[-1]["result"]
    assert result["status"] == "completed" and result["verified_steps"] == 2

def test_stream_failure_never_yields_completed(monkeypatch, runtime):
    gateway, principal = runtime
    monkeypatch.setattr(rt, "plan_readonly_task", lambda prompt: "both")
    monkeypatch.setattr(gateway.store, "get_trace_events", lambda trace: [])
    stream = rt.iter_readonly_task(gateway, principal, prompt="view and check", order_id="sample-order")
    seen=[]
    with pytest.raises(rt.LocalRuntimeError):
        while True:
            seen.append(next(stream))
    assert not any(e["type"] == "result" for e in seen)
