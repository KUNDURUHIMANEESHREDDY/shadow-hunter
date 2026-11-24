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
    opener.open.side_effect = [response("not-json"), response('{"reads":["order_details","refund_eligibility"]}')]
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

def test_tracked_history_persists_and_is_account_scoped(monkeypatch, runtime):
    from shadow_hunter.store import SQLiteStore
    from shadow_hunter.policy import Principal
    gateway, principal = runtime
    monkeypatch.setattr(rt, "plan_readonly_task", lambda prompt: "both")
    events=list(rt.tracked_readonly_task(gateway, principal, prompt="view and check", order_id="sample-order"))
    result=events[-1]["result"]
    reopened=SQLiteStore(gateway.store.database_path)
    rows=reopened.list_local_tasks(principal)
    assert len(rows)==1 and rows[0]["trace_id"]==result["trace_id"]
    assert rows[0]["status"]=="completed" and rows[0]["verified_steps"]==2
    assert set(rows[0])=={"trace_id","status","verified_steps","created_at","updated_at"}
    assert reopened.list_local_tasks(Principal("other-subject",principal.tenant_id,principal.customer_id,True))==[]
    assert reopened.list_local_tasks(Principal(principal.subject_id,"other-tenant",principal.customer_id,True))==[]

def test_tracked_history_interrupted(monkeypatch, runtime):
    gateway, principal = runtime
    planner=Mock(return_value="both")
    monkeypatch.setattr(rt, "plan_readonly_task", planner)
    stream=rt.tracked_readonly_task(gateway, principal, prompt="view and check", order_id="sample-order")
    first=next(stream)
    assert gateway.store.list_local_tasks(principal)[0]["status"]=="running"
    stream.close()
    planner.assert_not_called()
    row=gateway.store.list_local_tasks(principal)[0]
    assert row["trace_id"]==first["trace_id"] and row["status"]=="interrupted"

def test_tracked_history_failure(monkeypatch, runtime):
    gateway, principal=runtime
    monkeypatch.setattr(rt,"plan_readonly_task", Mock(side_effect=rt.LocalRuntimeError("offline")))
    with pytest.raises(rt.LocalRuntimeError):
        list(rt.tracked_readonly_task(gateway,principal,prompt="view",order_id="sample-order"))
    row=gateway.store.list_local_tasks(principal)[0]
    assert row["status"]=="failed" and row["verified_steps"]==0


def test_compound_coverage_guard_stops_partial_plan(monkeypatch):
    monkeypatch.setattr(rt, "_classify", Mock(return_value="order_details"))
    assert rt.plan_readonly_task("Show my purchase details and check if it can be refunded.")=="clarify"

def test_verified_answer_uses_gateway_data(monkeypatch,runtime):
    gateway,principal=runtime
    monkeypatch.setattr(rt,"plan_readonly_task",lambda prompt:"both")
    result=rt.run_readonly_task(gateway,principal,prompt="view and check",order_id="sample-order")
    assert "1000 minor units (USD)" in result["answer"]
    assert "eligible" in result["answer"]


def test_inconsistent_compound_read_recovers_once(monkeypatch, runtime):
    gateway, principal = runtime
    monkeypatch.setattr(rt, "plan_readonly_task", lambda prompt: "both")
    invoke = gateway.invoke
    calls = []

    def changed(**kwargs):
        result = invoke(**kwargs)
        calls.append(kwargs)
        if len(calls) == 2:
            result["eligibility"]["refundable_minor"] = 999
        return result

    monkeypatch.setattr(gateway, "invoke", changed)
    events = list(rt.iter_readonly_task(gateway, principal,
                                       prompt="view and check", order_id="sample-order"))
    result = events[-1]["result"]
    assert result["status"] == "completed"
    assert result["verified_steps"] == 2
    assert result["steps"][1]["result"]["eligibility"]["refundable_minor"] == 1000
    assert len(calls) == 4
    assert len({c["request_id"] for c in calls}) == 4
    assert {c["trace_id"] for c in calls} == {result["trace_id"]}
    assert all(c["arguments"] == {"order_id": "sample-order"} for c in calls)
    assert sum(e.get("stage") == "recovery" for e in events) == 1
    audit = [e for e in gateway.store.get_trace_events(result["trace_id"])
             if e["event_type"] == "POLICY_DECISION"]
    assert len(audit) == 4


def test_persistent_inconsistency_fails_after_one_recovery(monkeypatch, runtime):
    gateway, principal = runtime
    monkeypatch.setattr(rt, "plan_readonly_task", lambda prompt: "both")
    invoke = gateway.invoke
    calls = []

    def changed(**kwargs):
        result = invoke(**kwargs)
        calls.append(kwargs)
        if kwargs["tool_name"] == "check_refund_eligibility":
            result["eligibility"]["refundable_minor"] = 999
        return result

    monkeypatch.setattr(gateway, "invoke", changed)
    with pytest.raises(rt.LocalRuntimeError, match="bounded recovery"):
        list(rt.tracked_readonly_task(gateway, principal,
                                      prompt="view and check", order_id="sample-order"))
    assert len(calls) == 4
    assert gateway.store.list_local_tasks(principal)[0]["status"] == "failed"


def test_denial_and_evidence_failure_never_retry(monkeypatch, runtime):
    gateway, principal = runtime
    monkeypatch.setattr(rt, "plan_readonly_task", lambda prompt: "both")
    invoke = Mock(wraps=gateway.invoke)
    monkeypatch.setattr(gateway, "invoke", invoke)
    result = rt.run_readonly_task(gateway, principal,
                                  prompt="view and check", order_id="missing-order")
    assert result["status"] == "denied"
    assert invoke.call_count == 1
    invoke.reset_mock()
    monkeypatch.setattr(gateway.store, "get_trace_events", lambda trace: [])
    with pytest.raises(rt.LocalRuntimeError, match="evidence"):
        rt.run_readonly_task(gateway, principal,
                             prompt="view and check", order_id="sample-order")
    assert invoke.call_count == 1


@pytest.mark.parametrize("payload, expected", [
    ({"reads": []}, "unsupported"),
    ({"reads": ["order_details"]}, "order_details"),
    ({"reads": ["refund_eligibility"]}, "refund_eligibility"),
    ({"reads": ["refund_eligibility", "order_details"]}, "both"),
])
def test_structured_read_proposal(payload, expected):
    assert rt._proposal_intent(payload) == expected


@pytest.mark.parametrize("payload", [
    {"reads": ["write"]}, {"reads": ["order_details", "order_details"]},
    {"reads": ["order_details"], "arguments": {"order_id": "other"}},
    {"reads": "order_details"}, {"reads": [True]}, {"reads": [[]]},
    {"intent": "both"}, {"reads": ["order_details", "refund_eligibility", "order_details"]},
])
def test_malformed_read_proposals_rejected(payload):
    with pytest.raises(ValueError):
        rt._proposal_intent(payload)


def test_compiled_dependencies_are_server_owned(monkeypatch, runtime):
    gateway, principal = runtime
    monkeypatch.setattr(rt, "plan_readonly_task", lambda prompt: "both")
    result = rt.run_readonly_task(gateway, principal, prompt="view and check", order_id="sample-order")
    assert result["workflow"] == [
        {"id": "get_order", "depends_on": []},
        {"id": "check_refund_eligibility", "depends_on": ["get_order"]},
    ]
    assert result["verified_steps"] == 2
    assert rt.support_workflow("clarify") == []
    assert rt.support_workflow("refund_eligibility") == [
        {"id": "check_refund_eligibility", "depends_on": []}
    ]


def test_unverified_dependency_stops_before_invocation(monkeypatch, runtime):
    gateway, principal = runtime
    monkeypatch.setattr(rt, "plan_readonly_task", lambda prompt: "both")
    monkeypatch.setattr(rt, "support_workflow", lambda intent: [
        {"id": "get_order", "depends_on": ["check_refund_eligibility"]}
    ])
    invoke = Mock()
    monkeypatch.setattr(gateway, "invoke", invoke)
    with pytest.raises(rt.LocalRuntimeError, match="dependency"):
        rt.run_readonly_task(gateway, principal, prompt="view and check", order_id="sample-order")
    invoke.assert_not_called()


@pytest.mark.parametrize("prompt", [
    "Submit a refund now.", "Please issue my refund.", "Cancel my order.",
    "Refund this purchase.", "Process the refund.", "Approve a refund.",
])
def test_explicit_mutation_stops_before_model_or_gateway(monkeypatch, runtime, prompt):
    gateway, principal = runtime
    classifier = Mock()
    invoke = Mock()
    monkeypatch.setattr(rt, "_classify", classifier)
    monkeypatch.setattr(gateway, "invoke", invoke)
    result = rt.run_readonly_task(gateway, principal, prompt=prompt, order_id="sample-order")
    assert result["status"] == "unsupported"
    assert result["verified_steps"] == 0
    classifier.assert_not_called()
    invoke.assert_not_called()


@pytest.mark.parametrize("prompt", [
    "Check whether my order qualifies for a refund. Do not submit a refund.",
    "Can this order be refunded?", "Please check refund eligibility.",
])
def test_read_questions_remain_available(monkeypatch, prompt):
    classifier = Mock(return_value="refund_eligibility")
    monkeypatch.setattr(rt, "_classify", classifier)
    assert rt.plan_readonly_task(prompt) == "refund_eligibility"
    assert classifier.call_count == 2


@pytest.mark.parametrize("balance, eligible, expected", [
    (1000, True, "eligible under the recorded rules"),
    (0, True, "No refundable balance remains"),
    (1000, False, "specific reason is not available"),
])
def test_eligibility_explanation_uses_only_verified_fields(monkeypatch, runtime, balance, eligible, expected):
    gateway, principal = runtime
    gateway.store.add_order(order_id="sample-order", tenant_id=principal.tenant_id,
                            customer_id=principal.customer_id, currency="USD",
                            refundable_minor=balance, refund_eligible=eligible)
    monkeypatch.setattr(rt, "plan_readonly_task", lambda prompt: "refund_eligibility")
    result = rt.run_readonly_task(gateway, principal, prompt="why eligible?", order_id="sample-order")
    assert result["status"] == "completed"
    assert expected in result["answer"]
    assert result["verified_steps"] == 1


def test_impossible_eligibility_cannot_complete(monkeypatch, runtime):
    gateway, principal = runtime
    original = gateway.invoke
    def inconsistent(**kwargs):
        result = original(**kwargs)
        result["eligibility"]["refundable_minor"] = 0
        return result
    monkeypatch.setattr(gateway, "invoke", inconsistent)
    monkeypatch.setattr(rt, "plan_readonly_task", lambda prompt: "refund_eligibility")
    with pytest.raises(rt.LocalRuntimeError, match="Inconsistent eligibility"):
        rt.run_readonly_task(gateway, principal, prompt="check eligibility", order_id="sample-order")


def test_overlapping_independent_support_reads_preserve_account_isolation(monkeypatch, runtime):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    gateway, first = runtime
    second = Principal("second-subject", "second-tenant", "second-customer", True)
    gateway.store.add_order(order_id="second-order", tenant_id=second.tenant_id,
                            customer_id=second.customer_id, currency="EUR", refundable_minor=700)
    monkeypatch.setattr(rt, "plan_readonly_task", lambda prompt: "both")
    original = gateway.invoke
    barrier = Barrier(2, timeout=10)
    def overlapping(**kwargs):
        if kwargs["tool_name"] == "get_order":
            barrier.wait()
        return original(**kwargs)
    monkeypatch.setattr(gateway, "invoke", overlapping)
    def run(principal, order_id):
        return list(rt.tracked_readonly_task(gateway, principal, prompt="show and check", order_id=order_id))[-1]["result"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(run, first, "sample-order")
        b = pool.submit(run, second, "second-order")
        results = [a.result(timeout=15), b.result(timeout=15)]
    assert [r["status"] for r in results] == ["completed", "completed"]
    assert results[0]["trace_id"] != results[1]["trace_id"]
    for result, principal, order_id, currency in zip(results, (first, second), ("sample-order", "second-order"), ("USD", "EUR")):
        assert result["steps"][0]["result"]["order"]["order_id"] == order_id
        assert result["steps"][0]["result"]["order"]["currency"] == currency
        assert result["verified_steps"] == 2
        history = gateway.store.list_local_tasks(principal)
        assert len(history) == 1 and history[0]["trace_id"] == result["trace_id"]
        audit = [e for e in gateway.store.get_trace_events(result["trace_id"]) if e["event_type"] == "POLICY_DECISION"]
        assert len(audit) == 2
        assert all(e["actor_id"] == principal.subject_id and e["tenant_id"] == principal.tenant_id and e["resource_id"] == order_id for e in audit)


@pytest.mark.parametrize("models, status", [
    ([{"name": rt.MODEL}], "ready"),
    ([{"model": rt.MODEL}], "ready"),
    ([{"name": "another-model"}], "model_missing"),
    ([], "model_missing"),
    (None, "unavailable"),
])
def test_local_model_readiness(monkeypatch, models, status):
    import json
    from unittest.mock import MagicMock
    response = MagicMock()
    response.__enter__.return_value.read.return_value = json.dumps({"models": models}).encode()
    opener = Mock()
    opener.open.return_value = response
    monkeypatch.setattr(rt.urllib.request, "build_opener", lambda *args: opener)
    assert rt.model_readiness() == {"model": rt.MODEL, "status": status, "ready": status == "ready"}
    opener.open.assert_called_once_with("http://127.0.0.1:11434/api/tags", timeout=2.0)


def test_readiness_unavailable_is_sanitized(monkeypatch):
    opener = Mock()
    opener.open.side_effect = OSError("private internal error")
    monkeypatch.setattr(rt.urllib.request, "build_opener", lambda *args: opener)
    assert rt.model_readiness()["status"] == "unavailable"
    assert "private" not in rt.public_runtime_error(rt.ModelUnavailable("private internal error"))
    assert rt.public_runtime_error(rt.LocalRuntimeError("private internal error")) == "Task could not be verified."


def test_full_planner_admission_does_not_call_model(monkeypatch):
    from threading import BoundedSemaphore
    slots = BoundedSemaphore(2)
    assert slots.acquire(False) and slots.acquire(False)
    monkeypatch.setattr(rt, "_ADMISSION", slots)
    classify = Mock()
    monkeypatch.setattr(rt, "_classify", classify)
    with pytest.raises(rt.PlannerBusy, match="queue full"):
        rt.plan_readonly_task("show order")
    classify.assert_not_called()


def test_planning_wait_timeout_releases_admission(monkeypatch):
    from threading import BoundedSemaphore, Lock
    slots, lock = BoundedSemaphore(2), Lock()
    assert lock.acquire(False)
    monkeypatch.setattr(rt, "_ADMISSION", slots)
    monkeypatch.setattr(rt, "_LOCK", lock)
    monkeypatch.setattr(rt, "QUEUE_TIMEOUT", 0.01)
    classify = Mock()
    monkeypatch.setattr(rt, "_classify", classify)
    try:
        with pytest.raises(rt.PlannerBusy, match="queue timeout"):
            rt.plan_readonly_task("show order")
        classify.assert_not_called()
        assert slots.acquire(False) and slots.acquire(False)
    finally:
        lock.release()


def test_planner_failure_releases_resources(monkeypatch):
    from threading import BoundedSemaphore, Lock
    slots, lock = BoundedSemaphore(2), Lock()
    monkeypatch.setattr(rt, "_ADMISSION", slots)
    monkeypatch.setattr(rt, "_LOCK", lock)
    monkeypatch.setattr(rt, "_classify", Mock(side_effect=rt.ModelUnavailable("offline")))
    with pytest.raises(rt.ModelUnavailable):
        rt.plan_readonly_task("show order")
    assert lock.acquire(False)
    lock.release()
    assert slots.acquire(False) and slots.acquire(False)


def test_stop_before_first_read_persists_interruption(monkeypatch, runtime):
    from threading import Event
    gateway, principal = runtime
    signal = Event()
    planner = Mock(return_value="both")
    monkeypatch.setattr(rt, "plan_readonly_task", planner)
    stream = rt.tracked_readonly_task(gateway, principal, prompt="show order",
                                      order_id="sample-order", cancellation=signal)
    started = next(stream)
    signal.set()
    with pytest.raises(rt.TaskInterrupted):
        next(stream)
    planner.assert_not_called()
    assert not gateway.store.get_trace_events(started["trace_id"])
    row = gateway.store.list_local_tasks(principal)[0]
    assert row["status"] == "interrupted" and row["verified_steps"] == 0


def test_stop_between_planning_calls_releases_admission(monkeypatch):
    from threading import Event, BoundedSemaphore, Lock
    signal = Event()
    slots, lock = BoundedSemaphore(2), Lock()
    monkeypatch.setattr(rt, "_ADMISSION", slots)
    monkeypatch.setattr(rt, "_LOCK", lock)
    def classify(*args, **kwargs):
        signal.set()
        return "both"
    planner = Mock(side_effect=classify)
    monkeypatch.setattr(rt, "_classify", planner)
    with pytest.raises(rt.TaskInterrupted):
        rt.plan_readonly_task("show and check", cancellation=signal)
    assert planner.call_count == 1
    assert lock.acquire(False)
    lock.release()
    assert slots.acquire(False) and slots.acquire(False)


def test_stop_after_first_verified_read_prevents_dependent_read(monkeypatch, runtime):
    from threading import Event
    gateway, principal = runtime
    signal = Event()
    monkeypatch.setattr(rt, "plan_readonly_task", Mock(return_value="both"))
    invoke = Mock(wraps=gateway.invoke)
    monkeypatch.setattr(gateway, "invoke", invoke)
    stream = rt.tracked_readonly_task(gateway, principal, prompt="show and check",
                                      order_id="sample-order", cancellation=signal)
    for event in stream:
        if event.get("stage") == "tool" and event.get("status") == "verified":
            break
    signal.set()
    with pytest.raises(rt.TaskInterrupted):
        next(stream)
    assert invoke.call_count == 1
    row = gateway.store.list_local_tasks(principal)[0]
    assert row["status"] == "interrupted" and row["verified_steps"] == 1


def test_stop_registry_is_account_scoped_and_bounded(runtime):
    from threading import Event
    _, principal = runtime
    registry = rt.SupportCancellationRegistry()
    signals = [Event() for _ in range(9)]
    for i in range(8):
        registry.register(principal, str(i), signals[i])
    with pytest.raises(rt.PlannerBusy):
        registry.register(principal, "8", signals[8])
    foreign = Principal(principal.subject_id, principal.tenant_id, "foreign", True)
    assert not registry.request(foreign, "0")
    assert not registry.request(principal, "missing")
    assert not signals[0].is_set()
    assert registry.request(principal, "0")
    assert signals[0].is_set()
    registry.remove("0", signals[8])
    assert registry.request(principal, "0")
    registry.remove("0", signals[0])
    assert not registry.request(principal, "0")
    registry.register(principal, "8", signals[8])


def test_authenticated_cancellation_http_boundary(monkeypatch, runtime):
    import json
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from fastapi.testclient import TestClient
    from shadow_hunter.auth import TokenAuthenticator
    from shadow_hunter.api import create_app

    gateway, principal = runtime
    monkeypatch.setenv("SHADOW_HUNTER_AUTH_MODE", "local")
    monkeypatch.setenv("SHADOW_HUNTER_LOCAL_READONLY_ENABLED", "true")
    monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME", raising=False)
    auth = TokenAuthenticator(customer_tokens={
        "local-owner": {"subject_id": principal.subject_id, "tenant_id": principal.tenant_id,
                        "customer_id": principal.customer_id},
        "local-other": {"subject_id": "other-subject", "tenant_id": principal.tenant_id,
                        "customer_id": "other-customer"},
    }, operator_tokens={})
    app = create_app(store=gateway.store, authenticator=auth)
    entered, release = Event(), Event()

    def controlled_plan(prompt, *, cancellation=None):
        entered.set()
        if not release.wait(timeout=10):
            raise RuntimeError("Test did not release planner")
        return "both"

    monkeypatch.setattr(rt, "plan_readonly_task", controlled_plan)
    owner = {"Authorization": "Bearer local-owner"}
    other = {"Authorization": "Bearer local-other"}
    stream_path = "/v1/agent/local-readonly/stream"
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            TestClient(app).post, stream_path, headers=owner,
            json={"prompt": "show order and check eligibility", "order_id": "sample-order"}
        )
        try:
            assert entered.wait(timeout=5)
            rows = gateway.store.list_local_tasks(principal)
            assert len(rows) == 1
            trace = rows[0]["trace_id"]
            path = "/v1/agent/local-readonly/cancel/" + trace
            client = TestClient(app)
            assert client.post(path).status_code == 401
            assert client.post(path, headers=other).status_code == 404
            assert client.post(path, headers=owner).json() == {"status": "cancellation_requested"}
        finally:
            release.set()
        response = future.result(timeout=10)
    assert response.status_code == 200
    events = [json.loads(line) for line in response.text.splitlines()]
    assert events[-1]["type"] == "error" and events[-1]["status"] == "interrupted"
    assert not any(event["type"] == "result" for event in events)
    assert gateway.store.list_local_tasks(principal)[0]["status"] == "interrupted"
    assert not gateway.store.get_trace_events(trace)
    assert TestClient(app).post(path, headers=owner).status_code == 404
