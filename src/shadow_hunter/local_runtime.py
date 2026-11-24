"""Bounded, local-only orchestration for authenticated read-only support."""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Iterator
from uuid import uuid4

from .gateway import ToolGateway, public_tool_result
from .policy import Principal

MODEL = "qwen3.5:0.8b"
PLANS = {
    "order_details": ("get_order",),
    "refund_eligibility": ("check_refund_eligibility",),
    "both": ("get_order", "check_refund_eligibility"),
    "unsupported": (),
}
AGENT_ID = "local-readonly-support"
PLAN_TIMEOUT = 45.0
_LOCK = threading.Lock()

class LocalRuntimeError(RuntimeError):
    pass

class InvalidPlan(LocalRuntimeError):
    pass

def _classify(prompt: str, *, review: bool, deadline: float) -> str:
    schema = {
        "type": "object",
        "properties": {"intent": {"type": "string", "enum": list(PLANS)}},
        "required": ["intent"],
        "additionalProperties": False,
    }
    instructions = (
        "Classify the ENTIRE read-only support request, not just its first clause. "
        "Choose both when it asks to view order information AND check refund eligibility. "
        "Choose order_details only for order information alone; refund_eligibility "
        "only for eligibility alone. For writes or unrelated requests choose unsupported. "
        "A request not to submit a refund is still read-only. Examples: "
        "Show order details and check eligibility -> both. "
        "Show my order -> order_details. Can I get a refund? -> refund_eligibility. "
        "Check refund eligibility and show the order -> both. Return only JSON."
    )
    if review:
        instructions = (
            "You independently verify coverage of a read-only customer support request. "
            "There are exactly four intents. If BOTH order details and refund eligibility "
            "are requested, select both. Do not omit the second requested read. "
            "For order information alone choose order_details. For an eligibility check alone "
            "choose refund_eligibility. If an actual change is requested or the request "
            "is unrelated choose unsupported. Examples: "
            "Show my order details and check refund eligibility -> both. "
            "Check whether I qualify and show my order details -> both. "
            "Show my order -> order_details. "
            "Check whether I qualify for a refund without submitting -> refund_eligibility. "
            "Submit a refund -> unsupported. Return exactly one JSON intent."
        )
    for attempt in range(2):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise LocalRuntimeError("Local planning deadline exceeded")
        body = {
            "model": MODEL, "stream": False, "think": False, "format": schema,
            "messages": [
                {"role": "system", "content": instructions + (
                    " Output exactly one JSON intent from the allowed enum." if attempt else ""
                )},
                {"role": "user", "content": prompt},
            ],
            "options": {"temperature": 0, "num_ctx": 2048, "num_predict": 32},
        }
        request = urllib.request.Request(
            "http://127.0.0.1:11434/api/chat",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(request, timeout=min(35.0, remaining)) as response:
                raw = response.read(65537)
        except (OSError, urllib.error.URLError) as exc:
            # Do not keep retrying an unavailable model.
            raise LocalRuntimeError("Local model unavailable") from exc
        try:
            if len(raw) > 65536:
                raise ValueError("Oversized response")
            result = json.loads(raw)
            if not isinstance(result, dict) or result.get("model") != MODEL or result.get("done") is not True:
                raise ValueError("Unexpected model response")
            answer = json.loads(result["message"]["content"])
            if not isinstance(answer, dict) or set(answer) != {"intent"}:
                raise ValueError("Invalid intent object")
            intent = answer["intent"]
            if not isinstance(intent, str) or intent not in PLANS:
                raise ValueError("Invalid intent")
            return intent
        except (ValueError, TypeError, KeyError):
            if attempt == 1:
                raise InvalidPlan("Invalid local plan after bounded retry") from None
    raise InvalidPlan("Invalid local plan")

def plan_readonly_task(prompt: str) -> str:
    if not _LOCK.acquire(blocking=False):
        raise LocalRuntimeError("Local model busy")
    try:
        deadline = time.monotonic() + PLAN_TIMEOUT
        proposal = _classify(prompt, review=False, deadline=deadline)
        review = _classify(prompt, review=True, deadline=deadline)
        # Agreement is a quality check, never authorization or proof of intent.
        return proposal if proposal == review else "clarify"
    finally:
        _LOCK.release()

def _verify_step(gateway: ToolGateway, principal: Principal, *, trace: str,
                 request_id: str, tool: str, order_id: str, result: dict[str, Any]) -> None:
    if not isinstance(result, dict) or result.get("decision") not in {"ALLOW", "DENY"}:
        raise LocalRuntimeError("Invalid policy result")
    if result.get("trace_id") != trace or result.get("request_id") != request_id:
        raise LocalRuntimeError("Result correlation failed")
    events = [event for event in gateway.store.get_trace_events(trace)
              if event.get("event_type") == "POLICY_DECISION" and event.get("request_id") == request_id]
    if len(events) != 1:
        raise LocalRuntimeError("Missing or duplicate policy evidence")
    event = events[0]
    expected = {"trace_id": trace, "request_id": request_id,
                "actor_id": principal.subject_id, "tenant_id": principal.tenant_id,
                "resource_id": order_id}
    expected.update({key: result.get(key) for key in
                     ("decision", "reason_code", "policy_id", "policy_version", "action_digest")})
    if any(event.get(k) != v for k, v in expected.items()):
        raise LocalRuntimeError("Policy evidence mismatch")
    if event.get("details") != {"tool_name": tool, "agent_id": AGENT_ID}:
        raise LocalRuntimeError("Tool evidence mismatch")
    if result["decision"] == "DENY":
        return
    key = "order" if tool == "get_order" else "eligibility"
    data = result.get(key)
    if not isinstance(data, dict):
        raise LocalRuntimeError("Missing read result")
    if key == "order" and data.get("order_id") != order_id:
        raise LocalRuntimeError("Order result mismatch")
    flag = "refund_eligible" if key == "order" else "eligible"
    amount = data.get("refundable_minor")
    if (type(data.get(flag)) is not bool or type(amount) is not int or amount < 0
            or not isinstance(data.get("currency"), str) or len(data["currency"]) != 3):
        raise LocalRuntimeError("Invalid read result")

def iter_readonly_task(gateway: ToolGateway, principal: Principal, *,
                       prompt: str, order_id: str) -> Iterator[dict[str, Any]]:
    if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 1000:
        raise ValueError("Prompt must contain 1-1000 characters")
    if not isinstance(order_id, str) or not order_id.strip() or len(order_id) > 128 or order_id.strip() != order_id:
        raise ValueError("Invalid order ID")
    if not isinstance(principal, Principal) or principal.authenticated is not True:
        raise LocalRuntimeError("Authenticated principal required")
    trace = str(uuid4())
    yield {"type": "progress", "stage": "planning", "status": "started", "trace_id": trace}
    intent = plan_readonly_task(prompt)
    if not isinstance(intent, str) or (intent not in PLANS and intent != "clarify"):
        raise LocalRuntimeError("Invalid plan")
    plan = list(PLANS.get(intent, ()))
    steps = []
    timeline = [{"stage": "planning", "status": "reviewed"}]
    def response(status: str) -> dict[str, Any]:
        return {"model": MODEL, "status": status, "trace_id": trace,
                "plan": plan, "steps": steps, "timeline": timeline,
                "verified_steps": len(steps)}
    yield {"type": "progress", "stage": "planning", "status": "reviewed", "plan": plan, "trace_id": trace}
    if intent in ("unsupported", "clarify"):
        timeline.append({"stage": "planning", "status": intent})
        yield {"type": "result", "result": response(intent)}
        return
    for tool in plan:
        request_id = str(uuid4())
        yield {"type": "progress", "stage": "tool", "status": "started", "tool": tool, "trace_id": trace}
        result = gateway.invoke(
            principal=principal, tool_name=tool, arguments={"order_id": order_id},
            request_id=request_id, trace_id=trace, agent_id=AGENT_ID,
        )
        _verify_step(gateway, principal, trace=trace, request_id=request_id,
                     tool=tool, order_id=order_id, result=result)
        steps.append({"tool": tool, "result": public_tool_result(result), "verified": True})
        timeline.append({"stage": "tool", "tool": tool, "status": "verified"})
        yield {"type": "progress", "stage": "tool", "status": "verified", "tool": tool, "trace_id": trace}
        if result["decision"] != "ALLOW":
            timeline.append({"stage": "completion", "status": "denied"})
            yield {"type": "result", "result": response("denied")}
            return
    # Both reads should agree before marking a compound task complete.
    if len(steps) == 2:
        order = steps[0]["result"]["order"]
        eligibility = steps[1]["result"]["eligibility"]
        if (order["currency"] != eligibility["currency"]
                or order["refundable_minor"] != eligibility["refundable_minor"]
                or eligibility["eligible"] != (order["refund_eligible"] and order["refundable_minor"] > 0)):
            raise LocalRuntimeError("Read results changed; retry the task")
    timeline.append({"stage": "completion", "status": "verified"})
    yield {"type": "result", "result": response("completed")}


def run_readonly_task(gateway: ToolGateway, principal: Principal, *,
                      prompt: str, order_id: str) -> dict[str, Any]:
    for event in iter_readonly_task(gateway, principal, prompt=prompt, order_id=order_id):
        if event["type"] == "result":
            return event["result"]
    raise LocalRuntimeError("Task ended without a verified result")
