"""Bounded, local-only orchestration for authenticated read-only support."""
from __future__ import annotations

import json
import re
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

def _proposal_intent(answer: Any) -> str:
    """Translate only validated support capabilities into the legacy intent contract."""
    if not isinstance(answer, dict) or set(answer) != {"reads"}:
        raise ValueError("Invalid read proposal")
    reads = answer["reads"]
    if not isinstance(reads, list) or len(reads) > 2:
        raise ValueError("Invalid read list")
    if any(type(item) is not str or item not in {"order_details", "refund_eligibility"} for item in reads):
        raise ValueError("Unknown read capability")
    if len(set(reads)) != len(reads):
        raise ValueError("Duplicate read capability")
    return "both" if len(reads) == 2 else reads[0] if reads else "unsupported"


def _classify(prompt: str, *, review: bool, deadline: float) -> str:
    schema = {
        "type": "object",
        "properties": {"intent": {"type": "string", "enum": list(PLANS)}},
        "required": ["intent"],
        "additionalProperties": False,
    }
    instructions = (
        "Classify the entire request into exactly one intent. Only read-only customer support. "
        "order_details: show purchase/order information, currency, remaining refundable amount. "
        "refund_eligibility: check whether the purchase can be refunded or qualifies. "
        "both: the request asks for both kinds of information. "
        "unsupported: unrelated task or any request to actually change data. "
        "Distinguish how much (order_details) from whether possible (refund_eligibility). "
        "Look at all clauses before choosing. Examples: "
        "How much remains refundable? -> order_details. What currency? -> order_details. "
        "Can my purchase be refunded? -> refund_eligibility. "
        "Show purchase details and tell me whether it qualifies -> both. "
        "Get the order and see if I can get a refund -> both. "
        "Show the currency and check eligibility -> both. "
        "Explain a math concept -> unsupported. Write a story -> unsupported. "
        "Submit a refund -> unsupported. Return JSON only."
    )
    if not review:
        schema = {
            "type": "object",
            "properties": {"reads": {"type": "array", "maxItems": 2,
                                      "uniqueItems": True, "items": {"type": "string",
                                      "enum": ["order_details", "refund_eligibility"]}}},
            "required": ["reads"],
            "additionalProperties": False,
        }
        instructions += (
            " For this proposal, represent the requested capabilities as a reads array "
            "instead of an intent string. For both use both names; for unsupported use an "
            "empty array. Never include arguments, identifiers or write operations. "
            'Output only a JSON object with key reads, e.g. {"reads":["order_details"]}.'
        )
    if review:
        instructions += (
            " As the coverage reviewer, choose both when the request combines two "
            "different kinds of read, even if the clauses are phrased differently. "
            "Do not infer a support request from unrelated text."
        )
    for attempt in range(2):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise LocalRuntimeError("Local planning deadline exceeded")
        body = {
            "model": MODEL, "stream": False, "think": False, "format": schema,
            "messages": [
                {"role": "system", "content": instructions + (
                    (" Output exactly one JSON intent from the allowed enum." if review else
                     " Output exactly one JSON reads array object from the allowed capabilities.") if attempt else ""
                )},
                {"role": "user", "content": prompt},
            ],
            "options": {"temperature": 0, "num_ctx": 2048, "num_predict": 64},
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
            if not review:
                return _proposal_intent(answer)
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

def _obvious_compound_read(prompt: str) -> bool:
    """Conservative coverage check only: it may stop, never expand authority."""
    text = prompt.casefold()
    details = re.search(r"\b(?:order|purchase)\s+(?:details|information|currency)\b|\b(?:show|retrieve|view|get)\b.{0,32}\b(?:order|purchase)\b", text)
    eligibility = re.search(r"\b(?:eligibility|eligible|qualifies|qualify|can be refunded|can .*?be refunded|refund is possible|refund is available)\b", text)
    return bool(details and eligibility)


def _explicit_change_request(prompt: str) -> bool:
    """Stop direct change commands instead of silently reinterpreting as reads.

    This narrow quality guard is not an authorization boundary.
    """
    return bool(re.match(
        r"^\s*(?:please\s+)?(?:(?:submit|issue|process|execute|initiate|create|approve)\s+"
        r"(?:(?:a|the|my)\s+)?refund\b|refund\s+(?:my|the|this)\s+(?:order|purchase)\b|"
        r"cancel\s+(?:(?:my|the|this)\s+)?order\b)", prompt, re.IGNORECASE
    ))


def plan_readonly_task(prompt: str) -> str:
    if _explicit_change_request(prompt):
        return "unsupported"
    if not _LOCK.acquire(blocking=False):
        raise LocalRuntimeError("Local model busy")
    try:
        deadline = time.monotonic() + PLAN_TIMEOUT
        proposal = _classify(prompt, review=False, deadline=deadline)
        review = _classify(prompt, review=True, deadline=deadline)
        # Agreement is a quality check, never authorization or proof of intent.
        if proposal != review:
            return "clarify"
        if proposal != "both" and _obvious_compound_read(prompt):
            return "clarify"
        return proposal
    finally:
        _LOCK.release()

def support_workflow(intent: str) -> list[dict[str, Any]]:
    """Compile the reviewed intent into a server-owned dependency description.

    Related reads are deliberately serial: a denied order lookup stops the
    compound request before any second read. The model cannot choose dependencies.
    """
    if intent not in PLANS and intent != "clarify":
        raise InvalidPlan("Unknown reviewed intent")
    tools = PLANS.get(intent, ())
    return [
        {"id": tool, "depends_on": list(tools[:index])}
        for index, tool in enumerate(tools)
    ]


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
    if key == "eligibility" and data["eligible"] and amount == 0:
        raise LocalRuntimeError("Inconsistent eligibility result")

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
    workflow = support_workflow(intent)
    plan = [node["id"] for node in workflow]
    steps = []
    timeline = [{"stage": "planning", "status": "reviewed"}]
    def response(status: str) -> dict[str, Any]:
        if status == "completed":
            messages = []
            for step in steps:
                data = step["result"]
                if step["tool"] == "get_order":
                    order = data["order"]
                    messages.append("Order details verified. Refundable balance: "
                                    + str(order["refundable_minor"]) + " minor units ("
                                    + order["currency"] + ").")
                elif step["tool"] == "check_refund_eligibility":
                    eligibility = data["eligibility"]
                    amount = eligibility["refundable_minor"]
                    if eligibility["eligible"]:
                        messages.append("Refund eligibility: eligible under the recorded rules. "
                                        "Remaining refundable balance: "
                                        + str(amount) + " minor units (" + eligibility["currency"] + ").")
                    elif amount == 0:
                        messages.append("Refund eligibility: not eligible. No refundable balance remains.")
                    else:
                        messages.append("Refund eligibility: not eligible under the recorded rules. "
                                        "The specific reason is not available in this read result.")
            answer = " ".join(messages)
        else:
            answer = {
                "denied": "The requested resource is not available to this account.",
                "unsupported": "This workspace supports order information and refund eligibility reads only.",
                "clarify": "The task could not be interpreted consistently. Please rephrase it.",
            }[status]
        return {"answer": answer, "model": MODEL, "status": status, "trace_id": trace,
                "plan": plan, "workflow": workflow, "steps": steps, "timeline": timeline,
                "verified_steps": len(steps)}
    yield {"type": "progress", "stage": "planning", "status": "reviewed", "plan": plan, "workflow": workflow, "trace_id": trace}
    if intent in ("unsupported", "clarify"):
        timeline.append({"stage": "planning", "status": intent})
        yield {"type": "result", "result": response(intent)}
        return
    # At most one fresh read of the whole compound plan. Never retry a denial
    # or failed audit verification; those must stop execution immediately.
    for attempt in range(2):
        verified = set()
        for node in workflow:
            if not set(node["depends_on"]).issubset(verified):
                raise LocalRuntimeError("Unverified workflow dependency")
            tool = node["id"]
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
            verified.add(tool)
        if len(steps) != 2:
            break
        order = steps[0]["result"]["order"]
        eligibility = steps[1]["result"]["eligibility"]
        if (order["currency"] == eligibility["currency"]
                and order["refundable_minor"] == eligibility["refundable_minor"]
                and eligibility["eligible"] == (order["refund_eligible"] and order["refundable_minor"] > 0)):
            break
        if attempt == 1:
            raise LocalRuntimeError("Read results changed after bounded recovery")
        # Discard inconsistent data before collecting a fresh pair. Previous
        # decision evidence remains in the audit store under the same trace.
        steps.clear()
        timeline.append({"stage": "recovery", "status": "retrying"})
        yield {"type": "progress", "stage": "recovery", "status": "retrying", "trace_id": trace}
    timeline.append({"stage": "completion", "status": "verified"})
    yield {"type": "result", "result": response("completed")}


def run_readonly_task(gateway: ToolGateway, principal: Principal, *,
                      prompt: str, order_id: str) -> dict[str, Any]:
    for event in iter_readonly_task(gateway, principal, prompt=prompt, order_id=order_id):
        if event["type"] == "result":
            return event["result"]
    raise LocalRuntimeError("Task ended without a verified result")


def tracked_readonly_task(gateway: ToolGateway, principal: Principal, *,
                          prompt: str, order_id: str) -> Iterator[dict[str, Any]]:
    """Persist only minimal account-scoped task metadata, never prompt/results."""
    trace = None
    steps = 0
    finalized = False
    try:
        for event in iter_readonly_task(gateway, principal, prompt=prompt, order_id=order_id):
            if trace is None:
                new_trace = event["trace_id"]
                gateway.store.begin_local_task(principal, new_trace)
                trace = new_trace
            if event["type"] == "progress" and event.get("stage") == "recovery":
                # History counts the active attempt; audit retains all decisions.
                steps = 0
            if event["type"] == "progress" and event.get("stage") == "tool" and event.get("status") == "verified":
                steps += 1
            if event["type"] == "result":
                result = event["result"]
                gateway.store.finish_local_task(principal, trace, result["status"], result["verified_steps"])
                finalized = True
            yield event
    except Exception:
        if trace is not None and not finalized:
            gateway.store.finish_local_task(principal, trace, "failed", steps)
            finalized = True
        raise
    finally:
        if trace is not None and not finalized:
            gateway.store.finish_local_task(principal, trace, "interrupted", steps)
