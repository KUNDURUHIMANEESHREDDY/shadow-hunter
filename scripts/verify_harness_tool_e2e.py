"""Verify one governed get_order invocation against live staging audit evidence.

Read-only, staging-host pinned, and requires an explicit --invoke-model switch.
This uses genuine synthetic customer/operator Cognito JWTs. A model claiming
"success" is never accepted without a matching application policy audit event.
No customer records, JWTs, or response bodies are printed.
"""
from __future__ import annotations

import argparse
import json
import os

from scripts.smoke_agentcore_staging import STAGING_BASE, Response, send


def verify(sender, customer_token: str, operator_token: str, order_id: str) -> list[str]:
    failures = []
    if not customer_token or not operator_token or not isinstance(order_id, str) or not 1 <= len(order_id) <= 128:
        return ["Missing required synthetic identities or order ID"]
    health = sender(STAGING_BASE, "GET", "/health")
    if health.status != 200:
        return ["Staging health is unavailable"]
    try:
        body = json.loads(health.body)
    except (ValueError, TypeError):
        return ["Staging health payload is invalid"]
    if body.get("agentcore_configured") is not True or body.get("demo_mode") is True:
        return ["Staging managed Harness is not configured or demo mode is enabled"]
    chat = sender(
        STAGING_BASE, "POST", "/v1/agent/chat", token=customer_token,
        payload={"prompt": (
            "For this synthetic staging exercise, use the governed get_order "
            "tool to inspect the fictional order ID " + order_id +
            ". Never request or execute a refund. Summarize only whether access was allowed."
        )},
    )
    if chat.status != 200:
        return ["Harness did not complete an authenticated invocation"]
    try:
        result = json.loads(chat.body)
        activity = result["model_tool_activity"]
        trace_id = result["trace_id"]
    except (TypeError, ValueError, KeyError):
        return ["Harness did not return structured trace evidence"]
    if not isinstance(trace_id, str) or not 1 <= len(trace_id) <= 128 or not trace_id.replace("-", "").replace("_", "").isalnum():
        return ["Harness returned an invalid trace identifier"]
    if not isinstance(activity, dict):
        return ["Harness tool evidence is malformed"]
    uses = activity.get("observed_tool_uses")
    results = activity.get("observed_tool_results")
    errors = activity.get("observed_tool_errors", 0)
    if (
        type(uses) is not int or type(results) is not int
        or type(errors) is not int or not 1 <= uses <= 8
        or not 1 <= results <= uses or errors != 0
    ):
        return ["Harness did not report a valid successful tool-use and tool-result pair"]
    audit = sender(STAGING_BASE, "GET", "/v1/operator/audit/trace/" + trace_id, token=operator_token)
    if audit.status != 200:
        return ["Operator audit trace was unavailable"]
    try:
        events = json.loads(audit.body)
    except (ValueError, TypeError):
        return ["Operator audit response was invalid"]
    if not isinstance(events, list) or not any(
        isinstance(event, dict)
        and event.get("event_type") == "POLICY_DECISION"
        and event.get("decision") == "ALLOW"
        and event.get("resource_id") == order_id
        and isinstance(event.get("policy_id"), str) and bool(event["policy_id"])
        and isinstance(event.get("policy_version"), str) and bool(event["policy_version"])
        and isinstance(event.get("details"), dict)
        and event["details"].get("tool_name") == "get_order"
        for event in events
    ):
        failures.append("No matching policy ALLOW receipt for this exact synthetic order")
    if isinstance(events, list) and any(
        isinstance(event, dict)
        and (
            event.get("event_type", "").startswith("REFUND_EXECUT")
            or (
                event.get("event_type") == "POLICY_DECISION"
                and isinstance(event.get("details"), dict)
                and event["details"].get("tool_name") == "create_refund_request"
            )
        )
        for event in events
    ):
        failures.append("Unexpected refund action occurred in read-only tool proof")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--invoke-model", action="store_true",
                        help="Explicitly run a hosted model invocation, which may incur AWS charges")
    parser.add_argument("--synthetic-order-id", required=True)
    args = parser.parse_args(argv)
    if not args.invoke_model:
        print("NOT RUN: model invocation requires --invoke-model")
        return 2
    try:
        issues = verify(
            send, os.environ.get("SHADOW_HUNTER_E2E_CUSTOMER_JWT", ""),
            os.environ.get("SHADOW_HUNTER_E2E_OPERATOR_JWT", ""),
            args.synthetic_order_id,
        )
    except (OSError, TimeoutError, ValueError):
        issues = ["Staging evidence probe could not complete"]
    for issue in issues:
        print("BLOCKED", issue)
    if issues:
        return 1
    print("PASS governed Harness tool call correlated with application policy audit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
