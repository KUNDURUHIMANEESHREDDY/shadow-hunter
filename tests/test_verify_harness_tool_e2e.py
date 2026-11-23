"""No network and no real model calls; fail closed without audited tool evidence."""
import json

from scripts import verify_harness_tool_e2e as e2e
from scripts.smoke_agentcore_staging import Response


def sender_factory(*, include_audit=True, observed=1):
    def sender(base, method, path, *, token=None, payload=None):
        assert base == e2e.STAGING_BASE
        if path == "/health":
            return Response(200, b'{"agentcore_configured":true,"demo_mode":false}')
        if path == "/v1/agent/chat":
            assert token == "customer-jwt"
            assert "Never request or execute a refund" in payload["prompt"]
            return Response(200, json.dumps({
                "trace_id": "trace-123",
                "model_tool_activity": {
                    "observed_tool_uses": observed,
                    "observed_tool_results": observed,
                },
            }).encode())
        if path == "/v1/operator/audit/trace/trace-123":
            assert token == "operator-jwt"
            if include_audit:
                return Response(200, json.dumps([{
                    "event_type": "POLICY_DECISION", "decision": "ALLOW",
                    "resource_id": "synthetic-1",
                    "policy_id": "support-refund-baseline",
                    "policy_version": "0.1.0",
                    "details": {"tool_name": "get_order"},
                }]).encode())
            return Response(200, b'[]')
        raise AssertionError(path)
    return sender


def test_live_evidence_contract_needs_both_stream_and_app_audit():
    assert e2e.verify(sender_factory(), "customer-jwt", "operator-jwt", "synthetic-1") == []
    issue = e2e.verify(sender_factory(include_audit=False), "customer-jwt", "operator-jwt", "synthetic-1")
    assert any("No matching" in x for x in issue)
    assert any("did not report" in x for x in
               e2e.verify(sender_factory(observed=0), "customer-jwt", "operator-jwt", "synthetic-1"))


def test_live_evidence_contract_rejects_missing_identity_without_network():
    assert e2e.verify(None, "", "token", "synthetic-1")
    assert e2e.verify(None, "token", "operator", "")

def test_live_evidence_cannot_reuse_other_order_receipt():
    def sender(base, method, path, *, token=None, payload=None):
        if path == "/health":
            return Response(200, b'{"agentcore_configured":true,"demo_mode":false}')
        if path == "/v1/agent/chat":
            return Response(200, json.dumps({
                "trace_id": "trace-123",
                "model_tool_activity": {"observed_tool_uses": 1, "observed_tool_results": 1},
            }).encode())
        return Response(200, json.dumps([{
            "event_type": "POLICY_DECISION", "decision": "ALLOW",
            "resource_id": "different-order",
            "policy_id": "support-refund-baseline", "policy_version": "0.1.0",
            "details": {"tool_name": "get_order"},
        }]).encode())

    assert any("exact synthetic order" in issue for issue in
               e2e.verify(sender, "customer-jwt", "operator-jwt", "synthetic-1"))


def test_live_evidence_fails_closed_on_refund_execution_and_tool_errors():
    original = sender_factory()
    def unsafe_sender(base, method, path, *, token=None, payload=None):
        response = original(base, method, path, token=token, payload=payload)
        if path == "/v1/operator/audit/trace/trace-123":
            events = json.loads(response.body)
            events.append({"event_type": "REFUND_EXECUTED"})
            return Response(200, json.dumps(events).encode())
        return response
    assert any("Unexpected refund action" in issue for issue in
               e2e.verify(unsafe_sender, "customer-jwt", "operator-jwt", "synthetic-1"))

    def error_sender(base, method, path, *, token=None, payload=None):
        response = original(base, method, path, token=token, payload=payload)
        if path == "/v1/agent/chat":
            body = json.loads(response.body)
            body["model_tool_activity"]["observed_tool_errors"] = 1
            return Response(200, json.dumps(body).encode())
        return response
    assert any("valid successful tool" in issue for issue in
               e2e.verify(error_sender, "customer-jwt", "operator-jwt", "synthetic-1"))
