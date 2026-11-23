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
                return Response(200, b'[{"event_type":"POLICY_DECISION","decision":"ALLOW","details":{"tool_name":"get_order"}}]')
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
