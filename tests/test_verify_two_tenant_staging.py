"""Two-tenant verification only accepts real-style JWT-bound app results."""
import json

from scripts import verify_two_tenant_staging as mod
from scripts.smoke_agentcore_staging import Response


def fake_sender(*, allow_cross=False, tamper_audit=False):
    def send(base, method, path, *, token=None, payload=None):
        assert base == mod.STAGING_BASE
        if path.startswith("/v1/operator/audit/trace/"):
            assert token == "operator-token"
            return Response(200, b"[]" if tamper_audit else json.dumps([{
                "event_type": "POLICY_DECISION",
                "decision": ("DENY" if "cross" in path else "ALLOW"),
                "details": {"tool_name": "get_order"},
            }]).encode())  # replaced below by trace mapping
        assert method == "POST" and path == "/v1/agent/tools/get_order"
        order = payload["arguments"]["order_id"]
        own = (token == "jwt-A" and order == "owned-A") or (token == "jwt-B" and order == "owned-B")
        if allow_cross and order in {"owned-A", "owned-B"}:
            own = True
        body = {
            "decision": "ALLOW" if own else "DENY",
            "reason_code": "POLICY_ALLOWED" if own else "RESOURCE_NOT_AVAILABLE",
            "trace_id": payload["trace_id"],
            "request_id": payload["request_id"],
        }
        if own:
            body["order"] = {"order_id": order}
        return Response(200, json.dumps(body).encode())
    return send


class FakeServer:
    def __init__(self, *, cross=False, absent_audit=False):
        self.cross = cross
        self.absent_audit = absent_audit
        self.by_trace = {}

    def __call__(self, base, method, path, *, token=None, payload=None):
        assert base == mod.STAGING_BASE
        if path.startswith("/v1/operator/audit/trace/"):
            assert token == "operator-token"
            trace = path.rsplit("/", 1)[-1]
            data = self.by_trace.get(trace)
            return Response(200, b"[]" if self.absent_audit or data is None
                            else json.dumps([{"event_type": "POLICY_DECISION",
                                              "decision": data,
                                              "details": {"tool_name": "get_order"}}]).encode())
        assert method == "POST" and path == "/v1/agent/tools/get_order"
        order = payload["arguments"]["order_id"]
        own = (token == "jwt-A" and order == "owned-A") or (token == "jwt-B" and order == "owned-B")
        if self.cross and order in {"owned-A", "owned-B"}:
            own = True
        decision = "ALLOW" if own else "DENY"
        self.by_trace[payload["trace_id"]] = decision
        data = {"decision": decision, "reason_code": "OK" if own else "RESOURCE_NOT_AVAILABLE",
                "trace_id": payload["trace_id"], "request_id": payload["request_id"]}
        if own:
            data["order"] = {"order_id": order}
        return Response(200, json.dumps(data).encode())


def identities():
    return {
        "tenant_a": mod.StagingIdentity("A", "jwt-A", "owned-A"),
        "tenant_b": mod.StagingIdentity("B", "jwt-B", "owned-B"),
        "operator_token": "operator-token",
    }


def test_successful_two_tenant_read_only_isolation_and_audit():
    ok, details = mod.check_isolation(**identities(), sender=FakeServer())
    assert ok is True
    assert len(details) == 12
    assert all(line.startswith("PASS ") for line in details)


def test_cross_tenant_read_leak_blocks_gate():
    ok, details = mod.check_isolation(**identities(), sender=FakeServer(cross=True))
    assert not ok
    assert any(line.startswith("FAIL tenant A cannot read B") for line in details)


def test_missing_staging_audit_blocks_gate():
    ok, details = mod.check_isolation(**identities(), sender=FakeServer(absent_audit=True))
    assert not ok
    assert any("audited" in line and line.startswith("FAIL") for line in details)


def test_reused_identity_or_order_refuses_network():
    kwargs = identities()
    kwargs["tenant_b"] = mod.StagingIdentity("B", "jwt-A", "owned-B")
    ok, detail = mod.check_isolation(**kwargs, sender=None)
    assert not ok
    assert "distinct" in detail[0]
