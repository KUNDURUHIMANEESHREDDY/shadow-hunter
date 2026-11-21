from __future__ import annotations

from shadow_hunter.store import SQLiteStore


def test_latest_agent_evaluation_returns_redacted_summary_and_results(tmp_path):
    store = SQLiteStore(tmp_path / "agent-evaluation.sqlite3")
    store.append_audit(
        event_type="AGENT_EVALUATION_RUN",
        trace_id="run-0001",
        request_id="run-0001",
        actor_id="operator-1",
        tenant_id="evaluation-sandbox",
        details={
            "run_id": "run-0001",
            "attack_attempts": 2,
            "attack_successes": 0,
            "defensive_effectiveness": 1.0,
        },
    )
    store.append_audit(
        event_type="AGENT_EVALUATION_TRACE_EVENT",
        trace_id="run-0001",
        request_id="message-0001",
        actor_id="blue-agent",
        tenant_id="evaluation-sandbox",
        details={
            "sandbox_trace_id": "sandbox-trace-1",
            "source_event_type": "A2A_MESSAGE_RECEIVED",
            "authenticated": True,
        },
    )
    store.append_audit(
        event_type="AGENT_EVALUATION_RESULT",
        trace_id="run-0001",
        request_id="message-0001",
        decision="DENY",
        reason_code="RESOURCE_OWNER_MISMATCH",
        actor_id="blue-agent",
        tenant_id="evaluation-sandbox",
        resource_id="cross_customer_order_read",
        details={
            "scenario_id": "cross_customer_order_read",
            "attack_prevented": True,
            "attack_success": False,
            "risk_score": 100,
        },
    )

    latest = store.latest_agent_evaluation()

    assert latest["run"]["trace_id"] == "run-0001"
    assert latest["run"]["details"]["attack_attempts"] == 2
    assert len(latest["results"]) == 1
    assert latest["results"][0]["details"]["attack_prevented"] is True
    assert latest["results"][0]["reason_code"] == "RESOURCE_OWNER_MISMATCH"
    assert store.get_trace_events("run-0001")[1]["event_type"] == "AGENT_EVALUATION_TRACE_EVENT"


def test_latest_agent_evaluation_is_empty_before_first_run(tmp_path):
    store = SQLiteStore(tmp_path / "empty-agent-evaluation.sqlite3")

    assert store.latest_agent_evaluation() == {"run": None, "results": []}


def test_sqlite_a2a_nonce_is_single_use_and_expires(tmp_path):
    store = SQLiteStore(tmp_path / "a2a-nonces.sqlite3")

    assert store.claim_a2a_nonce(
        nonce="nonce-one",
        agent_id="red-agent",
        message_id="message-one",
        expires_at_epoch=4_000_000_000,
    )
    assert not store.claim_a2a_nonce(
        nonce="nonce-one",
        agent_id="red-agent",
        message_id="message-two",
        expires_at_epoch=4_000_000_000,
    )
    assert not store.claim_a2a_nonce(
        nonce="expired-nonce",
        agent_id="red-agent",
        message_id="message-three",
        expires_at_epoch=1,
    )


def test_operator_evaluation_budget_enforces_cooldown_and_daily_limit(tmp_path):
    import pytest

    from shadow_hunter.store import StoreError

    store = SQLiteStore(tmp_path / "evaluation-budget.sqlite3")
    store.reserve_agent_evaluation(
        "operator-1", daily_limit=2, cooldown_seconds=3600
    )
    with pytest.raises(StoreError, match="cooldown"):
        store.reserve_agent_evaluation(
            "operator-1", daily_limit=2, cooldown_seconds=3600
        )

    # A separate operator has an independent budget.
    store.reserve_agent_evaluation(
        "operator-2", daily_limit=1, cooldown_seconds=3600
    )
    with pytest.raises(StoreError, match="daily evaluation budget"):
        store.reserve_agent_evaluation(
            "operator-2", daily_limit=1, cooldown_seconds=0
        )


def test_operator_evaluation_budget_resets_on_next_utc_date(tmp_path, monkeypatch):
    from datetime import datetime, timezone
    import shadow_hunter.store as store_module

    store = SQLiteStore(tmp_path / "evaluation-budget-reset.sqlite3")
    class Clock:
        value = datetime(2026, 11, 20, 12, tzinfo=timezone.utc)
        def __call__(self):
            return self.value
    clock = Clock()
    monkeypatch.setattr(store_module, "utc_now", clock)

    store.reserve_agent_evaluation(
        "operator-1", daily_limit=1, cooldown_seconds=0
    )
    clock.value = datetime(2026, 11, 21, 12, tzinfo=timezone.utc)
    store.reserve_agent_evaluation(
        "operator-1", daily_limit=1, cooldown_seconds=0
    )
