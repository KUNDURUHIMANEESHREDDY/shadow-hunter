"""No-secrets sponsor readiness preflight tests."""
import json
from shadow_hunter import sponsor_preflight


def test_preflight_never_displays_keys_or_user_ids(monkeypatch, capsys):
    monkeypatch.setenv("SHADOW_HUNTER_BAND_API_KEY", "SECRET_BAND_KEY_123")
    monkeypatch.setenv("SHADOW_HUNTER_BAND_CHAT_ID", "private-room")
    monkeypatch.setenv("SHADOW_HUNTER_LYZR_API_KEY", "SECRET_LYZR_KEY_123")
    monkeypatch.setenv("SHADOW_HUNTER_LYZR_AGENT_ID", "private-agent")
    monkeypatch.setenv("SHADOW_HUNTER_LYZR_USER_ID", "private-user")
    assert sponsor_preflight.main([]) == 0
    output=capsys.readouterr().out
    assert json.loads(output)["band"]["live_authenticated"] == "not_checked"
    for secret in ("SECRET_BAND_KEY_123", "SECRET_LYZR_KEY_123", "private-user", "private-room"):
        assert secret not in output


def test_live_band_auth_requires_explicit_flag(monkeypatch, capsys):
    monkeypatch.setattr(
        sponsor_preflight, "check_band_auth",
        lambda: (_ for _ in ()).throw(AssertionError("must not make network call")),
    )
    sponsor_preflight.main([])
    capsys.readouterr()


def test_band_auth_reports_missing_key_without_network(monkeypatch):
    monkeypatch.delenv("SHADOW_HUNTER_BAND_API_KEY", raising=False)
    assert sponsor_preflight.check_band_auth() == "not_configured"
