import json

import pytest

from shadow_hunter.settings import IntegrationSecretStore, IntegrationSettingsError


class FakeSecretsManager:
    def __init__(self):
        self.values = {}
        self.writes = []

    def get_secret_value(self, *, SecretId):
        if SecretId not in self.values:
            raise KeyError(SecretId)
        return {"SecretString": self.values[SecretId]}

    def put_secret_value(self, *, SecretId, SecretString):
        self.values[SecretId] = SecretString
        self.writes.append((SecretId, SecretString))
        return {"VersionId": "version-test"}


def test_nim_secret_is_saved_and_status_never_returns_the_value():
    client = FakeSecretsManager()
    store = IntegrationSecretStore(
        nim_secret_arn="arn:aws:secretsmanager:region:account:secret:nim",
        a2a_secret_arn="arn:aws:secretsmanager:region:account:secret:a2a",
        client=client,
    )

    store.save_nim_api_key("nvapi-example-secret-value")

    status = store.status()
    assert status["nvidia_nim"] == {
        "storage_available": True,
        "configured": True,
    }
    assert "nvapi-example-secret-value" not in json.dumps(status)
    assert json.loads(client.values["arn:aws:secretsmanager:region:account:secret:nim"]) == {
        "NVIDIA_API_KEY": "nvapi-example-secret-value"
    }


def test_a2a_rotation_creates_distinct_server_side_keys():
    client = FakeSecretsManager()
    store = IntegrationSecretStore(
        a2a_secret_arn="arn:aws:secretsmanager:region:account:secret:a2a",
        client=client,
    )

    result = store.rotate_a2a_keys()
    stored = json.loads(client.values["arn:aws:secretsmanager:region:account:secret:a2a"])

    assert set(result) == {"red_key_id", "blue_key_id"}
    assert result["red_key_id"] in stored
    assert result["blue_key_id"] in stored
    assert stored[result["red_key_id"]]["agent_id"] == "red-agent"
    assert stored[result["blue_key_id"]]["agent_id"] == "blue-agent"
    assert len(stored[result["red_key_id"]]["secret"].encode()) >= 32
    assert len(stored[result["blue_key_id"]]["secret"].encode()) >= 32
    assert stored[result["red_key_id"]]["secret"] != stored[result["blue_key_id"]]["secret"]
    assert store.status()["red_blue_signing"]["configured"] is True
    assert stored[result["red_key_id"]]["secret"] not in json.dumps(result)
    assert stored[result["blue_key_id"]]["secret"] not in json.dumps(result)


def test_secret_write_requires_a_preprovisioned_target():
    store = IntegrationSecretStore(client=FakeSecretsManager())

    with pytest.raises(IntegrationSettingsError, match="not provisioned"):
        store.save_nim_api_key("nvapi-example-key")

    with pytest.raises(IntegrationSettingsError, match="not provisioned"):
        store.rotate_a2a_keys()


@pytest.mark.parametrize("value", ["", "short", "contains space", "contains\nnewline", "x" * 4097])
def test_nim_secret_rejects_invalid_key_format(value):
    store = IntegrationSecretStore(
        nim_secret_arn="arn:aws:secretsmanager:region:account:secret:nim",
        client=FakeSecretsManager(),
    )

    with pytest.raises(IntegrationSettingsError):
        store.save_nim_api_key(value)


def test_a2a_status_rejects_shared_or_malformed_keys():
    client = FakeSecretsManager()
    client.values["a2a"] = json.dumps({
        "red": {"agent_id": "red-agent", "secret": "x" * 48},
        "blue": {"agent_id": "blue-agent", "secret": "x" * 48},
    })
    store = IntegrationSecretStore(a2a_secret_arn="a2a", client=client)

    assert store.status()["red_blue_signing"]["configured"] is False


def test_status_reports_secret_target_unavailable_when_read_fails():
    class UnreadableSecretsManager:
        def get_secret_value(self, **_kwargs):
            raise PermissionError("access denied")

    store = IntegrationSecretStore(
        nim_secret_arn="nim",
        a2a_secret_arn="a2a",
        client=UnreadableSecretsManager(),
    )

    status = store.status()

    assert status["nvidia_nim"] == {
        "storage_available": False,
        "configured": False,
    }
    assert status["red_blue_signing"] == {
        "storage_available": False,
        "configured": False,
    }


def test_secrets_manager_errors_are_redacted():
    class FailingSecretsManager:
        def put_secret_value(self, **_kwargs):
            raise RuntimeError("provider error containing credential nvapi-do-not-leak")

    store = IntegrationSecretStore(
        nim_secret_arn="nim",
        client=FailingSecretsManager(),
    )
    with pytest.raises(IntegrationSettingsError) as error:
        store.save_nim_api_key("nvapi-safe-example")
    assert "nvapi-do-not-leak" not in str(error.value)
