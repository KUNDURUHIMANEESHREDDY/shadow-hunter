"""Operator-managed integration secrets backed by pre-provisioned AWS Secrets Manager entries."""
from __future__ import annotations

import json
import os
import secrets
from collections.abc import Mapping
from typing import Any


class IntegrationSettingsError(RuntimeError):
    """A secret target is absent or cannot be updated safely."""


class IntegrationSecretStore:
    """Read/write only the two explicitly configured Shadow Hunter secret ARNs.

    The application never accepts a SecretId from the browser. IAM is expected
    to scope GetSecretValue and PutSecretValue to these exact pre-provisioned
    ARNs. Secret values are returned only to the caller inside the server.
    """

    def __init__(
        self,
        *,
        nim_secret_arn: str = "",
        a2a_secret_arn: str = "",
        region: str = "",
        client: Any | None = None,
    ) -> None:
        self.nim_secret_arn = nim_secret_arn.strip()
        self.a2a_secret_arn = a2a_secret_arn.strip()
        self.region = region.strip()
        self._client = client

    @classmethod
    def from_environment(cls) -> "IntegrationSecretStore":
        return cls(
            nim_secret_arn=os.environ.get(
                "SHADOW_HUNTER_NIM_API_KEY_SECRET_ARN", ""
            ),
            a2a_secret_arn=os.environ.get(
                "SHADOW_HUNTER_A2A_KEYS_SECRET_ARN", ""
            ),
            region=(
                os.environ.get("AWS_REGION", "")
                or os.environ.get("AWS_DEFAULT_REGION", "")
            ),
        )

    def _secrets_manager(self):
        if self._client is None:
            try:
                import boto3
            except ImportError as exc:
                raise IntegrationSettingsError(
                    "AWS Secrets Manager support is not installed"
                ) from exc
            self._client = boto3.client(
                "secretsmanager", region_name=self.region or None
            )
        return self._client

    def _read(self, secret_arn: str) -> tuple[bool, str | None]:
        if not secret_arn:
            return False, None
        try:
            result = self._secrets_manager().get_secret_value(SecretId=secret_arn)
        except Exception:
            return False, None
        value = result.get("SecretString")
        return True, value if isinstance(value, str) and value.strip() else None

    def _write(self, secret_arn: str, value: str) -> None:
        if not secret_arn:
            raise IntegrationSettingsError(
                "The required Secrets Manager target is not provisioned"
            )
        try:
            self._secrets_manager().put_secret_value(
                SecretId=secret_arn,
                SecretString=value,
            )
        except Exception as exc:
            # Provider errors may contain request metadata. Never reflect them
            # into the operator UI because this operation handles credentials.
            raise IntegrationSettingsError(
                "AWS Secrets Manager could not update the configured secret"
            ) from exc

    @staticmethod
    def _nim_value_is_present(raw: str | None) -> bool:
        if not raw:
            return False
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return bool(raw.strip())
        if isinstance(parsed, Mapping):
            value = parsed.get("NVIDIA_API_KEY") or parsed.get("api_key")
            return isinstance(value, str) and bool(value.strip())
        return False

    @staticmethod
    def _a2a_value_is_present(raw: str | None) -> bool:
        if not raw:
            return False
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return False
        if not isinstance(parsed, dict) or len(parsed) != 2:
            return False
        agents: set[str] = set()
        fingerprints: set[str] = set()
        for entry in parsed.values():
            if not isinstance(entry, dict) or set(entry) != {"agent_id", "secret"}:
                return False
            agent_id, secret = entry.get("agent_id"), entry.get("secret")
            if (
                not isinstance(agent_id, str)
                or agent_id not in {"red-agent", "blue-agent"}
                or not isinstance(secret, str)
                or len(secret.encode("utf-8")) < 32
                or agent_id in agents
            ):
                return False
            agents.add(agent_id)
            fingerprints.add(secret)
        return (
            agents == {"red-agent", "blue-agent"}
            and len(fingerprints) == 2
        )

    def status(self) -> dict[str, dict[str, bool]]:
        nim_accessible, nim_raw = self._read(self.nim_secret_arn)
        a2a_accessible, a2a_raw = self._read(self.a2a_secret_arn)
        return {
            "nvidia_nim": {
                "storage_available": nim_accessible,
                "configured": self._nim_value_is_present(nim_raw),
            },
            "red_blue_signing": {
                "storage_available": a2a_accessible,
                "configured": self._a2a_value_is_present(a2a_raw),
            },
        }

    def save_nim_api_key(self, api_key: str) -> None:
        if not isinstance(api_key, str):
            raise IntegrationSettingsError("NVIDIA API key must be text")
        value = api_key.strip()
        if (
            not 8 <= len(value) <= 4096
            or any(
                character.isspace()
                or ord(character) < 32
                or ord(character) == 127
                for character in value
            )
        ):
            raise IntegrationSettingsError("NVIDIA API key has an invalid format")
        self._write(
            self.nim_secret_arn,
            json.dumps({"NVIDIA_API_KEY": value}, separators=(",", ":")),
        )

    def rotate_a2a_keys(self) -> dict[str, str]:
        red_id = "red-" + secrets.token_hex(6)
        blue_id = "blue-" + secrets.token_hex(6)
        values = {
            red_id: {
                "agent_id": "red-agent",
                "secret": secrets.token_urlsafe(48),
            },
            blue_id: {
                "agent_id": "blue-agent",
                "secret": secrets.token_urlsafe(48),
            },
        }
        self._write(
            self.a2a_secret_arn,
            json.dumps(values, separators=(",", ":"), sort_keys=True),
        )
        # Return identifiers only. Raw HMAC keys never leave this process.
        return {"red_key_id": red_id, "blue_key_id": blue_id}
