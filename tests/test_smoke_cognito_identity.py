"""Offline contract checks for staging-only live Cognito smoke runner."""
from __future__ import annotations

import copy
import pytest

from scripts.smoke_cognito_identity import (
    SmokeFailure,
    _inspect_identity,
    _stack_outputs,
    _totp,
    _check_mfa_user,
)


class FakeCloudFormation:
    def __init__(self, status="CREATE_COMPLETE"):
        self.status = status

    def describe_stacks(self, *, StackName):
        return {"Stacks": [{
            "StackStatus": self.status,
            "Outputs": [{"OutputKey": key, "OutputValue": val}
                        for key, val in output_values().items()],
        }]}


def output_values():
    return {
        "UserPoolId": "ap-southeast-2_test123",
        "CognitoIssuer": "https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_test123",
        "CognitoHostedUiDomain": "https://smoke.auth.ap-southeast-2.amazoncognito.com",
        "CustomerClientId": "cust-123",
        "OperatorClientId": "operator-123",
        "AgentAppClientId": "agent-123",
        "ToolAudience": "shadow-hunter-api",
        "CustomerScope": "shadow-hunter/customer",
        "ToolScope": "shadow-hunter-api/refunds",
        "AgentActorScope": "shadow-hunter-agent/actor",
        "OperatorGroup": "shadow_hunter_operators",
    }


class FakeCognito:
    def __init__(self):
        self.pool = {
            "MfaConfiguration": "ON",
            "EnabledMfas": ["SOFTWARE_TOKEN_MFA"],
            "DeletionProtection": "ACTIVE",
            "LambdaConfig": {"PreTokenGenerationConfig": {"LambdaVersion": "V3_0"}},
        }
        public = {
            "ExplicitAuthFlows": ["ALLOW_USER_SRP_AUTH"],
            "AllowedOAuthFlows": ["code"],
            "WriteAttributes": ["email"],
        }
        self.clients = {
            "cust-123": copy.deepcopy(public),
            "operator-123": copy.deepcopy(public),
            "agent-123": {
                "ExplicitAuthFlows": ["ALLOW_TOKEN_EXCHANGE_DELEGATION"],
                "AllowedOAuthFlows": ["client_credentials"],
                "AllowedOAuthScopes": ["shadow-hunter-agent/actor", "shadow-hunter-api/refunds"],
                "ClientSecret": "never-printed-test-secret",
            },
        }
        self.deleted = []

    def describe_user_pool(self, *, UserPoolId):
        return {"UserPool": self.pool}

    def describe_user_pool_client(self, *, UserPoolId, ClientId):
        return {"UserPoolClient": self.clients[ClientId]}

    def admin_delete_user(self, *, UserPoolId, Username):
        self.deleted.append(Username)


def test_totp_matches_rfc_6238_sha1_vector():
    # The RFC 6238 8-digit value at t=59 is 94287082; 6-digit truncation.
    assert _totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59) == "287082"


def test_read_only_live_pool_contract_passes():
    outputs = _stack_outputs(FakeCloudFormation(), "shadow-hunter-identity-staging")
    agent = _inspect_identity(FakeCognito(), outputs, "ap-southeast-2")
    assert "ClientSecret" in agent


def test_non_staging_and_noncomplete_stacks_rejected():
    with pytest.raises(SmokeFailure, match="non-staging"):
        _stack_outputs(FakeCloudFormation(), "shadow-hunter-identity-production")
    with pytest.raises(SmokeFailure, match="not complete"):
        _stack_outputs(FakeCloudFormation("ROLLBACK_COMPLETE"), "shadow-hunter-identity-staging")


@pytest.mark.parametrize("mutation", [
    lambda idp: idp.pool.update(MfaConfiguration="OFF"),
    lambda idp: idp.pool["EnabledMfas"].clear(),
    lambda idp: idp.pool["LambdaConfig"]["PreTokenGenerationConfig"].update(LambdaVersion="V2_0"),
    lambda idp: idp.clients["cust-123"].update(WriteAttributes=["email", "custom:tenant_id"]),
    lambda idp: idp.clients["operator-123"].update(AllowedOAuthFlows=["implicit"]),
    lambda idp: idp.clients["agent-123"]["ExplicitAuthFlows"].clear(),
    lambda idp: idp.clients["agent-123"]["AllowedOAuthScopes"].remove("shadow-hunter-api/refunds"),
    lambda idp: idp.clients["agent-123"].pop("ClientSecret"),
])
def test_unsafe_cognito_configurations_fail_closed(mutation):
    idp = FakeCognito()
    mutation(idp)
    with pytest.raises(SmokeFailure):
        _inspect_identity(idp, output_values(), "ap-southeast-2")


def test_mfa_test_user_removed_when_login_challenge_fails(monkeypatch):
    idp = FakeCognito()
    monkeypatch.setattr(
        "scripts.smoke_cognito_identity._create_synthetic",
        lambda *args, **kwargs: ("synthetic@example.com", "not-a-real-password"),
    )
    monkeypatch.setattr(
        "scripts.smoke_cognito_identity._srp_login",
        lambda *args: {"ChallengeName": "SOFTWARE_TOKEN_MFA"},
    )
    with pytest.raises(SmokeFailure, match="TOTP enrollment"):
        _check_mfa_user(idp, output_values(), operator=True)
    assert idp.deleted == ["synthetic@example.com"]
