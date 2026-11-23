from __future__ import annotations

from dataclasses import replace

from scripts.verify_agentcore_staging import Expected, verify


EXPECTED = Expected(
    harness_id="harness-1",
    gateway_id="gateway-1",
    target_id="target-1",
    policy_engine_id="policy-1",
    credential_provider_name="staging-obo",
    issuer="https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_test",
    customer_client_id="customer-app",
)


class FakeControl:
    def __init__(self):
        discovery = EXPECTED.issuer + "/.well-known/openid-configuration"
        self.harness = {
            "status": "READY",
            "authorizerConfiguration": {
                "customJWTAuthorizer": {
                    "discoveryUrl": discovery, "allowedClients": ["customer-app"]
                }
            },
            "tools": [{
                "type": "agentcore_gateway",
                "config": {"agentCoreGateway": {"gatewayArn": "arn:example:gateway"}}
            }]
        }
        self.gateway = {
            "status": "READY", "gatewayArn": "arn:example:gateway",
            "authorizerType": "CUSTOM_JWT",
            "authorizerConfiguration": {
                "customJWTAuthorizer": {
                    "discoveryUrl": discovery, "allowedClients": ["customer-app"]
                }
            },
            "policyEngineConfiguration": {"arn": "arn:example:policy", "mode": "ENFORCE"}
        }
        self.policy = {"status": "ACTIVE", "policyEngineArn": "arn:example:policy"}
        self.provider = {
            "status": "READY", "credentialProviderArn": "arn:example:oauth"
        }
        self.target = {
            "status": "READY", "targetConfiguration": {"http": {"openApiSchema": {}}},
            "credentialProviderConfigurations": [{
                "credentialProviderType": "OAUTH",
                "credentialProvider": {
                    "oauthCredentialProvider": {
                        "providerArn": "arn:example:oauth",
                        "grantType": "TOKEN_EXCHANGE",
                        "scopes": ["shadow-hunter-api/refunds"],
                        "customParameters": {
                            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                            "audience": "shadow-hunter-api"
                        }
                    }
                }
            }]
        }

    def get_harness(self, *, harnessId):
        assert harnessId == EXPECTED.harness_id
        return {"harness": self.harness}

    def get_gateway(self, *, gatewayIdentifier):
        assert gatewayIdentifier == EXPECTED.gateway_id
        return self.gateway

    def get_gateway_target(self, *, gatewayIdentifier, targetId):
        assert (gatewayIdentifier, targetId) == (EXPECTED.gateway_id, EXPECTED.target_id)
        return self.target

    def get_policy_engine(self, *, policyEngineId):
        assert policyEngineId == EXPECTED.policy_engine_id
        return self.policy

    def get_oauth2_credential_provider(self, *, name):
        assert name == EXPECTED.credential_provider_name
        return self.provider


def test_verified_control_plane_has_no_missing_security_boundaries():
    assert verify(FakeControl(), EXPECTED) == []


def test_gateway_policy_log_only_is_rejected():
    fake = FakeControl()
    fake.gateway["policyEngineConfiguration"]["mode"] = "LOG_ONLY"
    assert "Gateway policy is not in ENFORCE mode" in verify(fake, EXPECTED)


def test_passthrough_tool_tokens_are_rejected():
    fake = FakeControl()
    fake.target["credentialProviderConfigurations"][0]["credentialProviderType"] = "JWT_PASSTHROUGH"
    assert any("must use OAUTH" in issue for issue in verify(fake, EXPECTED))


def test_wrong_client_or_discovery_url_is_rejected():
    fake = FakeControl()
    issues = verify(fake, replace(EXPECTED, customer_client_id="untrusted"))
    assert any("client" in issue.lower() for issue in issues)


def test_wrong_gateway_or_oauth_provider_is_rejected():
    fake = FakeControl()
    fake.harness["tools"][0]["config"]["agentCoreGateway"]["gatewayArn"] = "arn:wrong"
    fake.target["credentialProviderConfigurations"][0]["credentialProvider"]["oauthCredentialProvider"]["providerArn"] = "arn:wrong"
    issues = verify(fake, EXPECTED)
    assert any("governed Gateway" in issue for issue in issues)
    assert any("expected OBO" in issue for issue in issues)
