"""Read-only AWS control-plane verifier for Shadow Hunter staging AgentCore.

This command does not create resources, read client secrets, or log JWTs.
It checks the managed configuration, not runtime identity propagation.
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class Expected:
    harness_id: str
    gateway_id: str
    target_id: str
    policy_engine_id: str
    credential_provider_name: str
    issuer: str
    customer_client_id: str


def verify(control, expected: Expected) -> list[str]:
    """Return generic failure reasons without exposing configurations or credentials."""
    errors: list[str] = []
    harness = control.get_harness(harnessId=expected.harness_id)["harness"]
    gateway = control.get_gateway(gatewayIdentifier=expected.gateway_id)
    target = control.get_gateway_target(
        gatewayIdentifier=expected.gateway_id, targetId=expected.target_id
    )
    policy = control.get_policy_engine(policyEngineId=expected.policy_engine_id)
    provider = control.get_oauth2_credential_provider(
        name=expected.credential_provider_name
    )
    discovery = expected.issuer.rstrip("/") + "/.well-known/openid-configuration"
    harness_auth = harness.get("authorizerConfiguration", {}).get("customJWTAuthorizer", {})
    gateway_auth = gateway.get("authorizerConfiguration", {}).get("customJWTAuthorizer", {})

    if harness.get("status") != "READY":
        errors.append("Harness is not READY")
    if harness_auth.get("discoveryUrl") != discovery:
        errors.append("Harness JWT discovery URL mismatch")
    if expected.customer_client_id not in harness_auth.get("allowedClients", []):
        errors.append("Harness customer client not authorized")
    if gateway.get("status") != "READY":
        errors.append("Gateway is not READY")
    if gateway.get("authorizerType") != "CUSTOM_JWT":
        errors.append("Gateway must use CUSTOM_JWT inbound authorizer")
    if gateway_auth.get("discoveryUrl") != discovery:
        errors.append("Gateway JWT discovery URL mismatch")
    if expected.customer_client_id not in gateway_auth.get("allowedClients", []):
        errors.append("Gateway does not authorize the customer client")
    if policy.get("status") != "ACTIVE":
        errors.append("Policy Engine is not ACTIVE")
    policy_config = gateway.get("policyEngineConfiguration") or {}
    if policy_config.get("mode") != "ENFORCE":
        errors.append("Gateway policy is not in ENFORCE mode")
    if policy_config.get("arn") != policy.get("policyEngineArn"):
        errors.append("Gateway is not attached to the expected policy engine")

    gateway_arn = gateway.get("gatewayArn")
    harness_tools = harness.get("tools") or []
    if not any(
        item.get("type") == "agentcore_gateway"
        and item.get("config", {}).get("agentCoreGateway", {}).get("gatewayArn") == gateway_arn
        for item in harness_tools
    ):
        errors.append("Harness does not use the governed Gateway")

    if target.get("status") != "READY":
        errors.append("Gateway target is not READY")
    # The OpenAPI target is exposed as an MCP gateway tool, not an HTTP
    # passthrough. Accepting `http` here would falsely certify an unrelated
    # target that cannot provide the governed refund tools.
    mcp_target = (target.get("targetConfiguration") or {}).get("mcp") or {}
    if not mcp_target.get("openApiSchema"):
        errors.append("Gateway target must provide the governed MCP OpenAPI schema")
    oauth_arn = provider.get("credentialProviderArn")
    if provider.get("status") != "READY" or not oauth_arn:
        errors.append("AgentCore Identity credential provider is not READY")
    credentials = target.get("credentialProviderConfigurations") or []
    if len(credentials) != 1:
        errors.append("Gateway target must have exactly one credential provider configuration")
    else:
        item = credentials[0]
        oauth = (item.get("credentialProvider") or {}).get("oauthCredentialProvider") or {}
        if item.get("credentialProviderType") != "OAUTH":
            errors.append("Gateway target must use OAUTH, not pass-through or shared IAM")
        if oauth.get("providerArn") != oauth_arn:
            errors.append("Gateway target does not use the expected OBO credential provider")
        if oauth.get("grantType") != "TOKEN_EXCHANGE":
            errors.append("Gateway target must use TOKEN_EXCHANGE")
        if oauth.get("scopes") != ["shadow-hunter-api/refunds"]:
            errors.append("Gateway target has an unexpected delegated refund scope")
        params = oauth.get("customParameters") or {}
        if params.get("subject_token_type") != "urn:ietf:params:oauth:token-type:access_token":
            errors.append("Gateway target must exchange the original access token")
        if params.get("audience") != "shadow-hunter-api":
            errors.append("Gateway target OBO resource audience is incorrect")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--harness-id", required=True)
    parser.add_argument("--gateway-id", required=True)
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--policy-engine-id", required=True)
    parser.add_argument("--credential-provider-name", required=True)
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--customer-client-id", required=True)
    args = parser.parse_args(argv)
    if not args.issuer.startswith("https://cognito-idp.ap-southeast-2.amazonaws.com/"):
        parser.error("Only the ap-southeast-2 Cognito staging issuer is permitted")
    expected = Expected(**vars(args))
    try:
        import boto3
        client = boto3.session.Session().client(
            "bedrock-agentcore-control", region_name="ap-southeast-2"
        )
        errors = verify(client, expected)
    except Exception as exc:
        # Authentication errors, missing AWS resources and service failures
        # fail closed. Do not print upstream responses or account details.
        print("FAIL AWS control-plane verification:", type(exc).__name__, file=sys.stderr)
        return 2
    for failure in errors:
        print("FAIL", failure)
    if errors:
        return 1
    print("PASS AgentCore control-plane configuration; live JWT E2E still required")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
