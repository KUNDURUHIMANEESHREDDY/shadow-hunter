"""Staging-only, credential-safe live Cognito identity smoke checks.

No secrets, JWTs, session IDs, TOTP seeds or passwords are printed or written.
Requires a fresh AWS CLI/SDK session. --mfa creates two disposable users and
deletes them in finally; --obo uses a customer OAuth access token supplied only
via an environment variable (SRP access tokens do not carry API OAuth scopes).

Examples:
  python scripts/smoke_cognito_identity.py
  python scripts/smoke_cognito_identity.py --mfa
  SHADOW_HUNTER_SMOKE_CUSTOMER_ACCESS_TOKEN=... python scripts/smoke_cognito_identity.py --obo
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import os
import secrets
import sys
import time
from collections.abc import Mapping
from urllib.parse import urlsplit
from uuid import uuid4

REGION = "ap-southeast-2"
STACK = "shadow-hunter-identity-staging"
API = "https://eh90jsiseg.execute-api.ap-southeast-2.amazonaws.com/prod"
TOKEN_ENV = "SHADOW_HUNTER_SMOKE_CUSTOMER_ACCESS_TOKEN"


class SmokeFailure(RuntimeError):
    """A check failed. Keep AWS exceptions and secret material out of logs."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SmokeFailure(message)


def _totp(secret: str, clock: float | None = None) -> str:
    """RFC 6238 SHA-1 six-digit TOTP for ephemeral staging test accounts."""
    position = int((time.time() if clock is None else clock) // 30)
    key = base64.b32decode(secret.upper(), casefold=True)
    digest = hmac.new(key, position.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return f"{code % 1000000:06d}"


def _stack_outputs(cf: object, stack_name: str) -> dict[str, str]:
    _require(stack_name.endswith("-staging"), "Refusing a non-staging identity stack")
    stacks = cf.describe_stacks(StackName=stack_name)["Stacks"]
    _require(
        len(stacks) == 1 and stacks[0]["StackStatus"] in {"CREATE_COMPLETE", "UPDATE_COMPLETE"},
        "Identity staging stack is not complete",
    )
    outputs = {x["OutputKey"]: x["OutputValue"] for x in stacks[0].get("Outputs", [])}
    names = (
        "UserPoolId", "CognitoIssuer", "CognitoHostedUiDomain", "CustomerClientId",
        "OperatorClientId", "AgentAppClientId", "ToolAudience", "CustomerScope",
        "ToolScope", "AgentActorScope", "OperatorGroup",
    )
    _require(all(outputs.get(name) for name in names), "Identity stack outputs incomplete")
    return outputs


def _inspect_identity(idp: object, outputs: Mapping[str, str], region: str) -> dict:
    pool = idp.describe_user_pool(UserPoolId=outputs["UserPoolId"])["UserPool"]
    _require(pool.get("MfaConfiguration") == "ON", "Mandatory MFA is not enabled")
    _require("SOFTWARE_TOKEN_MFA" in pool.get("EnabledMfas", []),
             "TOTP MFA not enabled")
    trigger = pool.get("LambdaConfig", {}).get("PreTokenGenerationConfig", {})
    _require(trigger.get("LambdaVersion") == "V3_0", "Pre-token trigger is not V3_0")
    _require(pool.get("DeletionProtection") == "ACTIVE", "User pool deletion protection off")
    _require(
        outputs["CognitoIssuer"] ==
        f"https://cognito-idp.{region}.amazonaws.com/{outputs['UserPoolId']}",
        "Unexpected Cognito issuer",
    )
    for name in ("CustomerClientId", "OperatorClientId"):
        client = idp.describe_user_pool_client(
            UserPoolId=outputs["UserPoolId"], ClientId=outputs[name]
        )["UserPoolClient"]
        _require("ALLOW_USER_SRP_AUTH" in client.get("ExplicitAuthFlows", []),
                 f"{name} cannot perform SRP sign-in")
        _require(client.get("AllowedOAuthFlows") == ["code"],
                 f"{name} is not OAuth authorization-code only")
        _require(client.get("WriteAttributes") == ["email"],
                 f"{name} can write non-email identity attributes")
        _require(not client.get("ClientSecret"), f"{name} is not a public app client")
    agent = idp.describe_user_pool_client(
        UserPoolId=outputs["UserPoolId"], ClientId=outputs["AgentAppClientId"]
    )["UserPoolClient"]
    _require("ALLOW_TOKEN_EXCHANGE_DELEGATION" in agent.get("ExplicitAuthFlows", []),
             "Agent client does not permit delegated exchange")
    _require("client_credentials" in agent.get("AllowedOAuthFlows", []),
             "Agent client does not permit client credentials")
    _require(outputs["AgentActorScope"] in agent.get("AllowedOAuthScopes", []),
             "Agent actor scope not allowed")
    _require(outputs["ToolScope"] in agent.get("AllowedOAuthScopes", []),
             "Delegated tool scope not allowed")
    _require(bool(agent.get("ClientSecret")), "Agent client is not confidential")
    parsed = urlsplit(outputs["CognitoHostedUiDomain"])
    _require(parsed.scheme == "https" and bool(parsed.hostname),
             "Invalid hosted UI domain")
    return agent


def _create_synthetic(idp: object, outputs: Mapping[str, str], *, operator: bool):
    """Provision an isolated nonhuman user; never use real customer data."""
    username = f"sh-smoke-{uuid4().hex[:22]}@example.com"
    password = "SH!" + secrets.token_urlsafe(24) + "aA9"
    attributes = [
        {"Name": "email", "Value": username},
        {"Name": "email_verified", "Value": "true"},
    ]
    if not operator:
        attributes.extend([
            {"Name": "custom:tenant_id", "Value": "smoke-tenant"},
            {"Name": "custom:customer_id", "Value": "smoke-customer"},
        ])
    idp.admin_create_user(
        UserPoolId=outputs["UserPoolId"], Username=username,
        MessageAction="SUPPRESS", UserAttributes=attributes,
    )
    # Once created, ensure caller cleans up even if subsequent steps fail.
    try:
        idp.admin_set_user_password(
            UserPoolId=outputs["UserPoolId"], Username=username,
            Password=password, Permanent=True,
        )
        if operator:
            idp.admin_add_user_to_group(
                UserPoolId=outputs["UserPoolId"], Username=username,
                GroupName=outputs["OperatorGroup"],
            )
    except Exception:
        idp.admin_delete_user(UserPoolId=outputs["UserPoolId"], Username=username)
        raise
    return username, password


def _srp_login(idp: object, outputs: Mapping[str, str], username: str,
               password: str, client_id: str) -> dict:
    try:
        from pycognito.aws_srp import AWSSRP
        from pycognito.exceptions import SoftwareTokenMFAChallengeException
    except ImportError as exc:
        raise SmokeFailure("Install pycognito for live SRP MFA checks") from exc
    srp = AWSSRP(
        username=username, password=password,
        pool_id=outputs["UserPoolId"], client_id=client_id, client=idp,
    )
    try:
        return srp.authenticate_user()
    except SoftwareTokenMFAChallengeException as exc:
        return exc.get_tokens()


def _check_mfa_user(idp: object, outputs: Mapping[str, str], *, operator: bool) -> str:
    client_id = outputs["OperatorClientId"] if operator else outputs["CustomerClientId"]
    username, password = _create_synthetic(idp, outputs, operator=operator)
    try:
        first = _srp_login(idp, outputs, username, password, client_id)
        _require(first.get("ChallengeName") == "MFA_SETUP",
                 "First sign-in did not require TOTP enrollment")
        associated = idp.associate_software_token(Session=first["Session"])
        seed = associated["SecretCode"]  # In memory only, never logged.
        verified = idp.verify_software_token(
            Session=associated["Session"], UserCode=_totp(seed),
            FriendlyDeviceName="Shadow Hunter ephemeral smoke",
        )
        _require(verified.get("Status") == "SUCCESS",
                 "Cognito did not verify TOTP enrollment")
        completion = idp.respond_to_auth_challenge(
            ClientId=client_id, ChallengeName="MFA_SETUP",
            Session=verified["Session"],
            ChallengeResponses={"USERNAME": username},
        )
        _require(bool(completion.get("AuthenticationResult", {}).get("AccessToken")),
                 "MFA setup did not complete sign-in")
        # Fresh code for reauthentication: never assume re-use of an OTP works.
        until_next_step = 30 - (time.time() % 30)
        if until_next_step < 2:
            time.sleep(until_next_step + 1)
        else:
            time.sleep(until_next_step + 1)
        second = _srp_login(idp, outputs, username, password, client_id)
        _require(second.get("ChallengeName") == "SOFTWARE_TOKEN_MFA",
                 "Repeat sign-in did not challenge for TOTP")
        _require("AuthenticationResult" not in second,
                 "Tokens were issued before the MFA response")
        completed = idp.respond_to_auth_challenge(
            ClientId=client_id, ChallengeName="SOFTWARE_TOKEN_MFA",
            Session=second["Session"],
            ChallengeResponses={
                "USERNAME": second.get("ChallengeParameters", {}).get("USERNAME", username),
                "SOFTWARE_TOKEN_MFA_CODE": _totp(seed),
            },
        )
        token = completed.get("AuthenticationResult", {}).get("AccessToken", "")
        _require(bool(token), "Valid TOTP did not finish sign-in")
        if operator:
            return token
        # SRP tokens cannot replace an OAuth-scoped subject token for OBO.
        return token
    finally:
        idp.admin_delete_user(UserPoolId=outputs["UserPoolId"], Username=username)


def _check_obo(idp: object, outputs: Mapping[str, str], agent: Mapping[str, str],
               api_base: str, customer_token: str) -> None:
    import jwt
    import requests
    from shadow_hunter.auth import CognitoJWTAuthenticator

    _require(customer_token.count(".") == 2 and len(customer_token) <= 16384,
             f"Invalid {TOKEN_ENV}")
    client_id = outputs["AgentAppClientId"]
    secret = agent["ClientSecret"]  # In memory only; never print or write.
    domain = outputs["CognitoHostedUiDomain"]
    response = requests.post(
        domain + "/oauth2/token",
        data={"grant_type": "client_credentials", "scope": outputs["AgentActorScope"]},
        auth=(client_id, secret), timeout=15,
    )
    _require(response.status_code == 200, "Cognito refused M2M actor token")
    actor_token = response.json().get("access_token", "")
    jwks = jwt.PyJWKClient(outputs["CognitoIssuer"] + "/.well-known/jwks.json")
    actor_claims = jwt.decode(
        actor_token, jwks.get_signing_key_from_jwt(actor_token).key,
        algorithms=["RS256"], issuer=outputs["CognitoIssuer"],
        options={"verify_aud": False, "require": ["exp", "iat", "iss", "sub"]},
    )
    actor_sub = actor_claims["sub"]
    _require(actor_claims.get("client_id") == client_id, "Actor client mismatch")
    _require(actor_claims.get("token_use") == "access", "Actor token-use mismatch")
    _require(outputs["AgentActorScope"] in actor_claims.get("scope", "").split(),
             "Actor scope missing")
    verifier = CognitoJWTAuthenticator(
        issuer=outputs["CognitoIssuer"],
        customer_client_id=outputs["CustomerClientId"],
        customer_scope=outputs["CustomerScope"],
        tool_audience=outputs["ToolAudience"],
        tool_scope=outputs["ToolScope"],
        actor_subject=actor_sub,
        operator_client_id=outputs["OperatorClientId"],
        operator_group=outputs["OperatorGroup"],
    )
    subject = verifier.authenticate_customer(customer_token)
    _require(subject is not None, "Customer OAuth token rejected (scope/identity/JWKS)")
    exchanged = idp.get_derived_token(
        ClientId=client_id, ClientSecret=secret,
        SubjectToken=customer_token, SubjectTokenType="ACCESS_TOKEN",
        ActorToken=actor_token, ActorTokenType="ACCESS_TOKEN",
        Audiences=[outputs["ToolAudience"]], Scopes=[outputs["ToolScope"]],
        RequestedTokenType="ACCESS_TOKEN",
    )
    token = exchanged["IssuedToken"]
    derived = verifier.authenticate_gateway_tool(token)
    _require(derived is not None, "Derived OBO token failed app JWT verification")
    _require(
        (derived.subject_id, derived.tenant_id, derived.customer_id) ==
        (subject.subject_id, subject.tenant_id, subject.customer_id),
        "Token exchange changed the customer principal",
    )
    _require(verifier.authenticate_customer(token) is None,
             "Delegated token was wrongly accepted as customer token")
    _require(verifier.authenticate_gateway_tool(customer_token) is None,
             "Original customer token was wrongly accepted as delegated token")
    denied = requests.get(
        api_base.rstrip("/") + "/v1/operator/approvals",
        headers={"Authorization": "Bearer " + token}, timeout=15,
    )
    _require(denied.status_code in (401, 403),
             "Delegated token gained operator API access")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", default=REGION)
    parser.add_argument("--stack", default=STACK)
    parser.add_argument("--api-base", default=API)
    parser.add_argument("--mfa", action="store_true",
                        help="Create and delete synthetic staging users; exercise SRP and TOTP")
    parser.add_argument("--obo", action="store_true",
                        help=f"Exchange a real OAuth token supplied via {TOKEN_ENV}")
    args = parser.parse_args()
    _require(args.region == REGION and args.stack == STACK,
             "This smoke runner is restricted to known staging resources")
    _require(urlsplit(args.api_base).scheme == "https", "HTTPS API required")
    import boto3
    session = boto3.Session(region_name=args.region)
    cf = session.client("cloudformation")
    idp = session.client("cognito-idp")
    outputs = _stack_outputs(cf, args.stack)
    agent = _inspect_identity(idp, outputs, args.region)
    print("PASS: live Cognito staging pool, mandatory TOTP, clients and delegation config")
    if args.mfa:
        from shadow_hunter.auth import CognitoJWTAuthenticator
        operator_token = _check_mfa_user(idp, outputs, operator=True)
        _check_mfa_user(idp, outputs, operator=False)
        verifier = CognitoJWTAuthenticator(
            issuer=outputs["CognitoIssuer"],
            customer_client_id=outputs["CustomerClientId"],
            customer_scope=outputs["CustomerScope"],
            tool_audience=outputs["ToolAudience"],
            tool_scope=outputs["ToolScope"],
            actor_subject="not-used-in-operator-check",
            operator_client_id=outputs["OperatorClientId"],
            operator_group=outputs["OperatorGroup"],
        )
        _require(verifier.authenticate_operator(operator_token) is not None,
                 "Real operator MFA token failed application verification")
        import requests
        ok = requests.get(
            args.api_base.rstrip("/") + "/v1/operator/approvals",
            headers={"Authorization": "Bearer " + operator_token}, timeout=15,
        )
        _require(ok.status_code == 200, "Real MFA operator token failed API authorization")
        print("PASS: live customer/operator SRP + enrolled TOTP + repeated MFA; operator API 200")
    if args.obo:
        customer_token = os.environ.get(TOKEN_ENV, "").strip()
        _require(bool(customer_token), f"{TOKEN_ENV} must hold a real OAuth customer access token")
        _check_obo(idp, outputs, agent, args.api_base, customer_token)
        print("PASS: live M2M actor + derived OBO token + scoped principal + API isolation")
    if not (args.mfa or args.obo):
        print("Read-only inspection complete. Run --mfa and --obo for live sign-in/token proof.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SmokeFailure as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        # Do not dump exception bodies: SDK errors can contain request metadata.
        print(f"FAIL: unexpected {type(exc).__name__}; inspect local logs securely",
              file=sys.stderr)
        sys.exit(1)
