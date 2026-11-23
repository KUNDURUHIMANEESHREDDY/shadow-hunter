"""Read-only staging prerequisites before ANY billable AgentCore deployment.

Uses the active AWS SDK login, never fetches customer records or prints tokens,
credentials, account IDs, client secrets, or stack outputs.
A budget alert is a notification, not a spending cap.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field

REGION = "ap-southeast-2"
STACKS = (
    "shadow-hunter-data-staging",
    "shadow-hunter-identity-staging",
    "shadow-hunter-api-staging",
)
EXPECTED_API = "https://eh90jsiseg.execute-api.ap-southeast-2.amazonaws.com/prod"


@dataclass
class Checks:
    passed: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)

    def require(self, condition: bool, label: str) -> None:
        (self.passed if condition else self.blocked).append(label)


def check_cognito_config(pool: dict, customer: dict, operator: dict, agent: dict) -> Checks:
    checks = Checks()
    checks.require(pool.get("UserPoolTier") in ("ESSENTIALS", "PLUS"),
                   "Cognito supports Essentials/Plus token exchange")
    checks.require(pool.get("MfaConfiguration") == "ON",
                   "staging Cognito MFA is mandatory")
    checks.require(pool.get("DeletionProtection") == "ACTIVE",
                   "staging Cognito deletion protection")
    pretok = (pool.get("LambdaConfig") or {}).get("PreTokenGenerationConfig") or {}
    checks.require(pretok.get("LambdaVersion") == "V3_0",
                   "Cognito V3 pre-token trigger present")
    checks.require(customer.get("ClientId") != operator.get("ClientId"),
                   "customer/operator app clients must differ")
    checks.require("shadow-hunter/customer" in customer.get("AllowedOAuthScopes", []),
                   "customer app has customer scope")
    checks.require("shadow-hunter-api/refunds" in customer.get("AllowedOAuthScopes", []),
                   "customer app permits delegated refund scope")
    checks.require("client_credentials" in agent.get("AllowedOAuthFlows", []),
                   "agent app supports client credentials")
    checks.require("ALLOW_TOKEN_EXCHANGE_DELEGATION" in agent.get("ExplicitAuthFlows", []),
                   "agent app permits Cognito token-exchange delegation")
    checks.require(bool(agent.get("ClientSecret")),
                   "agent OAuth client secret exists (value never disclosed)")
    return checks


def has_budget_alert(client, account: str) -> bool:
    """Require an existing cost budget with a configured notification subscriber.

    AWS Budgets are NOT hard limits. A second spending/call-volume policy is
    required for production; this gate merely avoids an unmonitored staging
    deployment.
    """
    page = client.describe_budgets(AccountId=account)
    for budget in page.get("Budgets") or []:
        if budget.get("BudgetType") != "COST":
            continue
        try:
            notes = client.describe_notifications_for_budget(
                AccountId=account,
                BudgetName=budget["BudgetName"],
            ).get("Notifications") or []
            for note in notes:
                if note.get("NotificationType") not in ("ACTUAL", "FORECASTED"):
                    continue
                subscribers = client.describe_subscribers_for_notification(
                    AccountId=account,
                    BudgetName=budget["BudgetName"],
                    Notification=note,
                ).get("Subscribers") or []
                if subscribers:
                    return True
        except Exception:
            # No readable notification subscribers: do not assume alerting.
            continue
    return False


def run(session) -> Checks:
    checks = Checks()
    aws_account = session.client("sts", region_name=REGION).get_caller_identity()["Account"]
    cf = session.client("cloudformation", region_name=REGION)
    outputs: dict[str, dict[str, str]] = {}
    for name in STACKS:
        stacks = cf.describe_stacks(StackName=name).get("Stacks") or []
        active = len(stacks) == 1 and stacks[0].get("StackStatus") in (
            "CREATE_COMPLETE", "UPDATE_COMPLETE"
        )
        checks.require(active, f"{name} CloudFormation stack is complete")
        if not active:
            return checks
        outputs[name] = {
            x["OutputKey"]: x.get("OutputValue", "")
            for x in stacks[0].get("Outputs") or []
        }
    identity = outputs[STACKS[1]]
    checks.require(outputs[STACKS[2]].get("ApiBaseUrl", "").rstrip("/") == EXPECTED_API,
                   "API staging URL matches the approved deployment")
    required = ("UserPoolId", "CustomerClientId", "OperatorClientId", "AgentAppClientId")
    if any(not identity.get(key) for key in required):
        checks.blocked.append("Cognito stack must expose all four identity outputs")
        return checks
    cognito = session.client("cognito-idp", region_name=REGION)
    pool_id = identity["UserPoolId"]
    pool = cognito.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    client_data = [
        cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=identity[key])["UserPoolClient"]
        for key in ("CustomerClientId", "OperatorClientId", "AgentAppClientId")
    ]
    identity_checks = check_cognito_config(pool, *client_data)
    checks.passed.extend(identity_checks.passed)
    checks.blocked.extend(identity_checks.blocked)
    try:
        monitored = has_budget_alert(
            session.client("budgets", region_name="us-east-1"),
            aws_account,
        )
    except Exception:
        monitored = False
    checks.require(monitored, "AWS cost budget has at least one notification subscriber")
    # No model invocation or cloud mutations. Verify the control plane is reachable.
    control = session.client("bedrock-agentcore-control", region_name=REGION)
    control.list_gateways(maxResults=1)
    control.list_harnesses(maxResults=1)
    checks.passed.append("AgentCore control-plane listings accessible in Sydney")
    return checks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", choices=[REGION], default=REGION)
    args = parser.parse_args(argv)
    try:
        import boto3
        result = run(boto3.session.Session(region_name=args.region))
    except Exception as exc:
        # No user data, AWS IDs, error bodies, or credentials are printed.
        print("BLOCKED AWS preflight could not complete:", type(exc).__name__)
        return 2
    for label in result.passed:
        print("PASS", label)
    for label in result.blocked:
        print("BLOCKED", label)
    print("NOTE AWS Budgets notify; they do not impose a hard spending cap.")
    return 0 if not result.blocked else 1


if __name__ == "__main__":
    raise SystemExit(main())
