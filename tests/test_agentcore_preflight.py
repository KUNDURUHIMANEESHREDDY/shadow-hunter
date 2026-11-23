from scripts.preflight_agentcore_staging import check_cognito_config, has_budget_alert


def pool():
    return {
        "UserPoolTier": "ESSENTIALS",
        "MfaConfiguration": "ON",
        "DeletionProtection": "ACTIVE",
        "LambdaConfig": {
            "PreTokenGenerationConfig": {"LambdaVersion": "V3_0"}
        },
    }


def apps():
    return (
        {
            "ClientId": "customer-id",
            "AllowedOAuthScopes": [
                "shadow-hunter/customer", "shadow-hunter-api/refunds"
            ],
        },
        {"ClientId": "operator-id"},
        {
            "ClientId": "agent-id",
            "AllowedOAuthFlows": ["client_credentials"],
            "ExplicitAuthFlows": ["ALLOW_TOKEN_EXCHANGE_DELEGATION"],
            "ClientSecret": "fake-secret-value-never-printed",
        },
    )


def test_cognito_preflight_allows_hardened_stage():
    result = check_cognito_config(pool(), *apps())
    assert result.blocked == []
    assert len(result.passed) == 10


def test_cognito_preflight_rejects_unsafe_identity():
    p = pool()
    p["MfaConfiguration"] = "OFF"
    customer, operator, agent = apps()
    operator["ClientId"] = customer["ClientId"]
    agent["ExplicitAuthFlows"] = []
    agent.pop("ClientSecret")
    result = check_cognito_config(p, customer, operator, agent)
    assert len(result.blocked) == 4
    assert not any("fake-secret" in x for x in result.blocked)


class FakeBudgets:
    def __init__(self, configured=True, subscriber=True):
        self.configured = configured
        self.subscriber = subscriber

    def describe_budgets(self, *, AccountId):
        return {"Budgets": [
            {"BudgetType": "COST", "BudgetName": "staging"}
        ] if self.configured else []}

    def describe_notifications_for_budget(self, *, AccountId, BudgetName):
        return {"Notifications": [
            {"NotificationType": "ACTUAL", "Threshold": 80.0}
        ]}

    def describe_subscribers_for_notification(self, *, AccountId, BudgetName, Notification):
        return {"Subscribers": [
            {"SubscriptionType": "EMAIL", "Address": "synthetic@example.invalid"}
        ] if self.subscriber else []}


def test_budget_alert_must_exist_with_subscriber():
    assert has_budget_alert(FakeBudgets(), "test") is True
    assert has_budget_alert(FakeBudgets(configured=False), "test") is False
    assert has_budget_alert(FakeBudgets(subscriber=False), "test") is False
