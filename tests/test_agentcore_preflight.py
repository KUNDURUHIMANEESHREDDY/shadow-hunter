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


from decimal import Decimal
from scripts.preflight_agentcore_staging import has_staging_cost_budget


class FakeProjectBudget:
    account = "111122223333"

    def __init__(self, *, name=None, amount="10", subscriber=True,
                 threshold=50, cost_filters=None, budget_type="COST",
                 pages=False):
        self.name = name or "shadow-hunter-staging-" + self.account
        self.amount = amount
        self.subscriber = subscriber
        self.threshold = threshold
        self.cost_filters = cost_filters
        self.budget_type = budget_type
        self.pages = pages

    def describe_budgets(self, *, AccountId, NextToken=None):
        assert AccountId == self.account
        data = {
            "BudgetName": self.name, "BudgetType": self.budget_type,
            "TimeUnit": "MONTHLY",
            "BudgetLimit": {"Unit": "USD", "Amount": self.amount},
        }
        if self.cost_filters is not None:
            data["CostFilters"] = self.cost_filters
        if self.pages and NextToken is None:
            return {"Budgets": [], "NextToken": "page2"}
        return {"Budgets": [data]}

    def describe_notifications_for_budget(self, *, AccountId, BudgetName, NextToken=None):
        assert BudgetName == self.name
        return {"Notifications": [{
            "NotificationType": "ACTUAL",
            "ComparisonOperator": "GREATER_THAN",
            "Threshold": self.threshold,
            "ThresholdType": "PERCENTAGE",
        }]}

    def describe_subscribers_for_notification(self, *, AccountId, BudgetName,
                                               Notification, NextToken=None):
        return {"Subscribers": [
            {"SubscriptionType": "EMAIL", "Address": "owner@example.invalid"}
        ] if self.subscriber else []}


def test_staging_budget_gate_requires_project_name_bounded_cost_and_alert():
    assert has_staging_cost_budget(FakeProjectBudget(), FakeProjectBudget.account)
    assert has_staging_cost_budget(FakeProjectBudget(pages=True), FakeProjectBudget.account)
    for fake in [
        FakeProjectBudget(name="unrelated-budget"),
        FakeProjectBudget(amount="100"),
        FakeProjectBudget(amount="NaN"),
        FakeProjectBudget(amount="0"),
        FakeProjectBudget(subscriber=False),
        FakeProjectBudget(threshold=100),
        FakeProjectBudget(cost_filters={"Service": ["Amazon EC2"]}),
        FakeProjectBudget(budget_type="USAGE"),
    ]:
        assert not has_staging_cost_budget(fake, FakeProjectBudget.account)


def test_staging_budget_gate_rejects_unknown_aws_account_number():
    assert not has_staging_cost_budget(FakeProjectBudget(), "test")
