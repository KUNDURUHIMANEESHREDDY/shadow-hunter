# Shadow Hunter staging AWS cost alert (not a hard spending limit)

As verified from the authorized account on 23 November 2026, AWS Budgets
returned **zero configured budgets**. The existing AgentCore deployment
preflight therefore correctly blocked release.

This change prepares an **account-wide** monthly budget and an improved
preflight. It does not create, update or delete AWS resources.

## Safe CloudFormation template

`infra/budgets/staging-budget.yaml` creates exactly one
`AWS::Budgets::Budget` with a name bound to the current AWS account.
A monthly USD amount defaults to **$10** and has a maximum template setting
of **$25**. Three account-wide email alerts are configured:

- 50% actual spend
- 80% actual spend
- 100% forecasted spend

This budget counts **the entire AWS account**, not just Shadow Hunter.
An existing spend in another project may trigger the alerts immediately.
A notification is never a hard stop or spending guarantee; protect billable
AgentCore calls separately with service quotas, IAM, allowed model selection,
invocation rate limits, logging, and a reviewed kill switch.

The alert receiver must be provided by the account owner and must confirm
their email subscription. Never infer an email from Git history or commit
an email address into the template.

## No-mutation verification and owner-approved deployment

Validate the template without creating resources:

```bash
aws cloudformation validate-template \
  --region us-east-1 \
  --template-body file://infra/budgets/staging-budget.yaml
python scripts/preflight_agentcore_staging.py
```

After the owner explicitly authorizes a budget resource creation and selects
both a monitored email recipient and the monthly USD budget value,
the following illustrates the *separate authorized* CloudFormation command:

```bash
aws cloudformation deploy \
  --region us-east-1 \
  --stack-name shadow-hunter-staging-budget \
  --template-file infra/budgets/staging-budget.yaml \
  --parameter-overrides NotificationEmail="<OWNER_APPROVED_ADDRESS>" MonthlyBudgetUsd=10
```

Do not run the command until the real recipient and budget amount are agreed.
Monitor the email account for AWS's verification request and confirm it; a
configured email subscriber alone is not proof alerts will be delivered.

The enhanced preflight refuses unrelated budgets, nonmonthly or filtered
budgets, a limit greater than $25, missing actual-spend warnings, or missing
email subscribers. This prevents a generic organization budget from masking
a missing staging safety control.

## Still required before live AgentCore

- A reviewed, owner-authorized **spending policy** and billable deployment
  scope for staging and separately for production.
- Confirmed functioning email alerts, not just configured subscribers.
- Hard service call/concurrency caps and emergency disable procedures.
- Actual AgentCore governed Gateway + Policy Engine deployment and Cognito
  delegated-token verification.
- Independent production security review, incident recovery and release signoff.

No production resources or hosted models were used to validate this template.

AWS reference:
https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-budgets-budget.html
