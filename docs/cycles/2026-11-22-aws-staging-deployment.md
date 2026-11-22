# AWS staging deployment — live verification, 22 November 2026

## Scope and approval

The owner approved proceeding from templates to real AWS infrastructure.
The deployed target is **staging** in `ap-southeast-2` (Sydney), not
production. AWS CLI authentication was verified through STS. No local
credential stores, client secrets, or personal customer records were read.
Do not extrapolate this approval to future production deployments.

All three CloudFormation stacks completed successfully:

| Stack | Outcome | Primary resources |
|---|---|---|
| `shadow-hunter-data-staging` | CREATE_COMPLETE | DynamoDB, S3 Object Lock audit archive, stream exporter Lambda, SQS DLQ, CloudWatch alarm |
| `shadow-hunter-identity-staging` | CREATE_COMPLETE; callback update complete | Cognito User Pool and clients, V3 pre-token Lambda, operator group, resource servers |
| `shadow-hunter-api-staging` | CREATE_COMPLETE; routing update complete | FastAPI Lambda, API Gateway HTTP API, JWT route authorizers, two empty Secrets Manager entries and logs |

## Live URL

Staging operator console:
`https://eh90jsiseg.execute-api.ap-southeast-2.amazonaws.com/prod/operator`

Public API stage:
`https://eh90jsiseg.execute-api.ap-southeast-2.amazonaws.com/prod`

The console is public for unauthenticated page loading. Operator API calls
require Cognito JWT authorization and subsequent server-side group checking.
The operator client callback and logout URL were updated through CloudFormation
to the live `/prod/operator` URL. No human operator accounts were provisioned.

## Live evidence

- Actual DynamoDB staging table: `shadow-hunter-staging`, ACTIVE, GSI1
  present, NEW_IMAGE stream enabled, deletion protection enabled.
- Actual S3 archive: S3 Object Lock GOVERNANCE retention of **one day** for
  staging; production's 365-day template defaults were not used.
- Synthetic-only staging test:
  `PYTHONPATH=src python scripts/smoke_aws_data.py --apply`.
  It created a synthetic order, completed maker-checker approval and a demo
  ledger refund, verified retry idempotency, and observed a remaining
  refundable balance of 2800 minor units.
- The same trace had **3 DynamoDB audit events** and **3/3 matching S3
  archive objects**. This is a real stream/exporter data-plane verification,
  not a local emulator; it is not a full archive reconciliation or DAST.
- Cognito user pool: ESSENTIALS tier, MFA ON, deletion protection ACTIVE,
  V3 pre-token trigger configured, staging email mode COGNITO_DEFAULT.
  Operator app client writes only `email`, and only reads
  `email`/`email_verified`.
- API Gateway live HTTP results after fixing Mangum's named-stage prefix:
  `GET /health` 200; `GET /operator` 200;
  `GET /operator/config` 200;
  unauthenticated operator API 401; unauthenticated agent chat POST 401;
  unauthenticated agent tool POST 401. Health response has
  `agentcore_configured=false`, `demo_mode=false`.
  CSP anti-framing, X-Frame-Options and X-Content-Type-Options were present.
- Clean staging worktree full Python suite after routing fix: **187 passed**.
  `python scripts/validate-repo.py`, compilation, and Git diff checks pass.
- Stage CLI and CloudFormation template validation passed. The Windows-host
  SAM API build fails due to a Windows-only pywin32 wheel selection; the
  Linux-targeted ZIP generated in WSL builds without Docker and deployed
  successfully. Runtime HTTP checks validate the deployment bundle.

## Changes kept separate from production

- Data template `infra/data/dynamodb.yaml` now permits a `staging`
  environment while defaulting to `production`; deletion protection remains
  enabled for both. Retain policies remain in place.
- `scripts/prepare_staging_aws.py` generates untracked Cognito/API overlays
  from the production templates, restricting the overlay Environment to staging,
  using COGNITO_DEFAULT staging email, disabling hosted model evaluations,
  and applying conservative API Gateway throttle (rate 2, burst 3) and Lambda
  reserved concurrency (2). Production templates keep their SES requirement
  and normal model configuration.
- `src/shadow_hunter/lambda_handler.py` uses
  `SHADOW_HUNTER_API_BASE_PATH` for stage-prefix handling, and the app SAM
  template sets it to `/prod`. New regression tests simulate HTTP API v2
  stage-prefixed requests and unprefixed requests.
- `scripts/build_staging_lambda_linux.sh` installs Python 3.12-compatible
  Linux wheels in a temporary WSL filesystem directory and writes one ZIP.
  `scripts/package_staging_lambda.py` validates binary compatibility and
  creates the untracked SAM overlay pointing to that ZIP.
- No produced .aws-sam artifacts, generated templates, AWS secrets or
  credentials are committed.

## Reproduction (with separate deployment authorization)

Run from the repository root. The local Python environment should include
the project server/AWS/development dependencies; WSL Ubuntu needs pip.

```powershell
python scripts/prepare_staging_aws.py
sam build --template-file infra/data/dynamodb.yaml --build-dir .aws-sam/staging-data --no-use-container
sam build --template-file infra/cognito/identity-stack.staging-generated.yaml --build-dir .aws-sam/staging-identity --no-use-container
wsl -d Ubuntu -- bash -lc 'cd /mnt/c/Users/himan/projects/shadow-hunter-aws-staging && bash scripts/build_staging_lambda_linux.sh'
python scripts/package_staging_lambda.py
sam validate --template-file .aws-sam/staging-app-manual/template.yaml
python -m pytest -q
```

Use a **reviewed CloudFormation change set** and explicit parameters for
each stack. Data staging parameters:
`Environment=staging AuditRetentionDays=1 AuditRetentionMode=GOVERNANCE`.
Cognito stage parameters: `Environment=staging`, `UserPoolTier=ESSENTIALS`,
unique Cognito domain prefix, and HTTPS callbacks. Pass actual stack outputs
(TableName/Arn, CognitoIssuer, client IDs, tool audience and hosted UI URL)
into the API stack. Keep `HarnessArn` unset and the delegated actor subject
unverified/fail-closed until AgentCore integration has live token evidence.
Do not commit tokens or Secrets Manager values.

## Remaining release gates and costs

- **Not production-ready.** No real operator login/MFA session or delegated
  Cognito OBO agent token was exercised. No customers were provisioned.
- AgentCore managed Harness/Gateway/Policy is not deployed, so model-driven
  chat is not end-to-end functional. The current adapter fails closed for
  unverified actor identity. Hosted NVIDIA evaluations are disabled in staging.
- No real payment provider is integrated: execution uses the demo ledger.
- No comprehensive staging cross-tenant integration, UI reload/token recovery
  E2E, load/penetration test, external budget alert, or full S3 integrity
  reconciliation was performed.
- **Charges can accrue** for DynamoDB, S3, Secrets Manager, Cognito,
  Lambda/API Gateway, CloudWatch and related services. The throttle and
  concurrency limits are not a global spending cap. Retain policies and
  deletion protection may keep resources and charges after a stack is removed.
  Do not delete or bypass S3 retained objects without explicit lifecycle
  review, and do not treat stack deletion as a complete cleanup.
