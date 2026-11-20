# Engineering cycle — production deployment readiness review

- Date: 2026-11-20
- Scope: Review the three SAM/CloudFormation templates and prepare an approval-gated production deployment plan.
- Reviewed main head: `0abe7f8b6eb1fbcfdd13961642a9ef4853e123bd`
- Status: Static review completed; formal SAM validation pending; no AWS deployment.

## Review outcome

- Confirmed the repository has three modular templates: Cognito pre-token Lambda, DynamoDB/S3 audit archive, and FastAPI/API Gateway.
- Reviewed template dependencies, parameters/outputs, IAM scopes, Lambda handlers, CodeUri paths and nested dependency manifests.
- Offline YAML parsing and local Ref/GetAtt checks passed for all three templates.
- Formal `sam validate --lint` could not be run because SAM CLI and cfn-lint are unavailable in the environment; network access prevented installing cfn-lint.
- No SAM build, tests, deployment commands, AWS API calls, or AWS resource modifications were performed.

## Readiness blockers recorded

- Cognito template deploys only a pre-token Lambda and invocation permission for an existing pool; the user pool, app clients, resource server/scopes, operator group, token-exchange configuration, and trigger association remain external/manual.
- The AgentCore guide contained V2 trigger references that conflicted with the Cognito V3_0 setup. The guide was corrected to V3_0 and the operator app client requirement clarified.
- Deployment sequencing must break the Harness ARN/API URL cycle: deploy API with no Harness ARN, configure Gateway/Harness against the API URL, then update the API stack with the Harness ARN.
- Existing audit reconciliation compares keys only. Added a separately scoped read-only auditor policy example and documented independent source-row/object-body verification for the final evidence demo.
- The production release remains blocked on formal SAM validation, Cognito foundation decisions/configuration, actual identity values, account/Region/cost approval, deployment and staging evidence.

## Files

- Added `docs/production-deployment-readiness.md`.
- Added `infra/data/audit-verification-policy.example.json`.
- Updated `infra/data/README.md` with the separate auditor role boundary.
- Updated `infra/agentcore/README.md` to consistently require V3_0 and a separate operator client.
- Updated the README deployment-readiness status.

## Safety / verification

No AWS resources, secrets, account settings, or credentials were accessed or changed. No tests, builds, SAM validation, deployments, or AWS integration checks were run. The offline static parser results are not a substitute for CloudFormation/SAM schema validation. All changes in this cycle remain untested.
