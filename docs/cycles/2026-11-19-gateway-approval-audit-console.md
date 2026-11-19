# Engineering cycle — tool gateway, approval, audit, console, and AgentCore adapter

- Date: 2026-11-19
- Scope: Continue the first support/refund workload through a local end-to-end application slice
- Status: Authored and committed; untested by repository operating contract

## Implemented

- Added a single allowlisted agent tool gateway backed by the existing deterministic policy engine.
- Added an authenticated FastAPI API surface for agent chat, agent tool calls, operator approvals, local refund execution, audit, and health.
- Added a local environment-backed bearer-token resolver. Identity is resolved from server configuration rather than request-body claims.
- Added transactional SQLite persistence for orders, refund requests, approvals, and audit events.
- Added expiring approvals bound to principal, tenant, action digest, policy ID/version, and refund request.
- Added one-time approval capability generation; only the token hash is stored and the raw token is returned once.
- Added operator-only refund execution with downstream ownership, eligibility, currency, balance, expiry, token, and digest checks.
- Added idempotent local-ledger execution. A replay by the same executor does not debit the order twice.
- Added correlated audit events for policy decisions, approval requests/grants/rejections, blocked execution, and successful demo-ledger execution; approval and execution records retain original request and trace identifiers.
- Added an operator trace-detail endpoint and console view for the full request/approval/execution event chain.
- Added revalidation of the current policy ID/version immediately before refund execution; policy changes invalidate a pending approval.
- Added AgentCore runtimeUserId and traceId metadata and aligned session validation to the documented 33–100 character range.
- Added a basic operator console for approvals, policy decisions, recent events, and local execution.
- Added an optional boto3 AgentCore managed-Harness adapter invoking InvokeHarness.
- Added AgentCore Harness, OpenAPI target, and Cedar Policy template examples.
- Added tests for gateway behavior, authentication separation, idempotency, approval execution, and agent execution denial.

## Explicit limitations

- SQLite is only a local/demo adapter. No AWS data store, Lambda, API Gateway, Cognito, KMS, CloudWatch, or IaC resources have been deployed.
- The execution path updates a local demo refundable-balance ledger; it does not send money or call a payment provider.
- The bearer-token map is development-only. Production needs verified Cognito/JWT identity and safe propagation through the AgentCore Gateway target.
- The Harness and Gateway template requires account-specific IAM roles, ARNs, API host, target creation, and an ENFORCE-mode Cedar policy engine before it can run in AWS.
- The current Boto3 Harness adapter uses SigV4. AWS documents that SigV4 does not propagate per-user identity into downstream tools; end-user deployment needs a CUSTOM_JWT authorizer and Bearer-JWT identity propagation. That path is not implemented yet.
- The operator console is intentionally small and is not a finished product UI.
- SQLite audit rows are not immutable or tamper-evident.
- The event listing currently says full details are coming soon; the final submission requirements may change.

## Verification

Tests, build, lint, formatting, and security scans were not executed, consistent with docs/engineering-cycle.md. GitHub file reads and branch-head confirmation are repository integrity checks only, not runtime verification.

## Next tasks

1. Resolve production authentication and tenant-claim propagation from AgentCore Gateway to the API.
2. Add a Lambda/API Gateway deployment package and AWS transactional data store.
3. Deploy the AgentCore Gateway and ENFORCE-mode Policy Engine, then validate actual tool-call interception.
4. Deploy and invoke the AgentCore Harness in an approved AWS account/region.
5. Complete the CUSTOM_JWT/Bearer identity propagation path through Harness, Gateway, and application tools.
6. Add a fixed adversarial evaluation runner with baseline/protected measurements.
7. Authorize and run regression/security tests before any production deployment.
