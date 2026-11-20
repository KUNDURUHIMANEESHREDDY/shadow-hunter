# Engineering cycle — Lambda and HTTP API deployment package

- Date: 2026-11-20
- Scope: Deployable FastAPI Lambda entrypoint, API Gateway HTTP API, and runtime IAM
- Status: Authored and committed; untested and not deployed

## Changes

- Added a lazy Mangum Lambda entrypoint so FastAPI is imported on first invocation and the adapter is reused across warm calls.
- Added a Lambda-specific requirements file with FastAPI, PyJWT/cryptography, boto3, the MCP SDK, and Mangum 0.22.0.
- Added a SAM template for Python 3.12 Lambda and API Gateway HTTP API.
- Added separate API Gateway JWT authorizers for customer chat, AgentCore OBO tool calls, and operator APIs.
- Customer, delegated-tool, and operator scopes/audiences are set per route. FastAPI repeats application-level JWT profile verification after the API Gateway authorizer.
- Kept health and static operator HTML routes public. All business API operations use their distinct route authorizer.
- Forced Cognito auth and DynamoDB storage in the Lambda environment and disabled demo mode.
- Limited the Lambda role to DynamoDB GetItem, PutItem, UpdateItem, Query, and TransactWriteItems on the configured table and GSI1.
- Added 30-day Lambda/API access log retention, API route throttling, and a reserved Lambda concurrency ceiling.
- Documented the deployment order, parameters, route authorizers, IAM boundary, and the 28-second synchronous chat limit.
- Deliberately omitted the localhost-only /mcp/ route from API Gateway. Public MCP exposure is blocked until a host allowlist and TLS/proxy boundary are implemented.
- Added an import-level Lambda entrypoint test.

## Security and operational boundaries

- The HTTP API has no broad catch-all route. Customer chat, OBO tool calls, and operator operations have separate JWT authorizers.
- API Gateway JWT validation is defense in depth. FastAPI independently checks signature, issuer, expiry, token-use, required scope, audience/client, actor, and business identity claims.
- The Lambda role has no DynamoDB Scan, DeleteItem, table administration, Cognito administration, or AgentCore resource-management permissions.
- Health and static operator HTML are public; operator data and action endpoints require the operator authorizer and group check.
- The MCP server remains localhost-only and is not reachable through the deployed HTTP API.
- Synchronous chat is bounded by a 28-second Lambda timeout. Longer/streaming sessions require a separate asynchronous or streaming transport.
- The deployment template is authored only; no AWS stack has been deployed.

## Verification

The Mangum 0.22.0 release is published on PyPI (22 August 2026), and the SAM per-route JWT authorizer syntax follows AWS SAM current HttpApi event and OAuth2Authorizer documentation. No SAM build, CloudFormation validation, tests, lint, formatting, or security scans were executed, consistent with docs/engineering-cycle.md.

## Next task

Add a protected audit-retention export path (for example, S3 Object Lock with a separate writer/reader role), then validate all deployment templates and exercise the end-to-end flow in an explicitly approved AWS environment.
