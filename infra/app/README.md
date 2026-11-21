# Shadow Hunter Lambda and HTTP API deployment

This package deploys the existing FastAPI application as a Python Lambda
function behind API Gateway HTTP API. It does not create Cognito, AgentCore,
or the DynamoDB table; those prerequisites are deployed separately.

## Architecture

- API Gateway HTTP API supplies route-specific Cognito JWT authorizers.
- Customer chat accepts only the customer app-client audience and customer
  scope.
- Agent tool calls accept only the resource audience and delegated refund
  scope from the AgentCore OBO token.
- Operator API routes require the operator app-client audience. FastAPI also
  checks the configured Cognito operator group.
- FastAPI repeats cryptographic JWT verification and validates token-use,
  issuer, subject, customer claims, audience, scope, and delegated actor. API
  Gateway authorization is an outer gate, not a replacement for application
  policy.
- The Lambda execution role can read/write only the configured DynamoDB table
  and query its GSI1. It has no table-administration or Scan permission.
- API Gateway access logs and Lambda logs retain 30 days. The HTTP API has a
  default route throttle of 20 requests/second with a burst of 40; Lambda
  reserved concurrency is 10.
- The synchronous Harness chat endpoint is bounded by a 28-second Lambda
  timeout. It is not a streaming WebSocket endpoint.

## Prerequisites

1. Deploy infra/data/dynamodb.yaml and record its TableName and TableArn
   outputs.
2. Use infra/cognito/identity-stack.yaml for a new production User Pool, or
   infra/cognito/pre-token-generation.yaml only for an existing pool. Configure
   the required SES sender, hosted domain, customer/operator callbacks, V3
   trigger, scopes, and delegated token exchange as described in
   infra/cognito/README.md.
3. Deploy the AgentCore Harness and Gateway, attach Cedar in ENFORCE mode,
   configure the Harness CUSTOM_JWT authorizer, and configure the Gateway
   target with OBO TOKEN_EXCHANGE as described in infra/agentcore/README.md.
4. Ensure the original customer access token contains both the configured
   customer scope and the delegated refund scope. Cognito token exchange
   cannot add scopes that the subject token does not contain.
5. Set the expected act.sub to the value actually issued by Cognito for the
   agent actor. The API function also verifies this exact value.

## Build and deploy

Run from the repository root after the templates and parameter values have
been reviewed:

    sam build --template-file infra/app/template.yaml --use-container

    sam deploy --guided --template-file .aws-sam/build/template.yaml

Supply these parameters when prompted:

- Environment
- DynamoDBTableName and DynamoDBTableArn from the DynamoDB stack
- CognitoIssuer
- CognitoCustomerClientId
- CognitoOperatorClientId
- CognitoHostedUiDomain (required HTTPS Cognito Hosted UI base URL)
- CognitoToolAudience
- CognitoActorSubject
- RefundLimitMinor (set the approved amount in minor units)
- optionally scopes, operator group, approval TTL, and Harness ARN

The SAM build uses src/requirements.txt; Mangum adapts the FastAPI ASGI app
to Lambda HTTP API events. The package includes FastAPI, PyJWT/cryptography,
boto3, and the MCP SDK because FastAPI constructs the MCP server during app
initialization.

## Routes and authorization

| Route | API Gateway authorizer | Additional application check |
|---|---|---|
| GET /health | Public | Health metadata only |
| GET /operator | Public static HTML | Operator data APIs remain authenticated |
| POST /v1/agent/chat | Customer JWT + customer scope | Cognito customer profile |
| POST /v1/agent/tools/{tool_name} | OBO JWT + refund scope | Resource audience, subject, act.sub, and customer claims |
| /v1/operator/{proxy+} | Operator app-client JWT | Cognito operator group |

The API does not configure a broad default authorizer or unauthenticated
catch-all route. All business API paths are explicitly covered by the
corresponding route authorizer. FastAPI still applies its own authentication
checks, so direct Lambda invocation does not bypass authorization.

## MCP exposure boundary

The application mounts the AgntID-facing MCP Streamable HTTP endpoint at
/mcp/, but this SAM template deliberately does not create an API Gateway
route for it. The current MCP server enforces localhost-only Host/Origin
protection. Do not expose it through a public API until an explicit public
host allowlist, TLS boundary, and AgntID credential/proxy contract have been
implemented and verified. The normal REST routes do not depend on the MCP
session-manager lifespan; the Lambda entrypoint uses lifespan=off.

## Operational boundaries

- SHADOW_HUNTER_DEMO_MODE is forced off in this template.
- The production template accepts only Environment=production. SQLite remains a local-only adapter.
- The DynamoDB refund operation still updates the Shadow Hunter demo ledger.
  It does not call a payment processor or send money.
- The Lambda role does not have permissions to create, update, or delete
  infrastructure.
- This guide describes a future production deployment. No AWS account, Region, credentials, or resources are used by the local validation workflow.
- Local SAM validate --lint, standalone cfn-lint, and SAM build passed for this template. This does not verify AWS deployment, live Cognito authorization, or service-side integration; no AWS resources have been deployed.
