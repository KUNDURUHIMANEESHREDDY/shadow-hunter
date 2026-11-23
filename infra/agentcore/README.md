# Amazon Bedrock AgentCore integration

Shadow Hunter targets the AgentCore managed Harness, not the legacy Amazon
Bedrock Agents Classic APIs. AWS recommends AgentCore for managed agent
workloads. Recheck the AWS Builder Center challenge page for event-specific
requirements before final submission.

## Identity chain

The intended identity chain is:

1. The customer signs in with Amazon Cognito and sends an access-token JWT to
   Shadow Hunter's HTTPS API.
2. The API authenticates the customer for the local application boundary and
   forwards the same JWT to `InvokeHarness` as `Authorization: Bearer`.
   The adapter uses an unsigned Boto3 request with a token-scoped request
   handler; it does not sign the Harness call with SigV4. It never puts the
   token in the request body or application logs.
3. The Harness validates the JWT using its `CUSTOM_JWT` authorizer. AgentCore
   Identity can then carry the inbound user identity through downstream tool
   calls. The checked-in Harness template includes the authorizer.
4. The Harness calls the governed Gateway using the Harness execution role
   (`outboundAuth.awsIam`). This authenticates the Harness-to-Gateway service
   hop; it is not the user-delegation mechanism for the Gateway's API target.
5. Configure the Gateway OpenAPI target with OAuth
   `TOKEN_EXCHANGE` using an AgentCore Identity credential provider backed by
   Cognito. The Gateway exchanges the inbound user access token for a
   resource-scoped access token and sends that token to the Shadow Hunter API.
   Do not use the original user token as a generic shared credential.

### Cognito prerequisites for on-behalf-of exchange

Cognito User Pools added OAuth 2.0 token exchange (RFC 8693) on 12 November
2026. It requires the Essentials or Plus feature plan, token exchange enabled
for the account, a resource server/audience and scopes, and an app client
configured for the intended token-exchange flow. Use delegation semantics so
the derived token can identify the agent in its `act` claim.

Create an AgentCore Identity Custom OAuth2 credential provider for the Cognito
user pool. Its `onBehalfOfTokenExchangeConfig` should use
`grantType: TOKEN_EXCHANGE` and `tokenExchangeGrantTypeConfig.actorTokenContent: M2M`
when an actor identity is required. Configure the actor-token scope for the
agent app client. Keep the OAuth client secret in the AgentCore credential
provider / AWS-managed secret store; never commit it.

The Gateway target's outbound authorization should use the example in
`gateway-target-oauth.example.json`. Replace the provider ARN, resource
audience, and API scope with values registered in the Cognito user pool.
Cognito's resource server and token-exchange app-client configuration must
permit the requested scope and audience.

For Cognito, keep the Gateway target custom parameter subject_token_type=
urn:ietf:params:oauth:token-type:access_token. The generic AgentCore token-
exchange default is JWT; Cognito expects the access-token type. Also set
audience=shadow-hunter-api and request only shadow-hunter-api/refunds. The exact
target configuration is in gateway-target-oauth.example.json.

### Gateway target outbound authorization example

The OpenAPI `BearerAuth` declaration describes the target API's authentication
scheme; it does not, by itself, configure Gateway outbound credentials. Attach
the credential-provider configuration to the Gateway OpenAPI target when
creating the target. Select `OAUTH` and `TOKEN_EXCHANGE`, not
`GATEWAY_IAM_ROLE` or `JWT_PASSTHROUGH`, for this end-user identity hop.

### Application JWT verification

The application JWT verifier is implemented in `src/shadow_hunter/auth.py`.
Set `SHADOW_HUNTER_AUTH_MODE=cognito` and configure the variables below.
Customer chat validates the original access token against the customer app
client ID and customer scope. The Gateway tool route accepts only the derived
OBO token and validates its resource audience, refund scope, subject, issuer,
expiry, RS256 signature, and exact `act.sub` actor identity. Operator routes
require a configured Cognito group. In `local` mode the existing opaque token
maps remain available for local demos only; there is no fallback from Cognito
mode to local tokens.

Cognito pre-token-generation must emit trusted `tenant_id` and `customer_id`
claims into both customer and token-exchange access tokens. Use a V3_0 access
token customization event for this deployment because the same trigger must
also handle M2M ClientCredentials actor-token events. Derive these values from trusted user-pool
attributes or a tenant directory. The token-exchange trigger can customize
claims but cannot add scopes. Therefore the original subject token must
already contain the delegated scope requested for the target. The tool API
must not be exposed until the Cognito claims, scopes, OBO actor, and JWKS
issuer have been configured and independently verified.

### Required application configuration

Set `SHADOW_HUNTER_AUTH_MODE=cognito` and configure:

- `SHADOW_HUNTER_COGNITO_ISSUER` — exact Cognito user-pool issuer.
- `SHADOW_HUNTER_COGNITO_CUSTOMER_CLIENT_ID` — customer-facing app-client ID.
- `SHADOW_HUNTER_COGNITO_CUSTOMER_SCOPE` — defaults to `shadow-hunter/customer`.
- `SHADOW_HUNTER_COGNITO_TOOL_AUDIENCE` — registered resource-server audience in the OBO token.
- `SHADOW_HUNTER_COGNITO_TOOL_SCOPE` — defaults only in documentation; configure the exact `shadow-hunter-api/refunds` target scope.
- `SHADOW_HUNTER_COGNITO_ACTOR_SUB` — exact `act.sub` value issued for the delegated agent.
- `SHADOW_HUNTER_COGNITO_OPERATOR_GROUP` — defaults to `shadow_hunter_operators`.
- `SHADOW_HUNTER_COGNITO_OPERATOR_CLIENT_ID` — required separate operator app-client ID for the deployed API stack.

Register both customer and delegated refund scopes for the original subject-token app client. Cognito token exchange only down-scopes to the intersection of requested, subject-token, and client-allowed scopes; it cannot add a missing refund scope. The pre-token-generation V3_0 trigger should add trusted `tenant_id` and `customer_id` claims to both original and derived access tokens. The OBO token must contain an `act.sub` that matches the configured actor identity.

## Deployment sequence

1. Create a Cognito User Pool (or compatible OIDC provider), app client, and
   access-token scope for the customer-facing application.
2. Copy
   `app/refund-assistant/harness.yaml.example` to `harness.yaml`, replace
   placeholders, and deploy a Harness with the `CUSTOM_JWT` authorizer.
3. Create an AgentCore Gateway with JWT inbound authorization and attach the
   Cedar policy engine in `ENFORCE` mode.
4. Create the AgentCore Identity OBO OAuth credential provider backed by
   Cognito and attach its `TOKEN_EXCHANGE` outbound configuration to the
   Gateway OpenAPI target.
5. Configure the API target's HTTPS URL and verify that the API validates the
   derived token's audience, scope, subject, and actor claims.
6. Set `SHADOW_HUNTER_HARNESS_ARN` and `AWS_REGION` for the Shadow Hunter
   API. Invoke `/v1/agent/chat` with a real Cognito access-token JWT.
7. Verify that each Harness tool call traverses the Gateway, the policy engine
   runs in `ENFORCE` mode, and the API receives a target-scoped OBO token.
8. Run cross-customer, wrong-audience, wrong-scope, expired-token, and missing
   actor-claim tests before enabling the endpoint for users.

## Local application

Install the server and AWS extras with the project instructions in the root
README. Without `SHADOW_HUNTER_HARNESS_ARN`, the chat API returns 503 and
makes no external call. The local policy and approval API can be exercised
with the SQLite demo store and configured local bearer tokens.

A configured Harness requires a compact OIDC JWT access token. Opaque local
demo tokens are rejected by the Harness adapter rather than forwarded.
The checked-in Harness YAML and Gateway target JSON are configuration
examples, not deployed resources.

## Important boundaries

- Do not expose `execute_refund` as an agent tool. Refund execution is an
  operator-only API action requiring the one-time approval capability.
- The Cedar policy is an outer tool allowlist. Application checks still enforce
  customer identity, tenant ownership, eligibility, currency, refundable
  balance, idempotency, and human approval.
- The local SQLite side effect updates only a demo ledger. No payment provider
  or banking rail is called.
- Do not use the Gateway's `NONE` authorizer in production.
- Do not deploy until account, Region, IAM role, model access, cost limits,
  public endpoint, OBO credential provider, and application JWT verification
  have been reviewed.
- The `act` claim is evidence of delegation, not a replacement for validating
  the subject, audience, scopes, and policy at the application boundary.

## Official references

- AgentCore Harness security:
  https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/harness-security.html
- AgentCore Gateway outbound authorization:
  https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-outbound-auth.html
- AgentCore OBO token exchange:
  https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/on-behalf-of-token-exchange.html
- AgentCore Gateway target credentials:
  https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-building-adding-targets-authorization.html
- InvokeHarness API:
  https://docs.aws.amazon.com/bedrock-agentcore/latest/APIReference/API_InvokeHarness.html
- Cognito token exchange:
  https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-token-exchange.html
- Cognito token-exchange announcement (12 November 2026):
  https://aws.amazon.com/about-aws/whats-new/2026/11/cognito-token-exchange/
- AgentCore Agents Classic maintenance mode:
  https://docs.aws.amazon.com/bedrock/latest/userguide/agents-classic-maintenance-mode.html
- Hackathon:
  https://builder.aws.com/build/hackathons/61c39fba-1383-37e7-bd5c-3f9d889d89fc/agents-your-rules-bedrock-managed-agents-build

## Staging Harness CloudFormation template (23 November 2026)

The new `harness-staging.yaml` defines the managed Harness **only**. The
Gateway, Policy Engine in ENFORCE mode, approved least-privilege execution
role, protected OpenAPI target and Identity OBO credential provider must
exist and pass `scripts/verify_agentcore_staging.py` before this stack
can be considered usable. Supplying an arbitrary gateway ARN is **not**
proof of policy enforcement.

Review the parameters for the approved Sydney account and Region:
`HarnessExecutionRoleArn`, `GovernedGatewayArn`,
`CustomerDiscoveryUrl`, `CustomerClientId`, and `ApprovedModelId`.
No default model or execution role is selected to avoid silent provider
charges or privileges. The template limits iterations to four, model
tokens to 800 per call, total output tokens to 1600 and invocation
duration to 45 seconds. These are not spending caps.

Non-mutating local validation:

```sh
cfn-lint infra/agentcore/harness-staging.yaml
python -m pytest -q tests/test_agentcore_staging_control.py tests/test_verify_harness_tool_e2e.py
python scripts/preflight_agentcore_staging.py
```

The mandatory budget/verified alert subscriber gate currently fails.
Do not create a CloudFormation change set, deploy this template or invoke
hosted inference until the organization administrator has approved the
CloudFormation path, the AWS account owner has approved concrete costs
and model quotas, and independent provider-spend limits and a kill switch
have been reviewed. AWS Budgets alerts do not prevent charges.

After authorized infrastructure deployment, run the control-plane verifier
with actual resource IDs and **then**, with short-lived synthetic Cognito JWTs
and a synthetic order, run `verify_harness_tool_e2e.py --invoke-model`.
The evidence checker now requires the exact order resource ID, versioned
policy allow receipt, and no observed tool failures or refund execution.
The Harness-to-Gateway-to-API trace propagation still needs genuine live
verification: the API will generate a distinct trace ID if the gateway
does not pass one. Never replace missing correlated audit evidence with
a model assertion.
