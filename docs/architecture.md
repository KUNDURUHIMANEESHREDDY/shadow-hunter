# Architecture and integration decisions

## Current implementation boundary

Shadow Hunter implements one customer-support/refund workload. Agent-facing tools are restricted to order lookup, eligibility lookup, and refund-request creation. Refund execution is not exposed to the model or the AgentCore tool list. It is an operator-only action after a human approves the exact stored request.

The current application stack is:
- Python policy engine and tool gateway
- FastAPI API boundary
- SQLite local/demo persistence adapter
- Parameter-bound approval service
- Local demo ledger execution (no payment provider)
- Append-oriented audit event table
- Minimal operator console served from the API
- Optional Amazon Bedrock AgentCore Harness client

This is a local end-to-end implementation slice, not a production AWS deployment.

## Trust boundaries

1. User identity is resolved by the API authentication boundary. Agent tool arguments cannot supply or override subject, tenant, or customer identity.
2. User prompts, order notes, retrieved text, tool output and model content remain untrusted data.
3. The model can propose only the explicitly registered agent tools. It cannot grant permissions or execute refunds.
4. The application gateway resolves the authenticated principal and loads order facts from trusted storage before calling the deterministic PolicyEngine.
5. The tool handler repeats resource ownership, tenant, currency, eligibility, refundable-balance, idempotency, and approval checks before changing state.
6. The approval service issues a random, one-time capability. Only its SHA-256 hash is stored. The raw token is returned once to the authenticated operator.
7. The local execution transition consumes the approval and changes the demo ledger balance in one SQLite transaction.
8. Audit rows correlate policy decisions, approval lifecycle events, blocked executions, and successful local-ledger execution.

## Tool contracts

AgentCore is configured with only these tools:
- get_order(order_id)
- check_refund_eligibility(order_id)
- create_refund_request(order_id, amount_minor, currency, reason, idempotency_key)

The application gateway rejects every other tool name. In particular, execute_refund is absent from the agent tool set and must not be added to the Harness Gateway target. The operator-only execute endpoint requires an authenticated operator identity and a capability created by the approval workflow.

## Policy outcomes

- ALLOW: the proposed read or refund request satisfies deterministic application policy.
- DENY: the request is malformed, unauthenticated, cross-tenant, cross-customer, ineligible, over the remaining refundable amount, currency-mismatched, unregistered, or conflicts with an existing idempotency key.
- ESCALATE: the request is valid but exceeds the configured self-service amount limit. It is stored as pending approval and cannot execute until an operator approves the bound request.

Even an ALLOW refund request remains pending operator approval before execution. This keeps the high-impact side effect behind an independent human approval boundary. The configured self-service limit decides whether a request is escalated; it does not grant the model payment authority.

## Approval and execution protocol

1. Normalize and policy-check the proposed request.
2. Compute an action digest covering the authenticated principal, tenant, customer, agent, tool name, order, and canonical arguments.
3. Create the refund request under a tenant-scoped idempotency key.
4. Create one approval row bound to the request ID, principal ID, tenant, action digest, policy ID/version, and expiry.
5. An authenticated operator approves or rejects the pending request.
6. Approval creates a cryptographically random token. Store only its hash; deliver the raw token once.
7. On execution, the service verifies token hash, approved status, expiry, exact stored digest/version, current policy ID/version, order ownership, eligibility, currency, and remaining balance.
8. A single SQLite transaction debits the demo refundable balance, marks the request executed, consumes the token, and appends the execution audit event.
9. Replaying the same token from the original executor returns the prior execution result without a second debit. Other tokens, operators, or parameters do not repeat the side effect.

The digest is a binding value, not a signature or authorization credential. Approval-token possession alone is insufficient without an approved database record and authenticated operator API access. Original request_id and trace_id values persist into approval and execution events, so the operator trace endpoint can return the complete event chain.

## Audit model

Audit entries include event type, decision, reason code, actor, tenant, resource, request/trace identifier, action digest, policy identifier/version, timestamp, and bounded structured details. Raw approval tokens are never written to audit records. The SQLite table is not immutable or tamper-evident and must not be described as WORM audit storage. Production retention requires a separately protected AWS audit sink/export.

## AWS managed-agent integration

The event page describes a managed Bedrock agent challenge. Shadow Hunter targets the AgentCore managed Harness API, with an AgentCore Gateway attached as a Harness tool and a Cedar Policy Engine attached to that Gateway in ENFORCE mode.

The Harness adapter now forwards the authenticated caller's compact JWT access token in the `Authorization: Bearer` header. It creates an unsigned Boto3 client per invocation and attaches a token-scoped `before-send` handler restricted to the regional AgentCore data-plane hostname; this avoids SigV4 and avoids sharing bearer headers across concurrent users. The checked-in Harness template configures a `CUSTOM_JWT` authorizer with the Cognito discovery URL and allowed app client. AWS documents that SigV4 does not propagate per-user identity, while inbound OAuth does.

The Harness-to-Gateway hop still uses its execution role. For the Gateway-to-API target hop, configure AgentCore Identity on-behalf-of `TOKEN_EXCHANGE` rather than forwarding the original JWT or using a shared gateway role. Cognito supports RFC 8693 token exchange on Essentials and Plus plans. The example target credential configuration is under `infra/agentcore/gateway-target-oauth.example.json`.

The application now has distinct Cognito JWT profiles. The customer API validates user-pool RS256 signatures, issuer, expiration, token_use, customer app-client ID, customer scope, and required tenant/customer claims. The Gateway tool API validates the exchanged token signature, issuer, expiration, resource audience, delegated refund scope, user subject, and expected act.sub agent identity. The operator API requires a configured Cognito group. The local auth mode remains available for opaque development tokens; Cognito mode never falls back to local tokens. This is an application-side implementation, not proof of a deployed Cognito/AgentCore identity chain. Cognito claim customization, OBO provider, Harness, Gateway, target authorization, and Cedar policy still require account-specific setup. No AWS resources have been created or deployed.

## Authentication

The environment-backed opaque token map remains the local development adapter. Set SHADOW_HUNTER_AUTH_MODE=cognito to use Cognito JWT verification. Customer chat requires an access token with the configured customer app-client ID and customer scope. The tool API requires the delegated OBO access token with the configured target audience, refund scope, and exact act.sub actor identity. The operator API requires membership in the configured Cognito group.

JWT signing keys are loaded from the HTTPS user-pool JWKS endpoint. Only RS256 is accepted; issuer, expiry, issued-at, subject, token_use, audience where applicable, app client, scopes, and actor claims are validated before a Principal is created. Tenant/customer values are taken from verified claims only. Do not accept identity from user prompts, Harness tool arguments, unverified JWT payloads, or unsigned headers.

## Data and deployment status

SQLite is a local/demo adapter. The local execution endpoint modifies only the demo ledger. It does not call a payment gateway, bank, or external refund provider. The production store, Lambda/API Gateway packaging, Cognito authorizer, CloudWatch retention/alarms, KMS, and infrastructure-as-code deployment remain unimplemented.

Do not deploy, create paid AWS resources, or modify credentials without explicit owner approval.
