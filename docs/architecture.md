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

The event page currently describes a managed Bedrock agent challenge. AWS documentation states that Amazon Bedrock Agents Classic stopped accepting new customers on 30 July 2026 and recommends AgentCore for equivalent managed-agent capabilities. The current implementation therefore targets the AgentCore managed Harness API, with an AgentCore Gateway attached as a Harness tool and a Cedar Policy Engine attached to that Gateway in ENFORCE mode.

The Harness adapter invokes the deployed Harness through boto3's bedrock-agentcore invoke_harness operation. It sets runtimeUserId and actorId metadata but currently uses SigV4. AWS explicitly documents that SigV4 callers do not propagate per-user identity into downstream tool calls. Before exposing this path to end users, configure a CUSTOM_JWT authorizer on the Harness, invoke with the user's Bearer JWT, and verify AgentCore Identity/Gateway propagation to the application tool boundary. The current adapter is an integration scaffold, not an end-user-ready authenticated chain. It does not create resources. Harness configuration, OpenAPI target schema, and Cedar policy template are under infra/agentcore/.

The Cedar policy is an outer allowlist for the three read/request tools. It does not replace application checks for customer identity, tenant ownership, eligibility, remaining balance, idempotency, or human approval. The Gateway must use a production authorizer; the AWS tutorial's NONE authorizer is not suitable for deployment.

Official references:
- https://docs.aws.amazon.com/bedrock/latest/userguide/agents-classic-maintenance-mode.html
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/harness.html
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/harness-tools.html
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-getting-started.html
- https://docs.aws.amazon.com/bedrock-agentcore/latest/APIReference/API_InvokeHarness.html

## Authentication

The current environment-backed token map is a local development adapter. It compares opaque bearer tokens and resolves trusted principal attributes from server-side environment configuration. It is not Cognito integration and must not be used as the production identity provider.

Production deployment must validate user JWTs at API Gateway/Cognito or an equivalent authorizer and pass verified claims to the application. Do not accept tenant/customer identity from user prompts, Harness tool arguments, or unsigned headers.

## Data and deployment status

SQLite is a local/demo adapter. The local execution endpoint modifies only the demo ledger. It does not call a payment gateway, bank, or external refund provider. The production store, Lambda/API Gateway packaging, Cognito authorizer, CloudWatch retention/alarms, KMS, and infrastructure-as-code deployment remain unimplemented.

Do not deploy, create paid AWS resources, or modify credentials without explicit owner approval.
