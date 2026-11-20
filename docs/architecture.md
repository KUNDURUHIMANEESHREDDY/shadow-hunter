# Architecture and integration decisions

## Current implementation boundary

Shadow Hunter implements one customer-support/refund workload. Agent-facing tools are restricted to order lookup, eligibility lookup, and refund-request creation. Refund execution is not exposed to the model or the AgentCore tool list. It is an operator-only action after a human approves the exact stored request.

The current application stack is:
- Python policy engine and tool gateway
- FastAPI API boundary
- SQLite local/demo persistence adapter
- Transactional single-table DynamoDB adapter for AWS
- Parameter-bound approval service
- Demo ledger execution in either local SQLite or DynamoDB (no payment provider)
- Append-oriented audit event table
- Minimal operator console served from the API
- Optional Amazon Bedrock AgentCore Harness client

The DynamoDB adapter preserves the SQLiteStore method contract and uses conditional TransactWriteItems for refund and approval state changes. It is implemented but untested and not deployed.

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

Audit entries include event type, decision, reason code, actor, tenant, resource, request/trace identifier, action digest, policy identifier/version, timestamp, and bounded structured details. Raw approval tokens are never written to audit records. The SQLite audit table is not immutable or tamper-evident.

For AWS persistence, every new DynamoDB item with entity_type=AUDIT is emitted through a NEW_IMAGE DynamoDB Stream to a separate exporter Lambda. The exporter allowlists audit fields, redacts nested secret-like keys, and writes deterministic JSON objects to an S3 bucket with Object Lock default retention. S3 requires conditional If-None-Match writes at the bucket-policy boundary; the exporter role has only PutObject on the audit-events prefix and no read, list, delete, retention-bypass, or retention-modification permissions.

The archive defaults to Governance retention for 365 days, configurable before deployment. Compliance mode is available only as an explicit deployment choice after confirming legal retention requirements. Failed stream batches go to an encrypted SQS DLQ and raise a CloudWatch alarm. DynamoDB Streams retains records for 24 hours; DLQ redrive, retention monitoring, and periodic reconciliation against archived event counts remain operational requirements. The exporter is authored but untested and undeployed; it does not backfill events created before stream enablement.

## AWS managed-agent integration

The event page describes a managed Bedrock agent challenge. Shadow Hunter targets the AgentCore managed Harness API, with an AgentCore Gateway attached as a Harness tool and a Cedar Policy Engine attached to that Gateway in ENFORCE mode.

The Harness adapter now forwards the authenticated caller's compact JWT access token in the `Authorization: Bearer` header. It creates an unsigned Boto3 client per invocation and attaches a token-scoped `before-send` handler restricted to the regional AgentCore data-plane hostname; this avoids SigV4 and avoids sharing bearer headers across concurrent users. The checked-in Harness template configures a `CUSTOM_JWT` authorizer with the Cognito discovery URL and allowed app client. AWS documents that SigV4 does not propagate per-user identity, while inbound OAuth does.

The Harness-to-Gateway hop still uses its execution role. For the Gateway-to-API target hop, configure AgentCore Identity on-behalf-of `TOKEN_EXCHANGE` rather than forwarding the original JWT or using a shared gateway role. Cognito supports RFC 8693 token exchange on Essentials and Plus plans. The example target credential configuration is under `infra/agentcore/gateway-target-oauth.example.json`.

The application now has distinct Cognito JWT profiles. The customer API validates user-pool RS256 signatures, issuer, expiration, token_use, customer app-client ID, customer scope, and required tenant/customer claims. The Gateway tool API validates the exchanged token signature, issuer, expiration, resource audience, delegated refund scope, user subject, and expected act.sub agent identity. The operator API requires a configured Cognito group. The local auth mode remains available for opaque development tokens; Cognito mode never falls back to local tokens. This is an application-side implementation, not proof of a deployed Cognito/AgentCore identity chain. Cognito claim customization, OBO provider, Harness, Gateway, target authorization, and Cedar policy still require account-specific setup. No AWS resources have been created or deployed.

## Authentication

The environment-backed opaque token map remains the local development adapter. Set SHADOW_HUNTER_AUTH_MODE=cognito to use Cognito JWT verification. Customer chat requires an access token with the configured customer app-client ID and customer scope. The tool API requires the delegated OBO access token with the configured target audience, refund scope, and exact act.sub actor identity. The operator API requires membership in the configured Cognito group.

JWT signing keys are loaded from the HTTPS user-pool JWKS endpoint. Only RS256 is accepted; issuer, expiry, issued-at, subject, token_use, audience where applicable, app client, scopes, and actor claims are validated before a Principal is created. Tenant/customer values are taken from verified claims only. Do not accept identity from user prompts, Harness tool arguments, unverified JWT payloads, or unsigned headers.

## DynamoDB persistence adapter

The optional DynamoDBStore is selected with SHADOW_HUNTER_STORE_BACKEND=dynamodb and preserves the SQLiteStore method contract. It uses a single table with one GSI for the operator audit and approval lists. Refund requests, tenant-scoped idempotency claims, approvals, approval pointers, audit events, and counters use separate partition/sort key namespaces.

Refund request creation, approval creation, approval/rejection transitions, and approved refund execution use conditional TransactWriteItems operations. The execution transaction conditionally decrements the trusted order balance, changes refund and approval state, consumes the approval token hash, writes the correlated audit event, and updates dashboard counters atomically. The public projection explicitly omits approval token hashes.

The table template is infra/data/dynamodb.yaml. It configures on-demand billing, GSI1, AWS-managed KMS encryption, 35-day point-in-time recovery, production deletion protection, and Retain policies. The global stats counter is a potential write hot key at higher throughput and should be sharded or asynchronously aggregated before scaling. The adapter remains untested and undeployed. DynamoDB audit rows are append-oriented but not WORM/tamper-evident.

## Lambda and HTTP API deployment

The FastAPI application has a lazy Lambda entrypoint at src/shadow_hunter/lambda_handler.py using Mangum. infra/app/template.yaml defines an HTTP API with separate Cognito JWT authorizers for customer chat, Gateway OBO tool calls, and operator routes. The Lambda repeats its own JWT profile verification and has only DynamoDB data-plane permissions for the configured table and GSI1. It has no infrastructure-administration permissions. The SAM package is untested and has not been deployed.

The application also mounts an AgntID-facing MCP Streamable HTTP endpoint, but the SAM template does not expose /mcp/. Its Host/Origin protection remains localhost-only, and a public host allowlist plus a separate TLS/proxy boundary must be completed before making it reachable from the internet.

The Lambda adapter disables ASGI lifespan because the public REST routes do not require the MCP session manager. The synchronous Harness chat path is bounded by a 28-second Lambda timeout; long-running/streaming agent sessions require a separate asynchronous or streaming design.

## Data and deployment status

SQLite remains the default local/demo adapter. Set SHADOW_HUNTER_STORE_BACKEND=dynamodb with SHADOW_HUNTER_DYNAMODB_TABLE and AWS_REGION to select the new AWS adapter. The single-table template uses an on-demand GSI1, KMS encryption, 35-day point-in-time recovery, production deletion protection, and Retain policies. The runtime adapter requires least-privilege GetItem, PutItem, UpdateItem, Query, and TransactWriteItems permissions. The adapter and table template are untested and undeployed. A SAM application template now describes the FastAPI Lambda and API Gateway HTTP API deployment, with route-specific customer, OBO-tool, and operator JWT authorizers plus a DynamoDB-only runtime IAM policy. The SAM package is authored but untested and undeployed. The Cognito user pool and AgentCore resources still require account-specific provisioning. The data stack now includes an untested DynamoDB Stream → S3 Object Lock export template, a separate writer role, conditional write enforcement, an encrypted SQS DLQ, and a CloudWatch DLQ alarm; it is not deployed and does not backfill historical rows. The DynamoDB refund path still only updates a demo ledger; it does not call an external payment provider.

Do not deploy, create paid AWS resources, or modify credentials without explicit owner approval.


## Autonomous local Red/Blue evaluation runtime

The Red/Blue runtime is an in-process deterministic strategy-and-reasoning harness in
src/shadow_hunter/agents.py. It does not call an LLM or model-provider API.

- Red uses AdversarialStrategyEngine to select a bounded pool of ownership,
  privilege-escalation, prompt-injection, parameter-tampering, type-confusion,
  approval-boundary, and legitimate-control scenarios. An observed policy-level
  attack acceptance increases that strategy family's priority on a later cycle.
- Blue uses BlueDefenseReasoner to classify untrusted proposal signals, assign a
  heuristic risk score, and recommend a handling action. This assessment is
  explanatory, not an authorization decision.
- Every Blue proposal is submitted to the existing ToolGateway. The deterministic
  PolicyEngine remains the final authority, and the refund execution tool remains
  unavailable to agents.
- Red and Blue messages are HMAC-SHA256 signed using separate agent-specific keys.
  Verification checks configured sender identity, recipient, timestamp window,
  payload integrity, and a single-use nonce. Nonce claims persist in SQLite or
  DynamoDB so a replay is rejected across application workers.
- The operator can trigger a bounded 1–20 round run. The run uses synthetic
  customer/order records in a temporary SQLite database. Aggregate metrics,
  redacted per-case outcomes, and allowlisted A2A/policy trace metadata are
  written to the primary audit store; raw messages, signatures, and secrets are not.
- The operator console reports attack success rate, defensive effectiveness,
  false-denial rate, expected policy-decision accuracy, and per-case reasoning
  evidence.

The HMAC envelope authenticates messages among processes that share configured
secrets; it is not a remote network transport, public-key identity system, or
replacement for TLS/mTLS. The current runtime is a deterministic autonomous
evaluation loop, not two LLM-driven agents. Risk scores are heuristic and must
not be interpreted as calibrated probabilities.

See docs/agent-evaluation.md for key configuration, metric definitions, and
operator usage.

## AgntID-facing MCP server

The FastAPI application mounts the official MCP Python SDK Streamable HTTP
server at /mcp/. It advertises only get_order, check_refund_eligibility, and
create_refund_request. Each handler delegates to the same ToolGateway used by
the existing application API; there is no second policy implementation.

An outer ASGI boundary requires exactly one Bearer token on every MCP HTTP
request and resolves the principal through authenticate_gateway_tool. In
Cognito mode this preserves the existing delegated-token checks, including
issuer, RS256 signature, expiry, audience, refund scope, subject, and act.sub.
The act.sub value is the server-assigned agent ID. Local opaque tokens use a
server-configured local agent ID and are restricted to local development.
MCP clientInfo and tool arguments never establish identity.

The operator-only refund execution route is not included in the MCP surface.
The MCP transport is localhost-only by default. AgntID proxy configuration and
the challenge-specific credential contract remain unverified; a token that
does not satisfy the existing verifier is rejected rather than trusted or forwarded.
See docs/agntid-integration.md.
