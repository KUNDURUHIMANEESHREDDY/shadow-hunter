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

The archive defaults to Governance retention for 365 days, configurable before deployment. Compliance mode is available only as an explicit deployment choice after confirming legal retention requirements. Failed stream batches go to an encrypted SQS DLQ and raise a CloudWatch alarm. DynamoDB Streams retains records for 24 hours. The SQS on-failure envelope contains batch metadata, not the original stream event payload; the replay tool therefore retrieves the original sequence range from the stream before using the same conditional S3 exporter. Replay is dry-run by default and deletes the DLQ message only after successful export. A key-level reconciliation command compares the AUDIT GSI identities with S3 object keys without reading archive bodies. These tools are authored but untested and undeployed; they do not backfill events created before stream enablement or recover stream records after the 24-hour retention window.

## AWS managed-agent integration

The event page describes a managed Bedrock agent challenge. Shadow Hunter targets the AgentCore managed Harness API, with an AgentCore Gateway attached as a Harness tool and a Cedar Policy Engine attached to that Gateway in ENFORCE mode.

The Harness adapter now forwards the authenticated caller's compact JWT access token in the `Authorization: Bearer` header. It creates an unsigned Boto3 client per invocation and attaches a token-scoped `before-send` handler restricted to the regional AgentCore data-plane hostname; this avoids SigV4 and avoids sharing bearer headers across concurrent users. The checked-in Harness template configures a `CUSTOM_JWT` authorizer with the Cognito discovery URL and allowed app client. AWS documents that SigV4 does not propagate per-user identity, while inbound OAuth does.

The Harness-to-Gateway hop still uses its execution role. For the Gateway-to-API target hop, configure AgentCore Identity on-behalf-of `TOKEN_EXCHANGE` rather than forwarding the original JWT or using a shared gateway role. Cognito supports RFC 8693 token exchange on Essentials and Plus plans. The example target credential configuration is under `infra/agentcore/gateway-target-oauth.example.json`.

The production Cognito design has separate customer, operator, and delegated-agent profiles. Customer access tokens require RS256/JWKS, issuer, expiry, token_use, customer app-client ID, customer scope, subject, tenant_id and customer_id. Gateway OBO tokens require the exact single resource audience, refund scope, subject, and act.sub agent identity. Operator tokens require a distinct operator app-client ID and the server-managed shadow_hunter_operators group; operators do not need fabricated customer claims. The V3-only pre-token trigger adds trusted tenant/customer claims only to customer and delegated-user tokens, passes M2M actor tokens through, and leaves operator-group tokens customer-claim-free. Synthetic offline tests exercise the real handler and verifier, but do not prove Cognito-issued tokens or a live AgentCore exchange. No AWS account or cloud resources were used.

## Authentication

The environment-backed opaque token map remains available only for local development. Production uses SHADOW_HUNTER_AUTH_MODE=cognito and requires all identity settings, including a separate SHADOW_HUNTER_COGNITO_OPERATOR_CLIENT_ID. The authenticator rejects identical customer/operator client IDs and delegated tokens with additional or mismatched resource audiences. Customer chat requires the customer app-client ID and customer scope; tool routes require the exact delegated audience, refund scope, and act.sub; operator routes require the distinct operator client and Cognito operator group.

The operator console now supports Cognito authorization-code login with PKCE (S256) for production. The hosted UI domain and public operator app-client ID are returned by the unauthenticated `GET /operator/config` endpoint; this response contains no secrets. The OAuth state and PKCE verifier are transient session-storage values, while the access token remains in page memory. The operator app client must be a public client without a client secret, enable authorization-code grant and the `openid` scope, and allow the deployed `/operator` URL as a callback. The API Gateway operator route and the FastAPI Cognito verifier both enforce operator authentication.

The operator Settings → Integrations & Secrets panel writes the NVIDIA API key and server-generated, distinct Red/Blue HMAC keys to two pre-provisioned Secrets Manager ARNs. Browser requests are operator-authenticated; the API never returns secret values or accepts arbitrary secret ARNs. The SAM template creates two retained secret resources when external ARNs are not supplied and grants the Lambda role only GetSecretValue and PutSecretValue on those exact resources. A configured Secrets Manager ARN takes precedence over direct local environment values so in-app changes are used by the next NIM or A2A initialization. See [operator integrations](operator-integrations.md).

JWT signing keys are loaded from the HTTPS user-pool JWKS endpoint. Only RS256 is accepted; issuer, expiry, issued-at, subject, token_use, audience where applicable, app client, scopes, and actor claims are validated before a Principal is created. Tenant/customer values are taken from verified claims only. Do not accept identity from user prompts, Harness tool arguments, unverified JWT payloads, or unsigned headers.

## DynamoDB persistence adapter

The optional DynamoDBStore is selected with SHADOW_HUNTER_STORE_BACKEND=dynamodb and preserves the SQLiteStore method contract. It uses a single table with one GSI for the operator audit and approval lists. Refund requests, tenant-scoped idempotency claims, approvals, approval pointers, audit events, and counters use separate partition/sort key namespaces.

Refund request creation, approval creation, approval/rejection transitions, and approved refund execution use conditional TransactWriteItems operations. The execution transaction conditionally decrements the trusted order balance, changes refund and approval state, consumes the approval token hash, writes the correlated audit event, and updates dashboard counters atomically. The public projection explicitly omits approval token hashes.

The table template is infra/data/dynamodb.yaml. It configures on-demand billing, GSI1, AWS-managed KMS encryption, 35-day point-in-time recovery, production deletion protection, and Retain policies. The global stats counter is a potential write hot key at higher throughput and should be sharded or asynchronously aggregated before scaling. The adapter remains untested and undeployed. DynamoDB audit rows are append-oriented but not WORM/tamper-evident.

## Lambda and HTTP API deployment

The FastAPI application has a lazy Lambda entrypoint at src/shadow_hunter/lambda_handler.py using Mangum. infra/app/template.yaml defines an HTTP API with separate Cognito JWT authorizers for customer chat, Gateway OBO tool calls, and operator routes. The Lambda repeats its own JWT profile verification and has only DynamoDB data-plane permissions for the configured table and GSI1. It has no infrastructure-administration permissions. The SAM template passes local SAM lint validation, standalone CloudFormation lint, and packaging; the AWS stack has not been deployed.

The application also mounts an AgntID-facing MCP Streamable HTTP endpoint, but the SAM template does not expose /mcp/. Its Host/Origin protection remains localhost-only, and a public host allowlist plus a separate TLS/proxy boundary must be completed before making it reachable from the internet.

The Lambda adapter disables ASGI lifespan because the public REST routes do not require the MCP session manager. The synchronous Harness chat path is bounded by a 28-second Lambda timeout; long-running/streaming agent sessions require a separate asynchronous or streaming design.

## Data and deployment status

SQLite remains the default local/demo adapter. Set SHADOW_HUNTER_STORE_BACKEND=dynamodb with SHADOW_HUNTER_DYNAMODB_TABLE and AWS_REGION to select the new AWS adapter. The single-table template uses an on-demand GSI1, KMS encryption, 35-day point-in-time recovery, production deletion protection, and Retain policies. The runtime adapter requires least-privilege GetItem, PutItem, UpdateItem, Query, and TransactWriteItems permissions. The DynamoDB adapter runtime remains untested; the data-stack template passes local SAM lint validation, standalone CloudFormation lint, and packaging, but remains undeployed. A SAM application template now describes the FastAPI Lambda and API Gateway HTTP API deployment, with route-specific customer, OBO-tool, and operator JWT authorizers plus a DynamoDB-only runtime IAM policy. The application SAM package builds locally and its template passes SAM lint and standalone CloudFormation lint; the stack remains undeployed. The Cognito user pool and AgentCore resources still require account-specific provisioning. The data stack now includes an untested DynamoDB Stream → S3 Object Lock export template, a separate writer role, conditional write enforcement, an encrypted SQS DLQ, a CloudWatch DLQ alarm, a key-level reconciliation CLI, and a dry-run-first replay CLI that reconstructs failed batches from their retained sequence ranges; it is not deployed and does not backfill historical rows. The DynamoDB refund path still only updates a demo ledger; it does not call an external payment provider.

Do not deploy, create paid AWS resources, or modify credentials without explicit owner approval.


## Hosted NVIDIA NIM Red/Blue evaluation runtime

The operator-triggered Red/Blue evaluator in `src/shadow_hunter/agents.py`,
`src/shadow_hunter/nim.py`, and `src/shadow_hunter/api.py` uses two hosted
NVIDIA NIM models. It does not use Ollama or any local inference runtime.

- Red uses `nvidia/nemotron-3.5-lightning-30b-a3b` through NVIDIA's hosted
  OpenAI-compatible chat completion API. It selects only from the existing
  bounded attack/control scenario catalogue. It may modify scenario description
  and an existing natural-language `reason` value; tool names, order IDs,
  amounts, currencies, expected policy outcomes, and control-case data remain
  fixed by application code.
- Blue uses `nvidia/nemotron-3.5-bolt-e4b`. It receives the synthetic proposal,
  trusted sandbox ownership facts, and deterministic preflight findings. It
  returns schema-validated risk, threat categories, indicators and a short
  explanation. The model can add signals but cannot remove deterministic
  findings.
- Both agents use the fixed NVIDIA API base URL
  `https://integrate.api.nvidia.com/v1`, with requests sent to
  `/chat/completions`. Red's JSON response is strictly validated in code;
  Blue uses NVIDIA's JSON-schema response format.
- Model IDs and per-round seeds are saved with redacted results. NVIDIA
  documents seed repeatability as best-effort; hosted model updates and serving
  changes can still produce different outputs. The seeds aid replay and
  comparison but do not guarantee bit-for-bit determinism.
- The synchronous operator endpoint is capped at three rounds. Each round makes
  one bounded request to each hosted model. Requests have a short timeout and
  strict prompt, response-size and output-token limits. Missing credentials,
  invalid output, timeouts, provider errors and rate limits fail the run; there
  is no local-model fallback.
- The evaluation still uses a disposable SQLite database populated only with
  synthetic customers and orders. No live customer or production order content
  is sent to NVIDIA. Aggregate metrics, model metadata, per-round seeds,
  validated summaries and allowlisted policy trace metadata are written to the
  primary audit store; raw prompts, API keys, HMAC secrets and message
  signatures are not copied.
- The existing HMAC-SHA256 A2A envelopes authenticate Red-to-Blue proposals and
  Blue-to-Red responses. Nonces remain persistent across runs in SQLite or
  DynamoDB.
- Every proposal is submitted to the existing `ToolGateway`. The deterministic
  `PolicyEngine` remains the only authorization authority. Neither Red nor
  Blue can grant permissions, skip the gateway, or invoke the operator-only
  refund execution operation. Human approval remains separately enforced.
- The operator console shows the Red strategy summary, Blue model ID, risk,
  threat categories and Blue's short analysis next to the gateway decision.

The local `shadow-hunter-agntid-demo` Ollama runner is a separate MCP integration
demonstration. It is not called by this Red/Blue evaluator.

See `docs/agent-evaluation.md` for credentials, defaults, limits, metrics and
the current verification status.

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


## AgntID pass-through and agent demo runner

The MCP server supports the existing Cognito customer-token authenticator for
pass-through and the delegated Gateway OBO profile. Both retain JWT
verification and backend tenant/customer authorization. In customer mode,
the server-configured agent label is audit attribution, not cryptographic
proof of the remote agent identity.

A UUID `X-Shadow-Hunter-Demo-ID` header optionally correlates calls within
one agent run; it never contributes to authentication or authorization. The
MCP SDK Host allowlist is configurable using exact hostnames; localhost-only
remains the default.

The `shadow-hunter-agntid-demo` runner uses Ollama and the official MCP SDK
Client. It exposes read tools only to the model, then sends a separate
sandbox-only write probe through the same proxy. Explicit AgntID decisions
are distinguished from backend decisions and unattributed errors.
See `docs/agntid-integration.md`.


## Release-candidate status and current trust boundaries — 2026-11-20

The current documentation baseline was reviewed against main commit
6b26b6aaea1308706abb1ba3eac375251bd45d25. This is a source-level
release-readiness record, not proof of a working AWS deployment or a verified
release candidate.

### API ingress map

| Surface | Exposure in the application template | Required identity / boundary |
|---|---|---|
| GET /health | Public | Returns operational booleans only; do not add secrets, identifiers, or tenant data |
| GET /operator | Public static console | Authentication is required before loading operator data or invoking operator actions |
| GET /operator/config | Public OAuth configuration | May expose hosted-UI domain and public app-client ID only |
| POST /v1/agent/chat | Customer JWT authorizer | Cognito customer access token; FastAPI verifies client profile and customer scope |
| POST /v1/agent/tools/{tool_name} | Gateway JWT authorizer | Delegated OBO token with configured resource audience, scope, subject, and act.sub |
| /v1/operator/{proxy+} | Operator JWT authorizer | Operator app-client profile and configured Cognito operator group |
| /mcp/ | Not mapped by the public SAM API template | Localhost-only by default; every MCP HTTP request also passes the authentication ASGI boundary |

The public health/configuration routes must remain free of customer data and
secrets. The operator page has no server-issued anti-framing headers in the
current implementation. Its OAuth access token and approval capabilities are
kept in page memory; they are not shared across page contexts.

### Identity and authorization assumptions

- Cognito's pre-token function copies custom:tenant_id and custom:customer_id
  into access-token claims. These attributes are trusted authorization inputs
  and must be writable only by a controlled provisioning process. Customer
  app-client write permissions and self-service profile updates must not allow
  users to change either attribute.
- A separate operator app client and operator group are required for the
  deployed API. The actual user pool, client write permissions, MFA policy,
  group membership, resource server, token exchange, and V3_0 trigger
  association are not provisioned by the checked-in Cognito template.
- The model never supplies the principal. The authenticated route or MCP
  boundary creates it; the gateway retrieves order facts from trusted storage;
  the deterministic policy makes the decision.
- Refund execution remains an operator API path, not an AgentCore or MCP tool.
  The persistence transition validates the approved action, token hash, policy
  version, order ownership, currency, eligibility, and remaining balance.

### Current release blockers

The source-level review found an order-existence oracle in customer-visible
policy reason codes, no enforced maker-checker invariant, an approval-token
recovery gap after page refresh, missing operator-console framing protections,
upstream AgentCore error reflection, and no per-operator hosted-inference
budget. The Cognito trusted-attribute write boundary is a conditional High
deployment blocker. Findings and required evidence are tracked in
[the 2026-11-20 security review](security-review-2026-11-21.md).

### Evidence classification

- Implemented in source: JWT verification paths, deterministic policy/tool
  gateway, parameter-bound approval flow, SQLite and DynamoDB adapters,
  operator API, MCP adapter, hosted Red/Blue evaluator, and audit archive
  components.
- Historically reported but not rerun in this cycle: focused test results and
  the local synthetic Red/Blue contract smoke result recorded elsewhere in the
  README/cycle history.
- Not verified in this cycle: tests, builds, SAST/DAST, dependency scans,
  browser behavior, SAM transform validation, package build, AWS IAM/user-pool
  configuration, deployed storage, AgentCore OBO exchange, and end-to-end
  audit archive evidence.
- Not deployed: Cognito, DynamoDB, S3 Object Lock archive, SQS DLQ, Lambda,
  API Gateway, AgentCore Harness, Gateway, Identity provider, or Cedar policy
  attachments.

The selected AWS target is ap-southeast-2 (Sydney). Regional availability
does not imply account entitlement, quota, token-exchange feature enablement,
or model availability. Production deployment remains **NO-GO** until the
security review and deployment-readiness gates are closed.
