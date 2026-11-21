# Shadow Hunter threat model

## Assets

- Customer order records and personal data
- Refund requests and payment-side effects
- Organization/tenant identities and support roles
- Policy bundles, approval tokens, signing keys and secrets
- Audit records and evaluation evidence
- Agent and gateway credentials
- Model and tool usage budgets

## Threat actors

- Malicious customer
- Compromised customer account
- Malicious or careless support operator
- Prompt-injection content embedded in order notes or documents
- Compromised/poisoned tool output or retrieved context
- Compromised agent skill, package, dependency, or action
- Misconfigured operator or overly privileged service identity

## Main abuse cases

1. Cross-tenant order lookup by changing an ID or injecting another customer's reference.
2. Refund amount manipulation, currency substitution, partial/full confusion, or eligibility bypass.
3. Prompt injection in user text, order notes, tool responses, or documents.
4. Approval replay, expiry bypass, principal substitution, and action-parameter substitution.
5. Duplicate refund caused by retry, race condition, or parallel agent invocation.
6. Policy downgrade or version race between approval and execution.
7. Direct tool endpoint invocation bypassing the gateway.
8. Audit tampering or suppression after an unauthorized operation.
9. Secret disclosure through prompts, traces, exceptions, or model outputs.
10. Cost exhaustion through agent loops, retries, large prompts, or excessive tool calls.
11. Malicious agent skill that attempts to exfiltrate files or run code at install/load time.

## Required mitigations

- Deterministic default-deny authorization outside the model.
- Strong tenant/resource checks in each data-access and mutation handler.
- Tool gateway with a single allowlisted route to business tools.
- Strict request schemas, canonical serialization, bounded numeric/currency fields.
- Approval tokens bound to exact action, arguments, principal, resource, policy version, expiry, and nonce.
- Maker-checker separation: the authenticated requester subject cannot approve its own refund; enforce the requester/approver inequality in both persistence approval and execution transitions.
- Atomic idempotency and execution-state transitions.
- Policy re-evaluation immediately before the side effect.
- Separate least-privilege roles for the agent, gateway, approval service, and business tools.
- Secrets in managed secret storage, never in prompts or logs.
- Durable, correlated audit events with separately protected retention/export.
- Per-tenant, per-agent and global rate/token/tool/runtime/cost limits.
- Manual skill review, immutable source pinning, license review, static scan, and script review.

## Test principle

For each threat, create at least one positive test and one adversarial test. The security test must attempt the action at the tool boundary, not only observe whether the model verbally refuses. Any successful unauthorized side effect is a release blocker.


## Agent-to-agent proposal threats

The first Red/Blue slice is an in-process evaluation harness. Red Agent messages remain
untrusted proposals and cannot supply or override the authenticated customer principal,
the Blue Agent identity, the policy bundle, or the gateway tool allowlist. The Blue
Agent validates the message envelope and submits every proposed tool action to the
same deterministic gateway used by the support workload. Only a redacted decision
summary is returned to Red; tool output and approval capabilities are not forwarded.

The current in-process envelope is not proof of remote sender authentication. Do not
expose it over a network until the transport binds sender identity to an authenticated
workload identity and adds replay protection, request limits, and per-agent rate limits.


## MCP and proxy-boundary threats

The Streamable HTTP MCP endpoint is a separate ingress path into the same tool
gateway. Every HTTP request must carry exactly one accepted Bearer credential.
Missing, duplicated, malformed, expired, wrong-audience, wrong-scope, wrong-actor,
JWKS-failure, and verifier-error cases must fail before MCP dispatch. Each tool
handler must also deny when no authenticated request context exists, such as
in-memory or non-HTTP invocation.

Caller-supplied MCP clientInfo, prompt text, tool arguments, and transport
metadata are not authenticated agent identity. The agent attribution is resolved
from the verified Cognito act.sub configuration, or from a local-only server
setting. The upstream bearer token must not be copied into tool arguments,
application logs, database rows, or downstream credentials.

The MCP tool surface must remain an explicit allowlist containing only order
read, eligibility read, and refund-request creation. Refund execution and all
operator routes remain outside the MCP server. AgntID's upstream token issuer,
audience, claims, exchange behavior, and expiry contract must be independently
confirmed before connecting a remote proxy; unknown token formats fail closed.
The SDK host allowlist and TLS boundary must be configured before any public
hostname is enabled.


## Autonomous Red/Blue runtime threats

- Red strategy output and all proposal fields remain attacker-controlled data.
- Blue's heuristic risk score and recommendation are advisory only. The deterministic
  PolicyEngine and existing tool handlers remain the sole authorization authority.
- Per-agent HMAC secrets must be unique, at least 32 bytes, provisioned outside source
  control, and protected as application secrets. Compromise of a sender's key allows
  message forgery as that sender until rotation.
- Operator-managed provider and A2A secrets are written only to two fixed Secrets
  Manager ARNs. The browser cannot choose a secret ARN, read secret values, or receive
  generated HMAC material. The Lambda role is scoped to GetSecretValue and
  PutSecretValue on those exact ARNs; it has no Secrets Manager create/delete/list
  permissions. The operator mutations require a verified operator identity and create
  redacted audit events. The OAuth console login uses authorization code + PKCE; the
  access token is kept in page memory rather than browser storage.
- Message signatures cover the protocol version, message identifiers, trace, sender,
  recipient, message type, payload, key ID, issue time, and nonce.
- The receiver enforces the configured sender-to-key mapping, a bounded timestamp
  window, constant-time signature comparison, and a persistent single-use nonce.
- A2A nonces are stored in the primary SQLite or DynamoDB store so replay detection
  is shared across workers. They are protocol metadata, not authorization grants.
- The current operator evaluation endpoint uses a disposable SQLite database seeded
  only with synthetic test principals and orders. Only non-sensitive case outcomes,
  aggregate metrics, and allowlisted A2A/policy trace metadata are copied to the
  primary audit table. Raw message payloads, signatures, tokens, and HMAC secrets are
  excluded. It never runs Red/Blue proposals against live customer orders.
- HMAC authentication does not encrypt message contents and does not establish a
  secure remote network channel. Do not expose remote agents until TLS/mTLS or
  platform workload identity, transport-level limits, and service authorization
  are deployed and independently verified.
- Attack-success metrics describe whether a malicious proposal received ALLOW at the
  policy boundary. They do not mean a refund was executed: refund execution remains
  behind a separate operator approval capability.
- Risk scores are deterministic heuristic indicators, not calibrated probabilities
  or proof of prompt-injection detection accuracy.


## AgntID pass-through and run correlation

Customer pass-through verifies the original Cognito JWT with the existing
signature, issuer, expiry, app-client, scope, subject, tenant and customer
checks. It proves user identity, not agent identity; the server-side agent
label is audit attribution only. OBO mode still requires target audience,
scope, subject, and act.sub.

The optional UUID demo header is correlation metadata only. Duplicate or
malformed values are ignored and cannot affect the principal, tenant,
customer, tool allowlist, or policy. AgntID must forward it for shared trace
IDs; otherwise tool results provide their own backend trace IDs.

The model sees read tools only. A separate write probe targets a disposable
order-demo record and uses a unique idempotency key; it never calls the
operator refund execution route. If AgntID fails to block the probe, it can
create only a pending sandbox approval, not execute a refund.


## Hosted model-provider boundary for Red/Blue evaluation

- Only the operator-triggered Red/Blue evaluation calls NVIDIA's hosted NIM
  endpoint. The separate AgntID/Ollama demo is not imported or invoked by this
  execution path.
- Every evaluation prompt is built from synthetic records in a disposable
  SQLite sandbox. Do not reuse this reasoning adapter for live customer
  conversations or production order context without a separate privacy,
  data-residency, retention and vendor-terms review.
- NVIDIA API keys and the two A2A signing keys are server secrets. Local
  development reads environment variables. AWS deployment reads only the
  configured Secrets Manager ARNs and grants `secretsmanager:GetSecretValue`
  for those exact ARNs. Never place the key in prompts, result records,
  exceptions, frontend code, or source control.
- Red output is attacker-controlled. Its schema allows only a known scenario
  ID, a bounded hypothesis string and bounded natural-language injection text.
  The selected scenario's tool, resource, monetary parameters, expected result
  and control status remain application-owned. Invalid selections or output
  abort the evaluation.
- Blue output is also untrusted. The application validates the JSON schema,
  category and recommendation enums, indicator identifiers, score range and
  summary length. Model categories are unioned with deterministic findings,
  and the risk score cannot drop below the deterministic score.
- Blue's recommendation is advisory. A model suggestion to allow or deny never
  controls the gateway result. The authenticated principal, tenant ownership,
  tool allowlist, policy and separate approval checks remain outside the model.
- NIM requests use fixed HTTPS host/path, bounded input and output sizes,
  non-streaming completion, a request timeout, bounded rounds and provider
  seeds. No automatic retries or local fallback occur. Timeout, 429, non-2xx,
  malformed output and invalid schema fail the evaluation. Operators should
  monitor provider quotas and invocation cost before increasing the run limit.
- NVIDIA reports seed reproducibility as best-effort. Model-serving changes can
  affect repeatability; stored model identifiers, seeds, scenario IDs and
  summaries are evidence for replay, not a determinism guarantee.
