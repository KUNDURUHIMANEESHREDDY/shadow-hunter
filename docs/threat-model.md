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
