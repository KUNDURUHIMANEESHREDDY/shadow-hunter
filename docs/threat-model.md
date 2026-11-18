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
