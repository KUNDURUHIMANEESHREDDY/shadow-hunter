# Engineering cycle — local Red/Blue A2A harness

- Date: 2026-11-20
- Scope: First Red Agent to Blue Agent proposal/defense exchange
- Status: Authored and committed; untested under the repository operating contract

## Changes

- Added a bounded, versioned JSON message envelope for attack proposals and defense results.
- Added a Red Agent that emits repeatable adversarial scenarios and evaluates the correlated response.
- Added a Blue Agent that validates sender, recipient, protocol version, message type, and payload shape before submitting the proposed tool action to the existing ToolGateway.
- Added server-assigned agent attribution to gateway invocations and policy-decision audit details; message payloads cannot choose the Blue Agent identity.
- Added four default refund-workload attacks: cross-customer order read, direct refund execution, prompt-injected over-refund, and injected policy-override arguments.
- Added an in-process simulation that records A2A send/receive/evaluation evidence alongside the gateway policy decision under a shared trace ID.
- Blue Agent responses contain only scenario ID, decision, reason code, and action digest; order data and other tool output are not returned to Red.
- Added focused behavior tests for attack blocking, audit correlation, forged-sender rejection, output minimization, and expected-outcome evaluation.
- Documented the non-production boundary: this is not a network A2A transport, authenticated remote agent runtime, or autonomous LLM pair.

## Security boundaries

- Red Agent messages are untrusted proposals, not policy instructions.
- All proposed tools still pass through the deterministic gateway and its allowlist.
- execute_refund remains outside the agent tool set and is not made callable by either agent.
- The Blue Agent identity is assigned by server-side code, not trusted from the message body.
- The current in-process transport does not establish cryptographic identity between remote processes; do not expose it remotely without authenticated transport and replay/rate-limit controls.
- No AWS resources were created or deployed.

## Verification

No tests, build, lint, formatting, or security scans were executed, consistent with docs/engineering-cycle.md. The new tests are authored but remain unexecuted. Repository reads and commit-head checks are not runtime verification.

## Next task

Add an authenticated operator-facing evaluation route and a persistent evaluation summary only after defining how the operator selects a trusted customer test principal and how test data is isolated from live refund requests. Then implement a separately authenticated remote A2A transport.
