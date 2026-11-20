# Decision 0006 — authenticated deterministic Red/Blue evaluation

- Date: 2026-11-20
- Status: Accepted

## Context

The project needs repeatable autonomous attack/defense iterations and inspectable
measurements, without making external model calls or weakening its deterministic
authorization boundary. Evaluation must not mutate real customer orders or refunds.

## Decision

Use a provider-independent Red strategy planner and Blue heuristic defense reasoner.
Sign each in-process A2A message with a separate per-agent HMAC-SHA256 key. Persist
single-use message nonces in the application store. Run operator-triggered evaluation
against synthetic data in a temporary SQLite database and persist only redacted
case results and aggregate metrics to the primary audit store.

The existing ToolGateway and PolicyEngine remain the sole authorization authority.
An ALLOW for a malicious proposal is counted as policy-level attack acceptance; it
does not imply payment execution.

## Consequences

- Reproducible 1–20 round loops can run without model-provider credentials.
- HMAC secrets must be provisioned and protected outside source control.
- The protocol is authenticated but remains in-process; it is not a remote network
  protocol and does not replace TLS/mTLS or cloud workload identity.
- Risk scores are heuristic indicators, not calibrated probabilities.
- The evaluation sandbox avoids executing adversarial requests against live data.
- LLM-driven agents, remote A2A transport, baseline comparisons, and model-assisted
  adversarial mutation remain future work.
