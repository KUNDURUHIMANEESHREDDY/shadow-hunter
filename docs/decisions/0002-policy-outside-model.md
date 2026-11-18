# ADR 0002: Authorization is enforced outside model reasoning

- Status: Accepted
- Date: 2026-11-18

## Context

System prompts and model refusals are not reliable access-control boundaries. A model can be manipulated, misinterpret context, or emit unexpected tool parameters.

## Decision

The model may propose tool calls, but a deterministic policy enforcement point validates identity, tenant, action, resource, canonical arguments, policy version and context before any sensitive tool executes. Business tools repeat critical authorization and domain checks.

## Consequences

- Every tool requires a registered contract and policy mapping.
- The gateway and downstream tool both enforce boundaries.
- Policy engine failures deny sensitive operations.
- Adversarial evaluation measures attempted and successful unauthorized actions; no blanket prompt-injection immunity claim is made.
