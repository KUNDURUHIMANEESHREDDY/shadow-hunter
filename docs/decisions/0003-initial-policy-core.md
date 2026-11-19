# ADR 0003: Start with a deterministic Python policy core

- Status: Accepted for the first implementation slice
- Date: 2026-11-19

## Context

The first product milestone needs a real tool-boundary authorization contract before agent orchestration, UI, or AWS infrastructure is added. The model must not be an authorization authority.

## Decision

Implement a dependency-free Python policy decision point with three registered support/refund tools: `get_order`, `check_refund_eligibility`, and `create_refund_request`. It accepts authenticated principal data and an order authorization snapshot only from trusted server-side components. Tool arguments use exact schemas. The decision contract is `ALLOW`, `DENY`, or `ESCALATE`.

An eligible refund within the configured self-service limit may proceed to a business tool. A refund above the limit escalates. Missing identity, resource mismatch, invalid arguments, unknown tools, unsupported context, and evaluation errors deny.

Refund execution is deliberately not registered until parameter-bound approval verification and idempotent execution are implemented. This prevents the initial policy core from implying that approval exists when it does not.

## Consequences

- The policy core can be tested locally without AWS credentials or a model provider.
- The action digest provides a stable correlation primitive for later approval binding; it is not an approval token.
- The core does not execute tools, persist audit records, or call AWS.
- A future gateway adapter must construct trusted identity/resource context and must route every registered tool through this engine.
