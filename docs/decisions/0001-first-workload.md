# ADR 0001: First workload is customer support and refunds

- Status: Accepted for initial implementation
- Date: 2026-11-18

## Context

The product could start with a broad collection of coding, finance, research and DevOps agents. That would spread authorization models and business integrations across too many unrelated domains before the enforcement core is proven.

## Decision

Start with one realistic customer-support/refund workflow, five narrow tools, explicit customer/tenant ownership, refund eligibility and limits, and parameter-bound approval for sensitive execution. Keep the policy and tool interfaces reusable for future workloads.

## Consequences

- Tests can define exact positive and negative outcomes.
- A single demo can show ordinary work, cross-tenant denial, refund escalation, approval replay prevention, and prompt-injection resistance at the tool boundary.
- Multi-agent governance and additional workload packs are future extensions, not first-release blockers.
