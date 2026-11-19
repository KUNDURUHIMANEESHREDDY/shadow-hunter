# Engineering cycle — deterministic policy core

- Date: 2026-11-19
- Scope: First application implementation slice
- Status: Authored and committed; untested by project instruction

## Acceptance criteria

- Provide a small dependency-free Python package for deterministic authorization.
- Accept identity and order facts from trusted server-side context, not model-supplied arguments.
- Return only ALLOW, DENY, or ESCALATE with a stable reason code and policy version.
- Enforce authenticated identity, tenant ownership, customer ownership, exact tool argument keys, refund eligibility, currency, remaining refundable amount, idempotency-key shape, and a configurable self-service limit.
- Treat unregistered tools and unexpected evaluation errors as DENY.
- Include behavior-focused tests for legitimate actions and adversarial cases.
- Do not claim tool execution, human approval, audit persistence, AWS integration, or deployment.

## Changes

- Added a Python package under `src/shadow_hunter`.
- Added a strict policy evaluator for `get_order`, `check_refund_eligibility`, and `create_refund_request`.
- Added canonical action digests for later approval binding. The digest is not an approval capability.
- Added tests for own-order reads, cross-customer and cross-tenant denial, allowed and escalated refunds, prompt-injection text in an untrusted reason, invalid amounts/currency, unknown tools, missing identity, and extra arguments.
- Added project packaging metadata with pytest as an optional development dependency.

## Verification

- Tests, package build, lint, formatting and security scans were not run, consistent with `docs/engineering-cycle.md`.
- All implementation and test code must therefore be treated as unverified until the owner authorizes checks.

## Remaining work

1. Add an application/API adapter that resolves authenticated principals and order snapshots from trusted sources.
2. Add a real tool gateway so no model path can invoke business tools directly.
3. Implement parameter-bound, expiring, single-use human approval and idempotent refund execution.
4. Persist correlated policy decisions and side effects in an audit store.
5. Validate the Bedrock Managed Agents and AgentCore integration path before selecting deployable AWS infrastructure.
