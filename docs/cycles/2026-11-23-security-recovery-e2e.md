# Shadow Hunter — security and recovery end-to-end test gate

**Scope:** synthetic/local regression only, 23 November 2026. No production
customer data, external model calls, payment/refund processor calls, or AWS
deployments. The DynamoDB backend uses Moto; the SQLite backend is a real
temporary file.

## Test matrix

| Requirement | Automated validation |
| --- | --- |
| Prompt injection | Signed Red→Blue messages containing attempted developer/policy overrides must be classified as injection, but the tool gateway must still DENY foreign resources; replayed signatures/nonce denied |
| Cross-tenant isolation | Alpha and Beta customer identities cannot read each other's orders; same-tenant different-customer ownership is also enforced |
| Privilege boundaries | A customer cannot call operator approval or audit APIs, cannot inject principal/policy override arguments, and cannot call the operator-only refund execution tool |
| Agent timeouts | Fake AgentCore connection errors and interrupted streams must fail; no automatic re-execution of ambiguous tool-bearing requests |
| Partial stream / malicious provider diagnostics | Missing end_turn, wrong stop reason and untrusted error messages must never return apparent success or leak upstream text |
| Retries after interruption | Force an approval-service error after durable refund creation, restart the service and replay exactly the same action using its idempotency key; no duplicate refunds or approval audits |
| Approval recovery | Lose the one-time approval token after an operator approval; restart the app, rotate the token via audited recovery, reject old token, execute once |
| Interrupted execution response | Replay the same completed execution from original operator returns prior result; a different operator is denied; ledger amount changes only once |
| FastAPI E2E | Real application HTTP routes verify customer/operator separation, no-store behavior, token rotation, execution and idempotent replay across restart |
| CI gate | Dedicated focused pytest step precedes the full Python regression suite |

## Implementation

- **tests/test_security_recovery_e2e.py**: exercises actual A2A authentication, BlueAgent, deterministic tool policy, approval store and local FastAPI routes against SQLite and Moto DynamoDB.
- **tests/test_agentcore_recovery.py**: injects fake Harness timeouts, partial streams and provider errors into the existing hardened AgentCore stream parser and the actual FastAPI chat route.
- **.github/workflows/python-tests.yml**: adds the focused security and recovery job step.

The repository's independently merged **agentcore_evidence.py** already
requires a completed final assistant response and sanitizes untrusted provider
messages. These tests assert that behavior rather than replacing that
separate implementation.

## Reproduce

From the repository root with the normal Python 3.11 dev and server test
dependencies:

    python -m pytest -q tests/test_security_recovery_e2e.py tests/test_agentcore_recovery.py
    python -m pytest -q
    python -m compileall -q src/shadow_hunter tests
    python scripts/validate-repo.py

## Verified GitHub Actions evidence

Pull request [#12](https://github.com/KUNDURUHIMANEESHREDDY/shadow-hunter/pull/12)
ran against this implementation and was merged into main
(squash commit 5aef9e6):

- **Focused security/recovery fault-injection gate:** 26 passed (2.92 s).
- **Full Python regression:** 320 passed, 1 skipped (9.57 s).
- **Real Chromium browser E2E job:** passed.
- **Tracked-repository validation and source/test compilation:** passed.

These are CI results for synthetic local scenarios, not evidence of live
Cognito OBO/AgentCore authenticated staging execution.

## Recovery and release boundaries

An AgentCore timeout is ambiguous: the remote workflow might have committed
state before losing its connection. The client intentionally must **not
automatically retry** a potentially consequential prompt. A caller retrying
a local refund request must preserve the authenticated principal and
idempotency key. Approval recovery is a separate authenticated operator
operation that invalidates the old token and emits an audit event.

The tests do **not** replace real Cognito OAuth/OBO and two-tenant staging
verification, a live AgentCore Gateway/Harness tool-use trace, a hosted
model prompt-injection evaluation, an independent bounded penetration test,
or external payment-provider consistency testing.

**Production remains NO-GO until those separate live acceptance gates pass.**
