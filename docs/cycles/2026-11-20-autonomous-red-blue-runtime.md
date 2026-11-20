# Engineering cycle — autonomous Red/Blue runtime

- Date: 2026-11-20
- Scope: strategy engine, defensive reasoner, authenticated A2A envelopes, bounded evaluation loop, metrics, and operator console
- Status: Authored and committed; untested under the repository operating contract

## Changes

- Replaced the initial fixed Red/Blue harness with a provider-independent adversarial strategy planner and a bounded adaptive iteration loop.
- Expanded the scenario pool to eight cases: cross-customer read, direct refund execution, prompt-injected over-refund, policy argument tampering, currency substitution, boolean amount type confusion, high-value approval escalation, and a legitimate control.
- Added a Blue defensive reasoner that emits risk score, threat categories, indicators, and recommended handling. This is advisory only; the deterministic gateway still authorizes every tool.
- Added separate per-agent HMAC-SHA256 signing keys, sender-key binding, signature/integrity checks, 90-second timestamp validation, and persistent single-use nonces.
- Added SQLite and DynamoDB replay-guard storage and redacted latest-evaluation queries.
- Added operator-authenticated run/latest endpoints. Every evaluation uses synthetic identities and a disposable SQLite database; the primary store receives nonce metadata, redacted results/metrics, and allowlisted A2A/policy trace metadata. Raw messages, signatures, approval tokens and HMAC secrets are never copied.
- Added operator-console metrics and a per-round outcome table.
- Added explicit metric definitions and secret configuration instructions in docs/agent-evaluation.md.

## Security boundaries

- This runtime does not call an LLM or external model API.
- The strategy planner and reasoner are deterministic components, not autonomous model instances.
- The Blue reasoner cannot authorize actions or bypass ToolGateway/PolicyEngine.
- HMAC keys are independent per agent and are never copied into audit events.
- Nonces are persisted in the main store to prevent replay across workers and runs.
- Evaluation actions use synthetic data. No real refund request or payment operation is created.
- HMAC does not encrypt messages or create a remote network trust boundary; the current exchange remains in-process.
- Attack-success rate measures policy-level ALLOW on attack scenarios, not completed financial side effects.
- No AWS resources were created or deployed.

## Verification

No tests, build, lint, formatting, or security scans were executed, consistent with docs/engineering-cycle.md. Regression tests were authored but remain unexecuted.

## Next task

Add a remote A2A transport only after selecting and validating a workload-identity mechanism and defining per-agent network authorization. Then consider optional local-LLM strategy/reasoner adapters behind the same typed interfaces, while keeping policy enforcement independent of model output.
