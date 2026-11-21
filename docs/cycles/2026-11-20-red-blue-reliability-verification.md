# Engineering cycle - Red/Blue reliability verification

- Date: 2026-11-20
- Scope: verify the NIM Red/Blue adapter path and repair the first end-to-end simulation defect
- Status: local synthetic contract path verified; hosted NVIDIA inference remains blocked by missing configuration

## Defect and repair

The first focused test run reproduced an `UnboundLocalError` in
`RedBlueSimulation.run()`. The Blue `A2A_MESSAGE_SENT` audit record referenced
`observation.strategy_summary` before the observation was constructed. Git
blame identifies that premature reference as introduced with the hosted
Red/Blue integration commit `0c2a33e`.

The audit record now reads the already-available
`scenario.model_strategy_summary`. The later `A2A_EVALUATION` record continues
to persist the evaluated observation summary. This keeps the audit event
ordering intact and removes the uninitialized local-variable reference.

## Verification evidence

- Before repair:
  `python -m pytest tests/test_nim.py tests/test_agents.py tests/test_gateway.py tests/test_agent_evaluation_store.py -q`
  - 32 passed, 5 failed; all five failures reached the same uninitialized
    `observation` reference.
- After repair, same focused command: **37 passed**.
- Full suite, `python -m pytest -q`: **112 passed, 2 failed**:
  - `test_agentcore_harness_client_rejects_short_session_id`: expected error
    wording does not match the current AgentCore exception text.
  - `test_lambda_entrypoint_exposes_handler`: `mangum` is not installed in
    this local environment.
  These are outside the Red/Blue fix and remain unresolved.
- `python -m compileall -q src/shadow_hunter tests`: passed.
- `git diff --check`: passed.

## Three-round synthetic contract run

The actual `NIMRedStrategyPlanner` and `NIMBlueDefenseReasoner` classes were
run with deterministic stub clients, against a disposable SQLite store,
through A2A HMAC signing, Blue processing, `ToolGateway`, and `PolicyEngine`.
The run deliberately included two attacks and one legitimate control:

| Case | Gateway decision | Expected result |
|---|---|---|
| Cross-customer order read | DENY | Attack prevented |
| Direct refund execution | DENY | Attack prevented |
| Legitimate own-order read | ALLOW | Control succeeded |

Recorded metrics:

- Rounds: 3
- Attack attempts / successes: 2 / 0
- Attacks prevented: 2
- Attack success rate: 0.0
- Defensive effectiveness: 1.0
- Control cases / false denials: 1 / 0
- False-denial rate: 0.0
- Expected-outcome passes / rounds: 3 / 3
- Policy decision accuracy: 1.0
- Executed refunds: 0
- Per-case trace events: 3 policy decisions and 3 A2A evaluation records

These values verify the local harness and policy-boundary accounting only.
Stubbed responses do not measure hosted model quality, provider latency,
prompt robustness, or the eight-scenario adversarial benchmark.

## Hosted evaluation blocker

Presence-only checks of the connected process environment found no
`NVIDIA_API_KEY` or NVIDIA secret ARN, no A2A key configuration, and no
operator token. No local API server was listening on port 8000. No `.env`,
credential file, or local authentication store was opened; no secret values
were read or requested. No hosted NVIDIA call or AWS operation was made.

## Next step

After the owner configures the NVIDIA API key, unique Red/Blue A2A keys, and
local operator authentication in the runtime environment, run one hosted
round first. Inspect provider status, response shape, request latency, trace
events and policy decision. Only then run all three hosted rounds and compare
their metrics with the local contract baseline.
