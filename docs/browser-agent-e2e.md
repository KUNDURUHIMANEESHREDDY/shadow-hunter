# Operator dashboard and agent workflow browser E2E

These are **real Chromium browser** tests against a **real localhost FastAPI
server** and a **real temporary SQLite store**, not screenshots or static
JavaScript checks. They use only fictional customers, synthetic orders and
local development tokens. AWS, NVIDIA NIM, Lyzr, BAND, payment providers and
deployed AgentCore are **not** called.

## What is exercised

- Operator login, live overview, policy decision pulse, audit filtering, trace
  drill-down and disconnect clearing sensitive browser content.
- HTTP tool-authentication boundary, own-tenant order reads, non-enumerating
  cross-tenant/missing-order denials, and default-deny of unauthorized tools.
- Agent `create_refund_request` -> pending human approval -> **browser**
  approve -> one-time approved execution -> SQLite demo-ledger balance change
  -> persisted execution audit trace.
- Oversized refund escalation without auto-execution.
- Optional sponsor UI request payloads and inert rendering of untrusted
  advisory text. **Only sponsor endpoints are browser-stubbed** in that test;
  these tests do not claim real Lyzr/BAND connectivity.

## Run locally

```sh
python -m pip install -e ".[dev]" fastapi uvicorn httpx pytest-playwright
python -m playwright install chromium
python -m pytest -q tests/e2e --browser chromium
```

To capture screenshots and browser traces only for failures:

```sh
python -m pytest -q tests/e2e --browser chromium \
  --screenshot only-on-failure --tracing retain-on-failure --output test-results
```

The GitHub Actions workflow runs these checks in a distinct `browser-e2e`
job on pushes and pull requests. When that job fails, it uploads its browser
traces and screenshots for debugging. Artifacts contain synthetic fixture
data only; avoid supplying real authentication or customer data.

## Explicit limitations

- **No hosted agent reasoning:** the workflow exercises the application's
  deterministic agent **tool/policy** paths, not remote LLM inference or
  deployed AgentCore Harness.
- **No real payment execution:** "refund execution" changes only a temporary
  local demo ledger.
- **No live AWS staging verification:** browser tests run on loopback and do
  not require or use cloud credentials.
- A green run is not a penetration-test certificate. Staging Cognito
  MFA, OBO delegation, external provider connectivity and real multi-tenant
  operations remain separate release gates.

The browser's operator console must never carry real credentials during this
suite. The test harness uses fixed synthetic token strings and an ephemeral
database that is removed when pytest finishes.
