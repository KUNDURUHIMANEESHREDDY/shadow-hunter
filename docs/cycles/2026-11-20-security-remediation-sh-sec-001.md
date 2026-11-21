# Engineering cycle — SH-SEC-001 resource-existence disclosure remediation

- Date: 2026-11-20
- Repository baseline: `main` at `18ab9165a3440205d5fdd2f4024a77ca6b66beb9`
- Scope: normalize customer-visible order-resource denial reasons at the authenticated HTTP and MCP tool boundaries while preserving internal policy/audit detail.
- Outcome: local implementation and regression tests pass; deployed staging verification remains pending.
- AWS resources created or changed: **none**.
- Credentials, local auth stores, or customer data accessed: **none**.

## Change contract

For an authenticated caller, a missing order ID, an order owned by another tenant, and an order owned by another customer must produce the same externally visible tool denial. Trusted operator audit evidence must preserve the distinct internal policy reason. Red/Blue evaluation must continue receiving the original gateway result so scenario metrics and internal diagnostics do not lose fidelity.

## Implementation

- Added `public_tool_result` in `src/shadow_hunter/gateway.py`. It copies the gateway payload and normalizes resource-related DENY reason codes to `RESOURCE_NOT_AVAILABLE`.
- Applied the normalizer to the authenticated FastAPI `/v1/agent/tools/{tool_name}` response.
- Applied the same normalizer to authenticated MCP tool dispatch.
- Left `ToolGateway.invoke`, policy evaluation, audit persistence, and the internal Red/Blue gateway caller unchanged. Detailed policy reasons therefore remain in operator audit traces and internal evaluation results.
- Included missing, invalid, context-mismatched, cross-tenant, and cross-customer resource reason codes in the outward normalization set.
- Added `tests/test_tool_resource_disclosure.py` to exercise API and MCP responses and verify operator-only audit detail.
- Updated the security review, architecture, production readiness, and README status to record the remediation and its evidence.

## Regression evidence

The new test was first run before the production fix. Both cases failed because the API/MCP exposed the different internal reason codes, confirming the test reproduced the defect.

After the fix:

- Focused command: `python -m pytest tests/test_tool_resource_disclosure.py tests/test_gateway.py tests/test_mcp_server.py -q`
- Result: **23 passed**.
- The HTTP test asserts complete response-payload equality for missing, cross-tenant, and cross-customer identifiers, then verifies that only an operator can inspect the trace and that the internal audit retains all three distinct reasons.
- The MCP test asserts the same outward reason normalization and preservation of detailed trace reasons.

## Broader verification

- `python -m pytest -q`: **159 passed, 1 failed**. The sole failure is `tests/test_lambda_handler.py::test_lambda_entrypoint_exposes_handler`, blocked during import because the local environment does not have the optional `mangum` dependency installed.
- `python -m pytest -q --ignore=tests/test_lambda_handler.py`: **159 passed**.
- `python -m compileall -q src tests`: passed.
- `python scripts/validate-repo.py`: passed (8 Codex TOML files, 0 workflow YAML files, 7 Copilot agent profiles, 4 required project files).
- `git diff --check`: passed.
- `python -m ruff check src/shadow_hunter/gateway.py src/shadow_hunter/api.py src/shadow_hunter/mcp_server.py tests/test_tool_resource_disclosure.py --ignore B008,BLE001`: passed. The two excluded rule classes identify existing FastAPI body defaults and the existing MCP fail-closed broad catch; neither was introduced by this change.

## Security and release boundaries

- No AWS CLI/API calls, Cognito inspection, live endpoint tests, staging checks, model-provider calls, deployment, change sets, or billable resources were used.
- The fix is confirmed by local HTTP/MCP regression tests, not by a deployed staging environment.
- Production deployment remains **NO-GO** until the other security findings and live-service verification gates are addressed.

## Next one-at-a-time objective

Proceed to SH-SEC-002 (maker-checker separation of duties) only after this cycle is reviewed and closed. The invariant must be enforced in both SQLite and DynamoDB persistence transitions, with same-subject denial and independent-operator allow tests.
