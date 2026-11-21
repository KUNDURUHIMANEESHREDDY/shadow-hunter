# Engineering cycle — release-candidate security remediation

- Date: 2026-11-20
- Initial source baseline: main at 6b26b6aaea1308706abb1ba3eac375251bd45d25
- Merged remediation baseline: main at b8968a8befe6cd031852ab43944a38544c5d5dc0
- Scope: close locally remediable findings from the release-candidate security review; reconcile remote main changes; run owner-authorized regression, browser, SAST/dependency, SAM and CloudFormation lint checks.
- Outcome: application remediations implemented; merged-main regression and infrastructure validation performed; production remains **NO-GO**.
- AWS resources/account data/credentials accessed: **none**.
- Live customer data and hosted model providers accessed: **none**.

## Changes and preserved remote work

- Preserved the four remote main commits that introduced the Cognito identity stack and follow-up remediation for order-response normalization and maker-checker approval/execution.
- SH-SEC-001 — order enumeration: preserved the common public HTTP/MCP response normalizer. Detailed internal policy reasons remain in audit evidence while callers receive a non-enumerating resource denial.
- SH-SEC-002 — maker-checker: preserved SQLite/DynamoDB denial audit events and requester/approver checks at approval and execution transitions.
- SH-SEC-003 — lost approval token: added operator-authenticated capability rotation. The old token hash is invalidated, raw tokens are never persisted or audited, and the event is redacted. Both stores compare the previous token hash atomically to prevent concurrent recoveries from both succeeding. Operator console offers recovery after refresh.
- SH-SEC-004 — browser framing: FastAPI adds CSP frame-ancestors, X-Frame-Options, nosniff and Referrer-Policy headers.
- SH-SEC-005 — upstream error disclosure: customer chat returns a generic AgentCore 502 with a trace identifier and does not reflect provider error text.
- SH-SEC-006 — inference budget: added atomic per-operator daily evaluation reservations and cooldown in SQLite and DynamoDB, plus a runtime kill switch. Defaults are five runs per operator per UTC day and 60 seconds between runs. A global spend cap, cross-operator aggregate quota and provider-spend alert are not implemented.
- SH-SEC-007 — identity trust boundary: preserved the new identity stack on remote main. It defines immutable tenant/customer attributes, customer-client write restrictions, separate operator/M2M clients, operator MFA/group and a V3_0 trigger. The deployed pool, provisioning process and issued-token claims still need staging verification.

## Verification evidence on merged main

- Python environment: isolated project .venv using Python 3.11 and the project's dev/server/aws extras.
- Full Python suite: **177 passed**.
- Focused approval/API/DynamoDB/gateway security group: **37 passed**.
- Python compile, repository metadata validation and final git diff checks are being re-run after the last documentation/rebase changes.
- Microsoft Edge headless browser check: operator page loaded with required headers; iframe framing attempt was blocked by frame-ancestors none. Full token-recovery reload/recovery/execution E2E remains pending.
- cfn-lint: **all four production templates passed** on the merged tree.
- SAM validation: sam validate --lint passed the existing-pool Cognito trigger, data and API templates; the new identity stack passed SAM basic validation because the bundled SAM schema lags the Cognito delegation property.
- Prior committed WSL2 verification cycle records sam build --no-use-container success for all four templates. A separate Windows-host API build attempt selected a Windows-only pywin32 wheel for a Linux Lambda target and failed due to the host platform; the earlier Linux build evidence is retained.
- Semgrep: the prior targeted source/security/secrets scan found 0 findings across 22 files / 122 rules; that scan predates the remote identity additions and is recorded as a prior snapshot.
- pip-audit: the prior scan of src/requirements.txt reported no known vulnerabilities; dependency manifests were not changed in this remediation.
- Bandit: prior scan reported 0 High / 0 Medium / 10 Low. Ruff's installed default ruleset reported repository-wide findings; no blanket autofix was applied.
- DAST, fuzzing, live endpoint tests, live AWS verification, deployment, package uploads, and hosted inference calls were not performed.

## Remaining release gates

1. Verify the deployed Cognito pool schema, customer app-client WriteAttributes, administrative provisioning path, V3_0 trigger association, operator MFA/group and real issued customer/operator/OBO claims in staging.
2. Run SH-SEC-001/002 response-equivalence and maker-checker checks against deployed API/MCP and DynamoDB.
3. Complete operator UI reload/recovery/execution/replay browser E2E and verify deployed API Gateway headers.
4. Add a global hosted-provider quota, spend cap and alerts; per-operator limits alone do not cap aggregate provider cost.
5. Run the staging cross-tenant denial, correlated audit trace, S3 archive and independent read-only byte-verification demonstration.
6. Obtain separate AWS approval before account/API access, package uploads, deployment, live model calls or billable resource changes.

## Files changed by this remediation cycle

- .gitignore
- README.md
- docs/engineering-cycle.md
- docs/production-deployment-readiness.md
- docs/security-review-2026-11-21.md
- docs/cycles/2026-11-20-release-candidate-remediation.md
- infra/app/template.yaml
- infra/data/dynamodb.yaml (merged with remote main)
- src/shadow_hunter/api.py
- src/shadow_hunter/approvals.py
- src/shadow_hunter/dynamodb_store.py
- src/shadow_hunter/gateway.py
- src/shadow_hunter/mcp_server.py
- src/shadow_hunter/store.py
- src/shadow_hunter/web/operator.html
- tests/test_agent_evaluation_store.py
- tests/test_approvals.py
- tests/test_dynamodb_store.py
- tests/test_gateway.py
- tests/test_operator_settings_api.py
