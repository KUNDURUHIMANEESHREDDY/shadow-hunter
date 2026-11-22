# Shadow Hunter security review

- Review date: 2026-11-20
- Repository: [KUNDURUHIMANEESHREDDY/shadow-hunter](https://github.com/KUNDURUHIMANEESHREDDY/shadow-hunter)
- Original source-review baseline: main at 6b26b6aaea1308706abb1ba3eac375251bd45d25
- Merged remediation baseline: main at b8968a8befe6cd031852ab43944a38544c5d5dc0, before this cycle's final commit
- Assessment: **PARTIAL — source review plus local regression/browser/SAST/dependency/SAM validation; not a penetration test, certification, or release approval**
- Deployment status: **NOT DEPLOYED**; no AWS account resources or live credentials were accessed or changed.

## Executive summary

The current implementation has several sound control boundaries: customer and delegated-agent JWT profiles are distinct in Cognito mode; tool calls pass through a fixed allowlist and deterministic policy engine; the model cannot execute refunds; approval capabilities are hashed at rest; SQLite and DynamoDB execution paths re-check stored approval state and order balance; and AWS roles are separated for application data access, audit export, and read-only audit verification.

The original source review identified seven findings. Subsequent main-branch work now implements maker-checker approval/execution checks and a Cognito identity stack with immutable tenant/customer attributes, restricted customer-client WriteAttributes, separate customer/operator/M2M clients, MFA/group controls, and a V3_0 pre-token trigger. This remediation cycle additionally implements audited approval-token rotation, API anti-framing headers, generic customer-facing AgentCore errors, and durable per-operator evaluation quotas/cooldowns with a kill switch. Order-existence response normalization is applied at the authenticated HTTP and MCP boundaries while detailed policy reasons remain in restricted audit evidence.

Five application findings are remediated in local source, the inference-budget finding is partially mitigated, and the Cognito identity-as-code finding has a source-level control. **Production remains NO-GO** until the real Cognito pool/client configuration and issued tokens are verified in staging, deployed API Gateway headers and the browser recovery path are tested end to end, and global provider spend controls are completed or formally accepted. This report is not a penetration test, certification, or release approval.

## Scope and method

Reviewed the current default-branch source and infrastructure relevant to:

- FastAPI route registration, customer chat, delegated tool calls, operator routes, approvals, refund execution, settings, and hosted evaluation.
- Local opaque-token authentication and Cognito RS256/JWKS authentication.
- Policy evaluation, tool allowlisting, tenant/customer ownership checks, action digests, and error outcomes.
- SQLite and DynamoDB persistence paths for orders, refund requests, idempotency claims, approvals, execution, audit events, and A2A nonces.
- MCP authentication middleware and tool registration.
- AgentCore Harness invocation and bearer-token handling.
- NVIDIA NIM provider boundaries, operator-managed secrets, and bounded Red/Blue evaluation.
- Cognito pre-token claim customization.
- DynamoDB/S3 audit export, replay, reconciliation, and content-verification paths.
- SAM templates and the operator console's token handling and dynamic HTML rendering.

The review was read-only. It used source inspection and targeted GitHub default-branch searches for common credential markers. No concrete credential value was surfaced by those searches; generic matches were in scanner rules, documentation, tests, or environment-variable references. This was **not** a full Git-history secret scan, dependency vulnerability scan, static-analysis run, or credential-validity check.

The original source-review cycle was read-only and did not run executable checks. The owner later authorized one remediation/verification cycle. Follow-up source changes and current merged-branch verification evidence are recorded below. No live AWS inspection, DAST, fuzzing, hosted model call, deployment, or penetration test was performed.

## Findings

### SH-SEC-001 — Order lookup exposes resource-existence distinctions

- **Severity:** MEDIUM
- **Confidence:** HIGH
- **Status:** Remediated in local source and regression-tested; staging verification remains pending.
- **Affected paths:** [gateway.py](../src/shadow_hunter/gateway.py), [api.py](../src/shadow_hunter/api.py), [mcp_server.py](../src/shadow_hunter/mcp_server.py), [policy.py](../src/shadow_hunter/policy.py)

**Evidence**

The gateway loads an order using the caller-supplied order_id before policy evaluation. The policy retains distinct internal reasons such as ORDER_CONTEXT_MISSING, RESOURCE_TENANT_MISMATCH, and RESOURCE_OWNER_MISMATCH. Before remediation, both HTTP and MCP tool boundaries exposed those distinctions. The follow-up fix normalizes these resource-denial reason codes to RESOURCE_NOT_AVAILABLE in an outward response copy; the gateway result and audit event retain the precise internal reason.

**Impact and precondition**

Before remediation, an authenticated customer or delegated agent able to submit guessed order IDs could distinguish missing IDs from existing foreign resources. The response did not return foreign order contents, but it exposed an order-existence and ownership-classification oracle.

**Remediation applied**

The authenticated FastAPI tool route and MCP dispatcher now pass gateway results through a customer-facing response normalizer. Missing, invalid, context-mismatched, cross-tenant, and cross-customer resource denials use the same RESOURCE_NOT_AVAILABLE reason code. The original detailed reason remains in the policy audit event and the internal gateway return, preserving operator investigation and Red/Blue evaluation evidence.

Regression tests exercise nonexistent, cross-tenant, and cross-customer order IDs through both HTTP and MCP. They assert identical public payloads and verify that detailed reason codes remain available through the operator-authenticated audit route.

### SH-SEC-002 — Approval does not enforce separation of duties

- **Severity:** MEDIUM
- **Confidence:** HIGH for the original missing invariant; identity overlap remains a deployment configuration concern
- **Status:** Remediated in local SQLite/DynamoDB source and regression-tested; live DynamoDB staging verification remains pending.
- **Affected paths:** [approvals.py](../src/shadow_hunter/approvals.py#L30), [store.py](../src/shadow_hunter/store.py), [dynamodb_store.py](../src/shadow_hunter/dynamodb_store.py), [api.py](../src/shadow_hunter/api.py#L384)

**Original evidence**

The approval service checked that an approver ID was non-empty. The SQLite and DynamoDB approval transitions stored the approver identity but did not compare it with the refund request's originating principal_id. Cognito requires an operator client ID and operator group, but one Cognito subject can potentially be provisioned as both a customer and an operator.

**Remediation applied**

Both persistence adapters now prohibit an approver whose authenticated subject matches the stored requester principal. SQLite performs the comparison inside its `BEGIN IMMEDIATE` approval transaction and adds `principal_id <> approver_id` to the state update. DynamoDB checks the subject before issuing a capability and repeats the inequality in the conditional `TransactWriteItems` approval update. Both paths record `APPROVAL_SELF_APPROVAL_BLOCKED` with DENY / `MAKER_CHECKER_VIOLATION` while leaving the approval pending.

Refund execution also re-checks the stored requester and approver in both adapters. SQLite validates before the ledger mutation and constrains the approval-consume update; DynamoDB validates the loaded record and includes `approver_id <> principal_id` in the atomic consume condition. This prevents legacy or mutated self-approved records from authorizing a new debit.

Regression tests prove same-subject denial, pending-state preservation, denial audit evidence, independent-operator approval, and rejection of a legacy self-approved SQLite record. DynamoDB approval tests use a fake transaction client to inspect the conditional write; live DynamoDB behavior remains unverified.

### SH-SEC-003 — One-time approval capability is lost on page refresh

- **Severity:** MEDIUM — workflow availability / recoverability
- **Confidence:** HIGH
- **Status:** **Remediated locally** — audited operator-authenticated token rotation invalidates the previous hash and returns a replacement only once. SQLite and DynamoDB include an atomic previous-token-hash condition to prevent concurrent rotations from both succeeding. Operator UI recovery is implemented; full reload/lost-response browser E2E remains pending.
- **Affected paths:** [operator.html](../src/shadow_hunter/web/operator.html), [api.py](../src/shadow_hunter/api.py), [approvals.py](../src/shadow_hunter/approvals.py), [store.py](../src/shadow_hunter/store.py), [dynamodb_store.py](../src/shadow_hunter/dynamodb_store.py)

**Evidence**

The raw approval token is returned once by the approve endpoint and retained only in the browser's in-memory approvalTokens map. The database stores only its hash. The remediation adds an operator-authenticated recover-token endpoint that rotates the stored hash, invalidating the previous capability and issuing the replacement once. SQLite and DynamoDB compare the previously read token hash in the atomic update, preventing concurrent recovery requests from both succeeding. The operator UI offers recovery after refresh.

**Impact**

A refresh or lost response no longer permanently strands an approved request: an authenticated operator can request an audited replacement capability. The new UI recovery path has API/service regression coverage; a full browser E2E through reload, recovery and execution remains to be run.

**Recommended remediation**

Verify the operator UI recovery flow end to end in a browser, including refresh, concurrent recovery attempts, replacement-token execution, and replay rejection. Keep raw approval tokens out of persistent browser storage and audit records.

### SH-SEC-004 — Operator console has no explicit anti-framing response policy

- **Severity:** LOW
- **Confidence:** HIGH for missing headers; exploitation depends on a valid authenticated operator session in the framed page
- **Status:** **Remediated locally** — all API responses now include CSP frame-ancestors 'none', X-Frame-Options DENY, nosniff, and Referrer-Policy no-referrer. HTTP tests and a real Edge iframe attempt pass; deployed API Gateway headers remain unverified.
- **Affected paths:** [api.py](../src/shadow_hunter/api.py), [operator.html](../src/shadow_hunter/web/operator.html)

**Evidence**

FastAPI now applies Content-Security-Policy frame-ancestors 'none', X-Frame-Options DENY, X-Content-Type-Options nosniff, and Referrer-Policy no-referrer to its responses. HTTP tests assert these headers, and Microsoft Edge headless confirms a same-origin iframe attempt is blocked. Deployed API Gateway/edge behavior has not been checked.

**Impact and precondition**

A malicious site may attempt to frame the operator interface and trick an already authenticated operator into interacting with controls. The console keeps tokens in page memory rather than cookies, which reduces ambient cross-site request risk, but it does not replace an explicit framing policy.

**Recommended remediation**

Verify the response headers at the deployed API Gateway edge and retain the automated HTTP and browser framing checks as regression coverage.

### SH-SEC-005 — AgentCore runtime error text is reflected to API callers

- **Severity:** LOW
- **Confidence:** HIGH
- **Status:** **Remediated locally** — the customer chat route returns a generic 502 plus trace ID and does not reflect upstream AgentCore error text. An API regression test confirms the provider message is absent.
- **Affected paths:** [agentcore.py](../src/shadow_hunter/agentcore.py), [api.py](../src/shadow_hunter/api.py)

**Evidence**

The adapter still retains typed upstream failure information internally, but the customer chat route now returns a generic HTTP 502 message with a correlation trace ID and does not include the upstream error text. A regression test injects a sensitive provider message and confirms it is absent from the response.

**Impact**

An upstream runtime diagnostic may disclose internal service details to an authenticated customer. No actual sensitive response was observed; this is an unsafe error-boundary pattern.

**Recommended remediation**

Keep the generic client-facing response and correlation identifier. Confirm that any future internal provider diagnostics are restricted and redacted; retain the regression test against arbitrary upstream message reflection.

### SH-SEC-006 — Hosted Red/Blue evaluation has no per-operator usage budget

- **Severity:** MEDIUM
- **Confidence:** HIGH
- **Status:** **Partially mitigated** — an operator-authenticated kill switch and durable per-operator daily run quota (default 5) plus cooldown (default 60 seconds) are enforced in SQLite/DynamoDB before hosted inference. No global aggregate provider budget, cross-operator spend cap, or provider-spend alert exists yet.
- **Affected paths:** [api.py](../src/shadow_hunter/api.py), [store.py](../src/shadow_hunter/store.py), [dynamodb_store.py](../src/shadow_hunter/dynamodb_store.py), [infra/app/template.yaml](../infra/app/template.yaml)

**Evidence**

The route remains bounded to three rounds per invocation (up to six hosted calls). A kill switch and durable per-operator usage reservations now exist in SQLite and DynamoDB: the default daily limit is five runs per UTC day, with a 60-second cooldown. Reservations are atomic and audited. There is still no global provider spend cap, aggregate cross-operator quota, or provider-spend alert.

**Impact and precondition**

The new controls reduce repeated use by one operator, but multiple operators can still collectively consume hosted-model quota without a global aggregate budget. The API Gateway throttle and Lambda concurrency are additional infrastructure limits, not a provider spend cap.

**Recommended remediation**

Add a global provider budget, cross-operator aggregate cap, usage alerts, and operational monitoring for the kill switch. Keep the existing per-operator daily reservation/cooldown and kill-switch regression tests; add concurrent multi-operator and provider-spend monitoring tests as the global control is implemented.

### SH-SEC-007 — Cognito tenant/customer claims depend on unverified attribute-write controls

- **Severity:** HIGH — deployment blocker, conditional on Cognito configuration
- **Confidence:** HIGH that the pre-token trigger trusts these attributes; the deployed app-client mutability, user-provisioning permissions and actual issued claims have not been observed
- **Status:** **Infrastructure-as-code remediated; deployment proof remains open**. The new identity stack defines immutable tenant/customer attributes, a customer app client without write permission for those attributes, separate operator/M2M clients, operator MFA/group, and a V3_0 pre-token trigger. Actual pool deployment, trigger association, user provisioning controls, token-exchange entitlement, and issued claims have not been verified against AWS.
- **Affected paths:** [identity-stack.yaml](../infra/cognito/identity-stack.yaml), [cognito_pretoken.py](../src/shadow_hunter/cognito_pretoken.py), [pre-token-generation.yaml](../infra/cognito/pre-token-generation.yaml), [auth.py](../src/shadow_hunter/auth.py), [production readiness](production-deployment-readiness.md)

**Evidence**

The original trigger-only template did not define the pool or app clients. The follow-up infra/cognito/identity-stack.yaml now defines a production User Pool with immutable tenant_id/customer_id schema attributes, administrative-only user creation, customer and operator app clients with explicit email-only WriteAttributes, separate operator and M2M clients, an operator group/MFA posture, and a V3_0 trigger. Offline contract tests assert the pool schema, human-client read/write allowlists, operator/M2M separation, trigger association, and the limited scope of the existing-pool add-on. A pre-token regression also proves pre-existing tenant/customer claim overrides cannot replace values from trusted user-pool attributes. These are source-level controls only; no deployed pool, live app-client configuration, or issued token was inspected.

**Impact and precondition**

If deployment uses a different or manually modified pool, or provisioning paths bypass the immutable schema/admin-only process, a customer might still obtain altered tenant/customer claims. The IaC now addresses the intended configuration; the remaining risk is whether the deployed resources and actual tokens match it.

**Required remediation / release gate**

Deploy the reviewed identity stack only after separate AWS approval. In staging, inspect the actual pool schema and customer WriteAttributes, verify that user provisioning is administrator-controlled, confirm the V3_0 trigger association and operator MFA/group, then issue customer/operator/OBO tokens and prove that customer-controlled flows cannot change tenant/customer claims. Keep the customer API blocked until this live evidence exists.

## Positive controls observed

- Cognito mode verifies RS256 signatures using the user-pool JWKS, issuer, expiry, token use, client profile, required scopes, delegated audience, and configured act.sub; verifier failures fail closed.
- The customer tool surface is an explicit allowlist: get_order, check_refund_eligibility, and create_refund_request. Refund execution is not an agent tool.
- The policy engine denies unknown tools, malformed argument sets, missing identity, cross-tenant/customer ownership, ineligible refunds, currency mismatch, over-balance amounts, and conflicting idempotency keys.
- Approval records bind the request/action digest and policy version; raw approval tokens are hashed at rest and consumed transactionally.
- DynamoDB refund execution uses conditional transactional state transitions and re-checks order ownership, currency, eligibility, and remaining balance at execution time.
- Application IAM is restricted to the configured DynamoDB table/index and two configured Secrets Manager targets. The audit exporter uses a separate role limited to stream reads, S3 prefix writes, DLQ sends, and logs. The audit verifier has a separate read-only policy example.
- The operator UI stores the access token and one-time approval tokens in page memory; dynamic values inserted into HTML are passed through escapeHtml in the reviewed render paths.
- The hosted evaluation uses a disposable SQLite database with synthetic customer/order records; its hosted-model path is separate from the local Ollama AgntID demo.
- MCP requests require exactly one Bearer header and use the same ToolGateway; localhost-only host protection remains the default.

These source observations are positive design controls, not proof that the deployed AWS configuration or runtime behavior satisfies them.

## Release-gate verification matrix

| ID | Current status | Evidence / remaining gate |
|---|---|---|
| SH-SEC-001 | **Remediated in source** | HTTP/MCP use the shared public response normalizer; local regressions preserve detailed audit reasons. Re-run response-equivalence checks against deployed API/MCP in staging. |
| SH-SEC-002 | **Remediated in source** | SQLite/DynamoDB approval and execution both enforce requester/approver separation and record denial evidence. Verify live DynamoDB conditions and real Cognito group separation in staging. |
| SH-SEC-003 | **Remediated locally; browser E2E pending** | Operator-authenticated token rotation, old-hash invalidation, audit record and atomic previous-hash condition are covered by service/API/DynamoDB contract tests. Run full browser reload/recovery/execution/replay coverage. |
| SH-SEC-004 | **Remediated locally; edge verification pending** | HTTP response-header tests and Edge iframe CSP check pass. Verify deployed API Gateway response headers. |
| SH-SEC-005 | **Remediated locally** | AgentCore failure injection confirms the HTTP 502 does not reflect arbitrary provider error text and includes a trace ID. |
| SH-SEC-006 | **Partially mitigated** | Per-operator daily limit, cooldown and kill switch are covered by SQLite/DynamoDB tests. Add global spend cap, aggregate quota and alerts. |
| SH-SEC-007 | **IaC controls and offline contract tests committed; live deployment proof open** | 39 focused Cognito template/auth/pre-token tests passed in the local cycle. Identity stack defines immutable trusted attributes and explicit email-only human-client write allowlists; a regression protects trusted claims from pre-existing overrides. Inspect deployed pool, every client/IdP mapping, provisioning controls and issued tokens in staging. |

## Verification limitations

| Check | Current result |
|---|---|
| Full Python regression/integration suite on merged main | **177 passed** (isolated Python 3.11 environment with dev/server/aws extras) |
| Focused approval/API/DynamoDB/gateway security tests | **37 passed**; includes maker-checker, token recovery/rotation, evaluation quota and public resource-denial behavior |
| Focused Cognito identity contract tests (local SH-SEC-007 cycle) | **39 passed**; offline template, authenticator and pre-token handler contracts; no live Cognito calls |
| Browser security | Microsoft Edge headless check passed for operator page response headers and iframe blocking; full recovery UI E2E and deployed edge behavior remain pending |
| Semgrep source/security/secrets | **0 findings**; 122 rules across 22 tracked source files on the merged tree |
| pip-audit | **No known vulnerabilities found** in src/requirements.txt |
| Bandit | **0 High / 0 Medium / 10 Low** on merged source; low findings are listed in the cycle record, and no production secret was reported |
| Ruff | **88 repository-wide findings** under the installed default ruleset; no blanket autofix was applied. Duplicate new DynamoDB test definitions were removed. |
| Python compilation / repository metadata / diff | **Passed**: scripts/validate-repo.py, compileall for src/shadow_hunter and tests, and git diff --check |
| cfn-lint | **Passed all four production templates** on the merged tree |
| SAM validation | sam validate --lint passed the existing-pool Cognito trigger, data and API templates; new identity stack passed basic SAM validation because bundled SAM schema lags the Cognito delegation property |
| SAM build | Existing committed WSL2 cycle record reports sam build --no-use-container passed all four templates. A separate Windows-host API build attempt selected pywin32 for a Linux Lambda target and failed for host-platform reasons. |
| AWS identity/IAM/resources/staging | Not inspected; no AWS resources created, deployed or changed |
| Staging cross-tenant denial + independent S3 audit verification | Not run; requires separate AWS approval |

## Prioritized remediation sequence

1. Close the SH-SEC-007 live-deployment gate by verifying the new identity stack's actual pool schema, app-client WriteAttributes, administrative provisioning path, V3_0 trigger association, operator MFA/group and issued tokens in staging.
2. Run SH-SEC-001/002 response-equivalence and live DynamoDB maker-checker checks in staging.
3. Complete operator UI reload/recovery/execution browser E2E and verify deployed API Gateway headers (SH-SEC-003/004).
4. Add a global hosted-provider quota, spend cap and alerts (SH-SEC-006).
5. Re-run browser and relevant SAST/dependency tools as appropriate against the final committed state.
6. Obtain separate AWS approval before deployment, package uploads, live model calls, or billable resource changes.

**Verdict:** source-level review is complete for this pass, but the overall security assessment and release verification remain **PARTIAL**. This document does not authorize AWS deployment.
