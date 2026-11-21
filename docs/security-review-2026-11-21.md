# Shadow Hunter security review

- Review date: 2026-11-20
- Repository: [KUNDURUHIMANEESHREDDY/shadow-hunter](https://github.com/KUNDURUHIMANEESHREDDY/shadow-hunter)
- Reviewed baseline: main at 6b26b6aaea1308706abb1ba3eac375251bd45d25
- Assessment: **PARTIAL — broad static source review; not a penetration test, certification, or release approval**
- Deployment status: **NOT DEPLOYED**; no AWS account resources or live credentials were accessed or changed.

## Executive summary

The current implementation has several sound control boundaries: customer and delegated-agent JWT profiles are distinct in Cognito mode; tool calls pass through a fixed allowlist and deterministic policy engine; the model cannot execute refunds; approval capabilities are hashed at rest; SQLite and DynamoDB execution paths re-check stored approval state and order balance; and AWS roles are separated for application data access, audit export, and read-only audit verification.

The source review also found release-relevant gaps. The most important deployment-dependent risk is that the pre-token trigger trusts Cognito tenant/customer attributes while the repository does not provision the user pool or constrain which app clients can write those attributes. A follow-up remediation has since closed the order-lookup disclosure in the authenticated HTTP and MCP response paths. The remaining application-level gaps are no enforced maker-checker rule, an unrecoverable one-time approval token after a page refresh, missing operator-console framing protections, upstream AgentCore error reflection, and unbounded per-operator hosted-model evaluation usage.

**Do not deploy the customer or operator API to production until the High finding is closed and the Medium findings are fixed or formally accepted with compensating controls.** The AWS deployment gate also remains closed pending formal SAM validation, identity configuration, account/Region confirmation, cost approval, and staging evidence.

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

No tests, builds, linters, SAM validators, browser checks, fuzzing, live endpoint calls, AWS API calls, or penetration tests were run in the original source-review cycle. The owner later authorized the prioritized remediation work and regression testing; follow-up evidence for SH-SEC-001 is recorded below.

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
- **Status:** Open
- **Affected paths:** [operator.html](../src/shadow_hunter/web/operator.html#L121), [operator.html](../src/shadow_hunter/web/operator.html#L189), [operator.html](../src/shadow_hunter/web/operator.html#L387), [api.py](../src/shadow_hunter/api.py#L384), [store.py](../src/shadow_hunter/store.py#L354)

**Evidence**

The raw approval token is returned once by the approve endpoint, retained in the browser's in-memory approvalTokens map, and never persisted by the UI. The database stores only the token hash. After a refresh, the UI explicitly reports that the one-time token is unavailable; the persisted approval is already APPROVED, and the existing approve endpoint will not issue another token for that state. No recovery or token-rotation operation exists.

**Impact**

A refresh, tab close, browser crash, or lost response after approval can leave an approved refund that cannot be executed through the supported UI. Operators may require manual database intervention, which is not an acceptable operational recovery path.

**Recommended remediation**

Preserve the one-time-token security property while adding an audited recovery protocol. Options include an explicit operator-authenticated capability rotation that invalidates the previous hash and issues a replacement once, or a server-side execution challenge bound to the approved action and operator identity. Do not store raw approval tokens in localStorage or the audit log. Add browser reload, lost-response, token-rotation, and replay tests.

### SH-SEC-004 — Operator console has no explicit anti-framing response policy

- **Severity:** LOW
- **Confidence:** HIGH for missing headers; exploitation depends on a valid authenticated operator session in the framed page
- **Status:** Open
- **Affected paths:** [api.py](../src/shadow_hunter/api.py#L98), [operator.html](../src/shadow_hunter/web/operator.html)

**Evidence**

The FastAPI application and SAM API template do not set Content-Security-Policy frame-ancestors or X-Frame-Options for the operator page. The console contains approval and refund-execution controls.

**Impact and precondition**

A malicious site may attempt to frame the operator interface and trick an already authenticated operator into interacting with controls. The console keeps tokens in page memory rather than cookies, which reduces ambient cross-site request risk, but it does not replace an explicit framing policy.

**Recommended remediation**

Send Content-Security-Policy: frame-ancestors 'none' (or the exact approved ancestor list) and X-Frame-Options: DENY on the operator page. Add X-Content-Type-Options: nosniff and a deliberate Referrer-Policy. Verify headers at the deployed API Gateway edge and add an automated response-header test.

### SH-SEC-005 — AgentCore runtime error text is reflected to API callers

- **Severity:** LOW
- **Confidence:** HIGH
- **Status:** Open
- **Affected paths:** [agentcore.py](../src/shadow_hunter/agentcore.py#L146), [api.py](../src/shadow_hunter/api.py#L285)

**Evidence**

When an AgentCore stream contains runtimeClientError, the adapter raises an exception containing the upstream message. The chat route returns str(exc) as the HTTP 502 detail.

**Impact**

An upstream runtime diagnostic may disclose internal service details to an authenticated customer. No actual sensitive response was observed; this is an unsafe error-boundary pattern.

**Recommended remediation**

Return a stable generic error and correlation identifier to the caller. Keep detailed provider diagnostics in a restricted, redacted server-side log. Add tests proving arbitrary upstream messages are not reflected in the HTTP response.

### SH-SEC-006 — Hosted Red/Blue evaluation has no per-operator usage budget

- **Severity:** MEDIUM
- **Confidence:** HIGH
- **Status:** Open
- **Affected paths:** [api.py](../src/shadow_hunter/api.py#L457), [infra/app/template.yaml](../infra/app/template.yaml)

**Evidence**

The operator-only evaluation route permits up to three rounds. Each round makes one Red and one Blue hosted NVIDIA request, so a single invocation can trigger up to six model calls. API Gateway has a default global throttle and the Lambda has a reserved-concurrency limit, but no per-operator run quota, cooldown, daily call budget, or cost circuit breaker is present in the inspected route.

**Impact and precondition**

A compromised operator account or an authorized operator repeatedly invoking the route can consume hosted-model quota and incur unbounded cumulative provider cost relative to the absence of a per-operator budget. The global throttle and Lambda concurrency are useful limits but are not a usage budget.

**Recommended remediation**

Add per-operator and global run quotas, daily call/token budgets, a cooldown, and a kill switch. Record provider usage metadata without retaining prompts or secrets. Alert on quota exhaustion and provider spend. Add tests for concurrent requests, quota exhaustion, retry behavior, and kill-switch enforcement.

### SH-SEC-007 — Cognito tenant/customer claims depend on unverified attribute-write controls

- **Severity:** HIGH — deployment blocker, conditional on Cognito configuration
- **Confidence:** HIGH that the trust dependency exists; actual app-client mutability is not observable from this repository
- **Status:** Open — must be closed before any customer-facing Cognito deployment
- **Affected paths:** [cognito_pretoken.py](../src/shadow_hunter/cognito_pretoken.py#L17), [pre-token-generation.yaml](../infra/cognito/pre-token-generation.yaml), [auth.py](../src/shadow_hunter/auth.py#L270), [production readiness](production-deployment-readiness.md)

**Evidence**

The pre-token-generation function reads custom:tenant_id and custom:customer_id from Cognito user attributes and adds them to access-token claims. The checked-in Cognito SAM template accepts an existing UserPoolId, creates only the trigger Lambda and invoke permission, and does not define the user pool, app clients, or their WriteAttributes permissions.

**Impact and precondition**

If a customer-facing app client can write either trusted custom attribute, a user may be able to alter the identity context that Shadow Hunter uses for tenant and customer authorization. The repository contains no deployed pool configuration proving these attributes are immutable to end users.

**Required remediation / release gate**

Use a controlled administrative provisioning process for tenant/customer attributes. Explicitly remove both custom attributes from customer app-client write permissions and prevent end-user profile mutation through other paths. Verify the operator app client, group assignment, MFA policy, and the Cognito V3_0 pre-token trigger association. Test that customer tokens cannot acquire another tenant/customer identity. Do not expose the customer API until this is evidenced against the actual user pool and issued tokens.

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

| ID | Required evidence before release | Suggested verification |
|---|---|---|
| SH-SEC-001 | No customer-visible order-existence oracle | Local HTTP/MCP regression tests pass for nonexistent, cross-tenant, and cross-customer IDs; staging verification remains pending |
| SH-SEC-002 | Maker-checker invariant or documented policy exception | Local SQLite tests and DynamoDB transaction-contract tests pass; verify the conditional transitions against live DynamoDB in staging |
| SH-SEC-003 | Recoverable, auditable one-time approval workflow | Browser test for reload, lost response, token rotation, one-time consumption, and replay |
| SH-SEC-004 | Operator page cannot be framed by unapproved origins | HTTP header assertions and cross-origin iframe test |
| SH-SEC-005 | Upstream error details are not reflected | Simulate arbitrary AgentCore runtime error text and assert generic HTTP response |
| SH-SEC-006 | Hosted evaluation has bounded cumulative usage | Per-operator quota, concurrent-call, daily-budget, and kill-switch tests |
| SH-SEC-007 | Trusted identity attributes cannot be customer-written | Inspect actual Cognito app-client WriteAttributes, pool attributes, trigger version/association, and issued JWT claims; attempt customer self-modification in staging |

## Verification limitations

| Check | Result |
|---|---|
| Static source inspection of API/auth/policy/gateway/approval/data paths | Performed; findings above |
| Targeted default-branch credential-marker search | Performed; no concrete credential value surfaced; not a history scan |
| Unit / integration / adversarial tests | Follow-ups: SH-SEC-001 focused gateway/API/MCP tests 23 passed; SH-SEC-002 approval/DynamoDB/gateway tests 22 passed; broader suite 163 passed with the Lambda-entrypoint test excluded because optional mangum is absent. |
| Browser / header / clickjacking checks | Not run |
| Dependency / SAST / DAST scan | Not run |
| SAM CLI validation / cfn-lint / package build | Not run |
| AWS identity, IAM, storage, Lambda, API Gateway, AgentCore inspection | Not run; no AWS resources created or accessed |
| Staging cross-tenant denial + independent S3 audit verification | Not run |

## Prioritized remediation sequence

1. Close SH-SEC-007 by proving customer clients cannot write trusted tenant/customer attributes; complete the real Cognito configuration.
2. **SH-SEC-002 remediated locally:** verify the same-subject denial and conditional transition against the deployed DynamoDB store in staging.
3. **SH-SEC-001 remediated locally:** repeat the response-equivalence check against the deployed API/MCP service during staging verification.
4. Design an audited, safe approval-token recovery flow (SH-SEC-003).
5. Add operator response headers and sanitize AgentCore error responses (SH-SEC-004/005).
6. Add per-operator/global inference budgets and a kill switch (SH-SEC-006).
7. Keep verification explicitly authorized and scoped per engineering cycle; add/run regression evidence for each remaining finding and complete formal infrastructure validation.

**Verdict:** source-level review is complete for this pass, but the overall security assessment and release verification remain **PARTIAL**. This document does not authorize AWS deployment.
