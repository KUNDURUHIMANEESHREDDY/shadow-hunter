# Shadow Hunter security review

- Review date: 2026-11-20
- Repository: [KUNDURUHIMANEESHREDDY/shadow-hunter](https://github.com/KUNDURUHIMANEESHREDDY/shadow-hunter)
- Reviewed baseline: main at 6b26b6aaea1308706abb1ba3eac375251bd45d25
- Assessment: **PARTIAL — broad static source review; not a penetration test, certification, or release approval**
- Deployment status: **NOT DEPLOYED**; no AWS account resources or live credentials were accessed or changed.

## Executive summary

The current implementation has several sound control boundaries: customer and delegated-agent JWT profiles are distinct in Cognito mode; tool calls pass through a fixed allowlist and deterministic policy engine; the model cannot execute refunds; approval capabilities are hashed at rest; SQLite and DynamoDB execution paths re-check stored approval state and order balance; and AWS roles are separated for application data access, audit export, and read-only audit verification.

The source review also found release-relevant gaps. The most important deployment-dependent risk is that the pre-token trigger trusts Cognito tenant/customer attributes while the repository does not provision the user pool or constrain which app clients can write those attributes. Application-level gaps include distinguishable order-lookup denial reasons, no enforced maker-checker rule, an unrecoverable one-time approval token after a page refresh, missing operator-console framing protections, and unbounded per-operator hosted-model evaluation usage.

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

No tests, builds, linters, SAM validators, browser checks, fuzzing, live endpoint calls, AWS API calls, or penetration tests were run in this cycle. The repository's docs/engineering-cycle.md currently prohibits verification commands until the owner explicitly changes that instruction. Source-level observations below therefore remain unconfirmed by runtime tests.

## Findings

### SH-SEC-001 — Order lookup exposes resource-existence distinctions

- **Severity:** MEDIUM
- **Confidence:** HIGH
- **Status:** Open
- **Affected paths:** [gateway.py](../src/shadow_hunter/gateway.py#L100), [policy.py](../src/shadow_hunter/policy.py#L197), [policy.py](../src/shadow_hunter/policy.py#L225), [policy.py](../src/shadow_hunter/policy.py#L229), [api.py](../src/shadow_hunter/api.py#L319)

**Evidence**

The gateway loads an order using the caller-supplied order_id before policy evaluation. The policy returns ORDER_CONTEXT_MISSING when the identifier has no record, but returns RESOURCE_TENANT_MISMATCH or RESOURCE_OWNER_MISMATCH when a record exists but belongs to another tenant/customer. The API returns the decision payload, including the reason code, to the authenticated caller.

**Impact and precondition**

An authenticated customer or delegated agent able to submit guessed order IDs can distinguish missing IDs from existing foreign resources. The response does not return the foreign order contents, but it provides an order-existence and ownership-classification oracle.

**Recommended remediation**

Use a customer-scoped data lookup where practical. Normalize outward responses for missing and unauthorized resources to the same non-enumerating result. Preserve the precise internal reason in the audit event for operators. Add tests proving that missing, cross-tenant, and cross-customer identifiers have indistinguishable customer-visible responses while retaining distinct restricted audit evidence.

### SH-SEC-002 — Approval does not enforce separation of duties

- **Severity:** MEDIUM
- **Confidence:** HIGH for the missing code invariant; exploitability depends on identity/group configuration
- **Status:** Open
- **Affected paths:** [approvals.py](../src/shadow_hunter/approvals.py#L30), [store.py](../src/shadow_hunter/store.py#L354), [dynamodb_store.py](../src/shadow_hunter/dynamodb_store.py#L422), [api.py](../src/shadow_hunter/api.py#L384)

**Evidence**

The approval service checks that an approver ID is non-empty. The SQLite and DynamoDB approval transitions store the approver identity but do not compare it with the refund request's originating principal_id. Cognito requires an operator client ID and operator group, but one Cognito subject can potentially be provisioned as both a customer and an operator.

**Impact and precondition**

Where policy or business rules require a second person to approve a customer's refund, an identity holding both customer and operator privileges can approve its own request. The current code does not enforce a maker-checker invariant.

**Recommended remediation**

Decide and document whether self-approval is prohibited. For a maker-checker policy, compare the authenticated operator subject with the refund request's originating principal in the authoritative persistence transition, not only in the UI. Enforce the same invariant in SQLite and DynamoDB and add negative tests for same-subject approval and positive tests for an independent operator.

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
- **Affected paths:** [agentcore.py](../src/shadow_hunter/agentcore.py#L146), [api.py](../src/shadow_hunter/api.py#L345)

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
| SH-SEC-001 | No customer-visible order-existence oracle | API tests for nonexistent, cross-tenant, and cross-customer IDs; compare public responses and inspect restricted audit distinctions |
| SH-SEC-002 | Maker-checker invariant or documented policy exception | SQLite and DynamoDB tests for same-subject deny and independent-operator allow |
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
| Unit / integration / adversarial tests | Not run under the current repository verification policy |
| Browser / header / clickjacking checks | Not run |
| Dependency / SAST / DAST scan | Not run |
| SAM CLI validation / cfn-lint / package build | Not run |
| AWS identity, IAM, storage, Lambda, API Gateway, AgentCore inspection | Not run; no AWS resources created or accessed |
| Staging cross-tenant denial + independent S3 audit verification | Not run |

## Prioritized remediation sequence

1. Close SH-SEC-007 by proving customer clients cannot write trusted tenant/customer attributes; complete the real Cognito configuration.
2. Decide and enforce maker-checker separation (SH-SEC-002).
3. Remove the order-existence oracle (SH-SEC-001).
4. Design an audited, safe approval-token recovery flow (SH-SEC-003).
5. Add operator response headers and sanitize AgentCore error responses (SH-SEC-004/005).
6. Add per-operator/global inference budgets and a kill switch (SH-SEC-006).
7. Obtain explicit owner authorization to change the verification rule in docs/engineering-cycle.md; then add/run regression evidence for every finding and complete formal infrastructure validation.

**Verdict:** source-level review is complete for this pass, but the overall security assessment and release verification remain **PARTIAL**. This document does not authorize AWS deployment.
