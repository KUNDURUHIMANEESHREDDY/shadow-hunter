# Production deployment readiness

- Review date: 2026-11-20
- Repository head reviewed: `6b26b6aaea1308706abb1ba3eac375251bd45d25` (`main`)
- Selected deployment Region: `ap-southeast-2` (Asia Pacific — Sydney)
- Status: **NO-GO — SOURCE REVIEW UPDATED; FORMAL VALIDATION AND AWS DEPLOYMENT NOT COMPLETE**
- Scope: current SAM/CloudFormation templates, stack dependencies, source-level API/auth/data security review, and staged deployment preparation.
- AWS resources created or changed: **none**.

## Go / no-go

**NO-GO for production deployment at this point.** All four current templates pass standalone CloudFormation lint and SAM packaging; three pass SAM lint validation and the new identity stack passes SAM basic validation. The security-review findings and live Cognito/AgentCore/data-plane verification remain release gates.

The user-approved boundary for this cycle is template review and preparation only. Do not create stacks, user pools, app clients, buckets, tables, queues, Lambda functions, API Gateway APIs, AgentCore Harnesses, Gateways, credential providers, model invocations, or paid resources until the owner gives explicit AWS deployment approval.

## Current baseline update — 2026-11-20

The prior infrastructure review referenced an older commit. This document now
uses the current reviewed main baseline. The source-level security review is
recorded in [security-review-2026-11-21.md](security-review-2026-11-21.md).
Its overall verdict is **PARTIAL**, and it identifies one conditional High
Cognito trust-boundary blocker plus six application/operability findings.
The detailed evidence, confidence, remediation direction, and required
regression tests are in that report.

The selected target remains ap-southeast-2 (Sydney). AWS's current
[AgentCore supported-Regions matrix](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-regions.html)
lists Sydney support for the Harness, Gateway, Identity, and Policy features
used by this architecture. Regional availability does not establish account
entitlement, service quotas, model availability, Cognito token-exchange
configuration, or pricing; those remain Stage 0 checks.

The earlier source-review cycle did not run tests, SAST/DAST, browser checks, SAM validation, cfn-lint, packaging, or AWS integration. The production-only offline implementation and its later verification are recorded below. Those checks do not close the security findings or prove live AWS behavior; the release gate remains **NO-GO**. No AWS resources or credentials were accessed.

## Security blockers to close before customer-facing deployment

1. **Trusted Cognito attributes (High, deployment-dependent):** customer
   app clients must not be able to write custom:tenant_id or
   custom:customer_id. Enforce controlled administrative provisioning and
   demonstrate issued token claims in staging.
2. **Maker-checker decision (Medium):** decide whether the request's
   originating principal may approve its own request. If not, enforce the
   separation in both SQLite and DynamoDB persistence transitions.
3. **Order identifier disclosure (Medium):** remediated locally in the
   authenticated HTTP and MCP response paths and covered by regression tests.
   Repeat the response-equivalence check against deployed services in staging
   before release; detailed audit reasons remain restricted to operators.
4. **Approval token recovery (Medium):** add a secure, audited recovery or
   rotation workflow for the in-memory-only one-time token.
5. **Operator console hardening (Low):** add anti-framing and standard browser
   security headers.
6. **Upstream error boundary (Low):** return generic AgentCore failures to
   customers and retain only redacted diagnostics internally.
7. **Hosted inference budget (Medium):** introduce per-operator/global usage
   budgets, alerts, and a kill switch for the NIM evaluation route.

Do not waive the conditional High item based solely on source comments. Verify
the actual Cognito user-pool and app-client configuration.

## Template inventory and review

The production implementation now has four independently validated SAM templates: a new Cognito identity stack, an existing-pool Cognito trigger add-on, the data stack, and the application stack. Their dependencies are passed as outputs and parameters.

| Template | Main resources | Dependency / interface |
|---|---|---|
| `infra/cognito/identity-stack.yaml` | Production User Pool, V3 trigger, customer/operator/agent clients, resource servers, operator group and hosted domain | Requires production SES identity and HTTPS customer/operator callback/logout URLs. |
| `infra/cognito/pre-token-generation.yaml` | Pre-token Lambda and Cognito invoke permission | Existing-pool add-on only; requires an already-existing User Pool ID. Pool trigger association is a separate step. |
| `infra/data/dynamodb.yaml` | DynamoDB table/GSI/stream, S3 Object Lock archive, exporter Lambda/role, SQS DLQ, CloudWatch alarm | Outputs table name/ARN, archive bucket name/ARN, and DLQ URL. |
| `infra/app/template.yaml` | FastAPI Lambda, API Gateway HTTP API, route JWT authorizers, logs and runtime IAM role | Requires data-stack outputs and exact Cognito issuer/client/scope/actor values. Harness ARN is optional during initial API deployment. |

### Package-path review

The template-relative code locations correspond to the checked-in handlers and dependency manifests:

- New Cognito identity stack: `../../src/shadow_hunter/`, handler `cognito_pretoken.handler`, nested `src/shadow_hunter/requirements.txt`.
- Existing-pool Cognito trigger add-on: `../../src/shadow_hunter/`, handler `cognito_pretoken.handler`, nested `src/shadow_hunter/requirements.txt`.
- Data stack: `../../src/shadow_hunter/`, handler `audit_exporter.handler`, nested `src/shadow_hunter/requirements.txt`.
- Application stack: `../../src/`, handler `shadow_hunter.lambda_handler.handler`, `src/requirements.txt`.

The initial package-path review was source-only. Subsequent local SAM builds passed for all four templates; this does not prove service-side deployment behavior.

### Earlier baseline structural validation (superseded by current verification below)

At the earlier review baseline, an offline YAML parser with CloudFormation intrinsic-tag handling parsed the three templates then present and checked their local `Ref` and `GetAtt` resource references:

| Template | YAML parse | Internal reference check |
|---|---:|---:|
| Cognito | Pass | Pass |
| Data | Pass | Pass |
| Application | Pass | Pass |

This historical check was **not** formal CloudFormation schema validation. SAM CLI and `cfn-lint` were unavailable during that earlier review. The current four-template validation and package results are recorded in the production-only offline implementation update below.

The following were the earlier three-template validation commands. Current four-template validation has since been completed locally, as recorded below:

```powershell
sam validate --lint --template-file infra/cognito/pre-token-generation.yaml
sam validate --lint --template-file infra/data/dynamodb.yaml
sam validate --lint --template-file infra/app/template.yaml
```

A successful local validation or package build is not proof of AWS service acceptance or production operation. Live deployment remains a separate approval-gated activity.

## Findings that must be closed

### 1. Cognito identity infrastructure and trusted attributes

The earlier review baseline had only an existing-pool trigger add-on. This implementation adds infra/cognito/identity-stack.yaml for a new production User Pool, and retains infra/cognito/pre-token-generation.yaml as an add-on for an existing pool. The new identity stack defines:

- the User Pool and immutable custom:tenant_id / custom:customer_id attributes;
- separate customer, operator, and agent/M2M app clients with restricted attribute write permissions;
- resource servers, audiences, scopes, operator group, and hosted sign-in domain;
- the V3_0 pre-token trigger association and Cognito-to-Lambda invoke permission.

The AgentCore OBO provider is documented with an external Secrets Manager reference, but its live provider/Gateway configuration is not deployed. Cognito token-exchange account entitlement and real issued token claims remain unverified.

For a new pool, the identity stack associates the V3_0 trigger. For an existing pool, the add-on still requires deliberate trigger association. The customer app client cannot write the immutable tenant/customer attributes; actual deployed pool configuration and administrative provisioning controls still require live evidence.

For this workload, configure the trigger as **V3_0**. V3 supports M2M ClientCredentials access-token customization, which is required for the actor-token flow; the Lambda intentionally passes ClientCredentials actor events through unchanged. The AgentCore guide was aligned to this version in this cycle. Confirm the User Pool feature plan and account-level token-exchange enablement before attempting OBO configuration. Cognito token exchange requires the applicable Essentials/Plus feature tier and its issued scopes remain constrained by the subject token and exchange client's allowed scopes. <https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-token-generation.html> <https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-token-exchange.html>

### 2. Identity values must be real, not inferred

Before deploying the API stack, record and independently verify:

- exact Cognito issuer URL;
- customer app-client ID;
- **separate operator app-client ID** (required by the API SAM parameters);
- registered resource-server audience and delegated refund scope;
- exact `act.sub` agent actor subject from a real delegated token;
- operator group name;
- customer and token-exchange tokens carrying the trusted tenant/customer claims.

The trusted tenant/customer values must come from controlled User Pool attributes or a tenant directory, never from prompts, tool arguments, client metadata, or caller-supplied headers.

### 3. Stack dependency and Harness ARN cycle

Use this order to avoid a deployment cycle:

1. Finish Cognito identity setup and deploy/attach the pre-token trigger.
2. Deploy the data stack and capture its outputs.
3. Deploy the API stack with `HarnessArn` left empty. The REST API can then be created and its `ApiBaseUrl` captured; chat intentionally remains unavailable until the Harness is configured.
4. Create the Gateway target using the API base URL, then create the Harness referencing the Gateway.
5. Update the API stack with the deployed Harness ARN and re-check the customer-to-Harness identity flow.

The OpenAPI target server URL must be the API base URL including its `/prod` stage. Keep the target operation IDs aligned with the Cedar policy. The Cedar template currently expects the Gateway target/tool prefix `RefundTools` (actions `RefundTools___get_order`, `RefundTools___check_refund_eligibility`, and `RefundTools___create_refund_request`); verify the actual generated tool names before attaching the policy in ENFORCE mode.

AgentCore's intended identity path is customer JWT to Harness `CUSTOM_JWT`, then Gateway target outbound `OAUTH` / `TOKEN_EXCHANGE` to the API. Do not replace this with a shared bearer token or generic Gateway IAM credentials. The Harness-to-Gateway service hop uses the Harness execution role, while the target hop exchanges the end-user identity. <https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/harness-security.html> <https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-outbound-auth.html>

### 4. Audit coverage and independent verification

The data template's exporter only sees DynamoDB Stream records emitted after the Stream is enabled. It does not backfill historical audit rows. Before directing business traffic to the table, confirm that the stream mapping is enabled and that a synthetic audit event reaches the S3 archive.

DynamoDB Streams retains source records for 24 hours. The SQS DLQ retains failure metadata for 14 days, but this does not extend the source-stream retention window. Reconcile and replay failures before that source window expires.

The existing `shadow-hunter-audit-reconcile` command verifies **key coverage only**: it compares AUDIT GSI event identities with S3 object keys and does not read archived object bodies. A separate `shadow-hunter-audit-verify` command is now authored for content verification. It uses a separate read-only auditor identity with `dynamodb:Query` on the table and GSI plus `s3:GetObject` on the archive prefix (policy example: `infra/data/audit-verification-policy.example.json`). A `--trace-id` check queries the base-table `TRACE#<trace-id>` partition; a full verification queries the AUDIT GSI. It reads the allowlisted source audit row and matching S3 object, compares exact canonical JSON bytes, and emits SHA-256 hashes/mismatch status without printing payloads. Run key reconciliation as well to detect orphan objects. Neither command has been run against AWS yet. Do not grant the verifier PutObject, DeleteObject, retention-bypass, queue-delete, or application-write permissions.

### 5. Public API and runtime boundaries

The application template exposes the default API Gateway HTTPS endpoint. It intentionally exposes only the health endpoint, static operator page, customer chat, delegated tool path, and authenticated operator API; it does not expose the localhost-only MCP endpoint. The health and static console routes are public, but operator data routes remain JWT-protected. Confirm those routes reveal no customer data.

The Lambda role is limited to the application DynamoDB table/GSI and basic logging. The audit exporter has a separate stream-read, S3-prefix-write, DLQ-send, and logging role. The audit verifier must remain a separate read-only identity.

The application still updates a Shadow Hunter demo refund ledger; it does not contact a payment provider or move money. Do not describe this as real payment execution.

## Deployment preparation checklist

### Stage 0 — approval and account controls

- Use the owner-selected Region `ap-southeast-2` (Sydney); do not substitute another Region without approval.
- Obtain explicit owner approval for the target AWS account, deployment environment, and billable resource creation. No account ID, SSO start URL, or authenticated AWS profile was established in this review.
- Confirm the current AgentCore regional matrix and service quotas for Harness, Gateway, Identity, and Policy; confirm Cognito token-exchange entitlement and the exact hosted model/provider access. Regional service availability is not proof of account enablement.
- Confirm account-level budgets/alerts and service quotas.
- Confirm the approved Cognito feature tier, Bedrock model access/Region, AgentCore availability, and token-exchange feature enablement.
- Review retention requirements before selecting an Object Lock duration or mode. The template defaults to Governance mode for 365 days. Do not select Compliance mode without legal approval.
- Confirm the self-service refund limit in currency minor units and the approval TTL; do not choose business thresholds by guesswork.

### Stage 1 — Cognito

- Decide whether to use an existing pool or add a separately reviewed User Pool stack.
- Ensure the pool has trusted tenant/customer attributes and a controlled provisioning process. Customer-facing app clients must not have `WriteAttributes` permission for `custom:tenant_id` or `custom:customer_id`; verify no self-service profile path can change them.
- Require the approved operator MFA posture and a dedicated operator app client/group. Prove that customer users cannot self-assign operator membership.
- Associate the pre-token Lambda using the required `V3_0` trigger version and capture the deployed trigger configuration as evidence.
- Create distinct customer and operator app clients, a dedicated agent/M2M client, operator group, resource server, scopes, and the approved OAuth token-exchange/delegation flow.
- Deploy `infra/cognito/pre-token-generation.yaml` with the selected `UserPoolId`, then associate its output Lambda ARN to the pool as a V3_0 pre-token trigger.
- Verify customer token claims and the derived OBO token's issuer, subject, audience, scopes, and `act.sub`; never store raw tokens in logs or source control.

### Stage 2 — DynamoDB and audit archive

- Validate `infra/data/dynamodb.yaml` with SAM/cfn-lint.
- Deploy with `Environment=production`, `AuditRetentionMode=GOVERNANCE`, and the legally approved retention days.
- Record `TableName`, `TableArn`, `AuditArchiveBucketName`, `AuditArchiveBucketArn`, and `AuditExportDlqUrl`.
- Confirm DynamoDB point-in-time recovery, deletion protection, stream enablement, S3 versioning/Object Lock/default retention, public access blocks, TLS-only policy, conditional writes, DLQ encryption, and alarm configuration.
- Run a synthetic audit-write/export smoke check only after deployment approval; do not send real customer data during initial validation.

### Stage 3 — FastAPI application

- Validate `infra/app/template.yaml`.
- Deploy with the Stage 1 Cognito values and Stage 2 table name/ARN outputs.
- Supply the approved `RefundLimitMinor` and `ApprovalTtlSeconds`; use `HarnessArn=''` for this first API deployment.
- Capture `ApiBaseUrl` and `ApiFunctionArn`. Confirm only expected routes exist, the three JWT profiles fail closed, and the application role has no infrastructure administration or S3 archive-write permissions.

### Stage 4 — AgentCore Harness and Gateway

- Configure the Harness `CUSTOM_JWT` authorizer with the correct Cognito discovery URL and allowed customer app client.
- Verify an operator cannot approve a refund request they originated if the maker-checker policy is enabled; do not rely on role naming alone.
- Create the Gateway with JWT inbound authentication; add the OpenAPI target using the deployed API base URL and OBO `TOKEN_EXCHANGE` credential-provider configuration.
- Attach the Cedar policy to the Gateway in **ENFORCE** mode. Confirm the three generated tool action names and ensure `execute_refund` is absent.
- Restrict the Harness execution role to invoking only the intended Gateway. Keep OAuth client secrets in the AWS-managed credential provider/secret path, never in repository files or parameters.
- Update the API stack with the actual Harness ARN and re-check the original customer token -> Harness -> Gateway -> OBO target token -> FastAPI identity chain.

### Stage 5 — unauthorized-action evidence demo

Use a staging account and synthetic orders first. The cleanest end-to-end evidence path is a valid, allowlisted `get_order` tool request for an order owned by a different customer. This is intentionally allowed through the Gateway tool surface so the application PolicyEngine can make and record the customer-ownership denial.

Expected result:

1. FastAPI returns `decision=DENY` and public reason `RESOURCE_NOT_AVAILABLE`; no order data is returned and no refund state changes. The restricted operator audit event retains `RESOURCE_OWNER_MISMATCH` as the internal reason.
2. The response's `trace_id` and `request_id` identify a `POLICY_DECISION` denial in the authenticated operator trace endpoint.
3. The independent audit verifier reads the matching AUDIT item from the DynamoDB GSI and reads the deterministic S3 object under `audit-events/YYYY/MM/DD/<event_id>.json` using its read-only role.
4. The verifier confirms the archived JSON bytes match the canonical source event projection and records object keys and SHA-256 hashes in a redacted evidence report. It must not mutate either store.
5. Repeat with an unregistered agent tool to demonstrate the application default-deny path. Do not use the outer Cedar denial as the only audited example because a Gateway-side rejection may never reach the application's audit store.

Only report the demonstration as passed after recording the actual HTTP response, correlated audit trace, archive object, and independent read-only comparison. Include tests for missing versus foreign order IDs to verify that customer-visible responses do not disclose resource existence. The current code has not demonstrated this in AWS.

## Cost surfaces

The templates intentionally create resources that can incur charges: DynamoDB on-demand reads/writes and PITR, S3 storage and retained Object Lock versions, Lambda invocations/compute/logging, SQS, CloudWatch alarms/log retention, API Gateway requests, Cognito feature-tier/token-exchange use, and AgentCore/Bedrock model execution. Costs depend on Region, request volume, retention, model, token use, and enabled features. No cost estimate is asserted here.

## Initial source-review verification and deployment record (historical)

During the initial source-review cycle:

- Offline YAML parse and in-template reference checks: passed for all three templates.
- SAM transform / `sam validate --lint`, SAM build/package, and runtime tests: not run in that review cycle.
- CloudFormation deployment/change sets: not run.
- Cognito, DynamoDB, S3, Lambda, API Gateway, AgentCore, and Gateway resources: not deployed or inspected.
- End-to-end unauthorized-action demonstration: not run.

Subsequent non-deploying infrastructure validation and local regression evidence are recorded in the sections below and in the per-cycle record.

**Approval gate:** the next AWS action that creates or modifies billable resources requires explicit owner approval. After approval, deploy in the staged order above; do not skip formal template validation or the staging evidence run.


## Current local release-candidate status

- Production-infrastructure review baseline: 6b26b6aaea1308706abb1ba3eac375251bd45d25.
- SH-SEC-001 remediation baseline: `main` at 18ab9165a3440205d5fdd2f4024a77ca6b66beb9.
- Architecture document: [architecture.md](architecture.md).
- Security findings and release-test matrix: [security-review-2026-11-21.md](security-review-2026-11-21.md).
- Initial security-review record: [2026-11-20-local-release-candidate-security-review.md](cycles/2026-11-20-local-release-candidate-security-review.md).
- SH-SEC-001 remediation record: [2026-11-20-security-remediation-sh-sec-001.md](cycles/2026-11-20-security-remediation-sh-sec-001.md).
- Selected Region: ap-southeast-2 (Sydney).
- SH-SEC-001 follow-up: 23 focused gateway/API/MCP tests passed; the broader suite passed 159 tests when the Lambda-entrypoint test was excluded because optional `mangum` is not installed. The unfiltered suite reported 159 passed and one environment failure.
- Compilation, repository metadata validation, focused Ruff checks, and `git diff --check`: passed for the SH-SEC-001 working tree.
- Browser/header checks, SAST/DAST, dependency scans, and deployed-service verification: not run.
- Four production templates passed standalone CloudFormation lint and SAM build/package; three passed `sam validate --lint`, and the new identity stack passed SAM basic validation (see offline implementation evidence below).
- Cognito/DynamoDB/S3/Lambda/API Gateway/AgentCore resources: not deployed or inspected.
- Deployment decision: **NO-GO**.

The next engineering slice is SH-SEC-002 (maker-checker separation of duties). Local verification authorization does not authorize AWS access or resource creation. Creating billable resources remains a separate approval gate.

## Production-only offline implementation update - 2026-11-20

The owner selected a production-only implementation and explicitly excluded AWS account access and cloud deployment. The following local work is complete; it does not change the overall release verdict above. SH-SEC-001 has since been remediated locally with HTTP/MCP regression coverage; six findings remain open, and no live AWS behavior is claimed.

- All four templates are production-only. The new infra/cognito/identity-stack.yaml defines the User Pool, V3 trigger, separate customer/operator/M2M clients, scopes, operator group, and hosted domain. The customer app client cannot write tenant/customer attributes; the schema attributes are immutable and intended for trusted administrative provisioning.
- infra/cognito/pre-token-generation.yaml remains an add-on for an existing production User Pool.
- Customer and operator app-client IDs must be distinct. The V3-only trigger fails closed for customer/delegated events missing trusted tenant/customer attributes, leaves M2M actor events unchanged, and passes operator-group events through without customer claims.
- The application requires the separate operator client ID and exact single delegated resource audience.
- infra/agentcore/cognito-obo-provider.example.json is a secret-free external Secrets Manager reference example. No credential values are included.
- Data-stack S3 policy Null key and retention settings are corrected; production deletion protection is always enabled.

### Local verification evidence

Environment: Windows working tree with WSL2 Ubuntu; Python 3.12.16; SAM CLI 1.174.0; standalone cfn-lint 1.61.0.

- Full Python suite: 158 passed.
- Focused identity/authentication/trigger suite: 35 passed.
- Bandit on src/shadow_hunter/auth.py and src/shadow_hunter/cognito_pretoken.py: 0 findings.
- Semgrep p/python: 151 rules across both changed authentication modules, 0 findings.
- Standalone cfn-lint 1.61.0: all four production templates passed.
- SAM validate --lint: existing-pool Cognito trigger, data, and API templates passed. SAM basic validation passed for the new Cognito identity template; the bundled SAM schema is older than the current standalone cfn-lint schema for ALLOW_TOKEN_EXCHANGE_DELEGATION.
- SAM build --no-use-container: all four templates passed.
- Repository validator, Python compilation, app dependency check, JSON parsing and git diff --check: passed.
- No AWS CLI/API calls, account lookup, credentials, live service tests, deployments, change sets, or billable resources were used.

The Cognito trusted-attribute write boundary still requires live account configuration evidence. Maker-checker, order-existence disclosure, approval-token recovery, anti-framing, upstream error reflection, and hosted-inference usage-budget findings also remain unresolved or require explicit risk acceptance. The release decision therefore remains NO-GO.
