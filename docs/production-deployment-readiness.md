# Production deployment readiness

- Review date: 2026-11-20
- Repository head reviewed: `0abe7f8b6eb1fbcfdd13961642a9ef4853e123bd`
- Status: **PRE-DEPLOYMENT REVIEW; NOT RELEASE-READY**
- Scope: SAM/CloudFormation review, stack dependencies, validation limits, approval-gated deployment preparation.
- AWS resources created or changed: **none**.

## Go / no-go

**NO-GO for production deployment at this point.** The templates are structurally coherent, but formal SAM/CloudFormation lint validation has not completed and the Cognito foundation is not fully represented as infrastructure-as-code.

The user-approved boundary for this cycle is template review and preparation only. Do not create stacks, user pools, app clients, buckets, tables, queues, Lambda functions, API Gateway APIs, AgentCore Harnesses, Gateways, credential providers, model invocations, or paid resources until the owner gives explicit AWS deployment approval.

## Template inventory and review

The repository intentionally uses three independently deployable SAM stacks rather than one all-in-one root stack. Their dependencies are passed as outputs and parameters.

| Template | Main resources | Dependency / interface |
|---|---|---|
| `infra/cognito/pre-token-generation.yaml` | Pre-token Lambda and Cognito invoke permission | Requires an already-existing User Pool ID; outputs the Lambda ARN. Pool trigger association is a separate step. |
| `infra/data/dynamodb.yaml` | DynamoDB table/GSI/stream, S3 Object Lock archive, exporter Lambda/role, SQS DLQ, CloudWatch alarm | Outputs table name/ARN, archive bucket name/ARN, and DLQ URL. |
| `infra/app/template.yaml` | FastAPI Lambda, API Gateway HTTP API, route JWT authorizers, logs and runtime IAM role | Requires data-stack outputs and exact Cognito issuer/client/scope/actor values. Harness ARN is optional during initial API deployment. |

### Package-path review

The template-relative code locations correspond to the checked-in handlers and dependency manifests:

- Cognito stack: `../../src/shadow_hunter/`, handler `cognito_pretoken.handler`, nested `src/shadow_hunter/requirements.txt`.
- Data stack: `../../src/shadow_hunter/`, handler `audit_exporter.handler`, nested `src/shadow_hunter/requirements.txt`.
- Application stack: `../../src/`, handler `shadow_hunter.lambda_handler.handler`, `src/requirements.txt`.

This was a source-tree review only; SAM packaging has not been built.

### Static structural validation

An offline YAML parser with CloudFormation intrinsic-tag handling parsed all three templates and checked their local `Ref` and `GetAtt` resource references:

| Template | YAML parse | Internal reference check |
|---|---:|---:|
| Cognito | Pass | Pass |
| Data | Pass | Pass |
| Application | Pass | Pass |

This is **not** formal CloudFormation schema validation. The current environment does not have SAM CLI or `cfn-lint`; the attempt to obtain the missing validator was blocked by unavailable network access. Consequently, the SAM transform, resource-property schemas, service-side constraints, and package resolution remain unverified.

When SAM CLI and cfn-lint are available, run these non-deploying validation commands from the repository root:

```powershell
sam validate --lint --template-file infra/cognito/pre-token-generation.yaml
sam validate --lint --template-file infra/data/dynamodb.yaml
sam validate --lint --template-file infra/app/template.yaml
```

Do not treat a successful YAML parse or local reference check as a substitute for these commands. A separate SAM build/package review is also still required before deployment and should be performed only within the separately approved validation scope.

## Findings that must be closed

### 1. Cognito is only partially provisioned

The current Cognito SAM template creates the pre-token-generation Lambda and a resource-based permission scoped to an existing User Pool. It does **not** create or configure:

- the User Pool and its `custom:tenant_id` / `custom:customer_id` attributes;
- customer, operator, and agent/M2M app clients;
- the resource server, audience, scopes, operator group, or hosted sign-in domain;
- OAuth token-exchange/delegation settings or the AgentCore Identity credential provider;
- the User Pool's `LambdaConfig.PreTokenGenerationConfig` association.

The Cognito README currently describes the trigger association as a manual console step. This must be completed deliberately or replaced with an approved User Pool template before Cognito can be called fully reproducible from infrastructure-as-code.

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

- Obtain explicit owner approval for the target AWS account, Region, deployment environment, and billable resource creation.
- Confirm account-level budgets/alerts and service quotas.
- Confirm the approved Cognito feature tier, Bedrock model access/Region, AgentCore availability, and token-exchange feature enablement.
- Review retention requirements before selecting an Object Lock duration or mode. The template defaults to Governance mode for 365 days. Do not select Compliance mode without legal approval.
- Confirm the self-service refund limit in currency minor units and the approval TTL; do not choose business thresholds by guesswork.

### Stage 1 — Cognito

- Decide whether to use an existing pool or add a separately reviewed User Pool stack.
- Ensure the pool has trusted tenant/customer attributes and a controlled provisioning process.
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
- Create the Gateway with JWT inbound authentication; add the OpenAPI target using the deployed API base URL and OBO `TOKEN_EXCHANGE` credential-provider configuration.
- Attach the Cedar policy to the Gateway in **ENFORCE** mode. Confirm the three generated tool action names and ensure `execute_refund` is absent.
- Restrict the Harness execution role to invoking only the intended Gateway. Keep OAuth client secrets in the AWS-managed credential provider/secret path, never in repository files or parameters.
- Update the API stack with the actual Harness ARN and re-check the original customer token -> Harness -> Gateway -> OBO target token -> FastAPI identity chain.

### Stage 5 — unauthorized-action evidence demo

Use a staging account and synthetic orders first. The cleanest end-to-end evidence path is a valid, allowlisted `get_order` tool request for an order owned by a different customer. This is intentionally allowed through the Gateway tool surface so the application PolicyEngine can make and record the customer-ownership denial.

Expected result:

1. FastAPI returns `decision=DENY` and reason `RESOURCE_OWNER_MISMATCH`; no order data is returned and no refund state changes.
2. The response's `trace_id` and `request_id` identify a `POLICY_DECISION` denial in the authenticated operator trace endpoint.
3. The independent audit verifier reads the matching AUDIT item from the DynamoDB GSI and reads the deterministic S3 object under `audit-events/YYYY/MM/DD/<event_id>.json` using its read-only role.
4. The verifier confirms the archived JSON bytes match the canonical source event projection and records object keys and SHA-256 hashes in a redacted evidence report. It must not mutate either store.
5. Repeat with an unregistered agent tool to demonstrate the application default-deny path. Do not use the outer Cedar denial as the only audited example because a Gateway-side rejection may never reach the application's audit store.

Only report the demonstration as passed after recording the actual HTTP response, correlated audit trace, archive object, and independent read-only comparison. The current code has not demonstrated this in AWS.

## Cost surfaces

The templates intentionally create resources that can incur charges: DynamoDB on-demand reads/writes and PITR, S3 storage and retained Object Lock versions, Lambda invocations/compute/logging, SQS, CloudWatch alarms/log retention, API Gateway requests, Cognito feature-tier/token-exchange use, and AgentCore/Bedrock model execution. Costs depend on Region, request volume, retention, model, token use, and enabled features. No cost estimate is asserted here.

## Verification and deployment record

- Offline YAML parse and in-template reference checks: passed for all three templates.
- SAM transform / `sam validate --lint`: not completed; SAM CLI and cfn-lint were unavailable in the current environment.
- SAM build/package: not run.
- Unit/integration/adversarial tests: not run under the repository operating contract.
- CloudFormation deployment/change sets: not run.
- Cognito, DynamoDB, S3, Lambda, API Gateway, AgentCore, and Gateway resources: not deployed or inspected.
- End-to-end unauthorized-action demonstration: not run.

**Approval gate:** the next AWS action that creates or modifies billable resources requires explicit owner approval. After approval, deploy in the staged order above; do not skip formal template validation or the staging evidence run.
