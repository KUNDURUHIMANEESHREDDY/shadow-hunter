# DynamoDB persistence for Shadow Hunter

This package provisions the production persistence table. It does not deploy
the FastAPI service, Cognito, AgentCore, or the application Lambda/API.

## Table layout

The adapter uses one DynamoDB table with a composite primary key:

| Entity | PK | SK |
|---|---|---|
| Order | ORDER#<order_id> | META |
| Refund request | REFUND#<refund_id> | META |
| Approval | APPROVAL#<approval_id> | META |
| Refund-to-approval pointer | REFUND#<refund_id> | APPROVAL |
| Idempotency claim | IDEMP#<tenant_id> | KEY#<sha256(key)> |
| Trace audit event | TRACE#<trace_id> | EVENT#<timestamp>#<event_id> |
| A2A replay nonce | A2A_NONCE#<nonce> | META |
| Counters | STATS | COUNTERS |

GSI1 serves two operator-console views:
- GSI1PK=AUDIT, ordered by event timestamp and event ID.
- GSI1PK=APPROVALS, ordered by approval creation time and approval ID.

The full item projection allows the console to read event and approval
summaries without a join. Capability token hashes are removed from all
public store projections.

## Transaction boundaries

- Refund request creation atomically writes a tenant-scoped idempotency claim,
  refund item, and request counter.
- Approval creation atomically writes the approval, refund pointer, audit
  event, and counters.
- Approval/rejection atomically transitions the approval and related refund
  state with an audit event and counter changes.
- Approved execution atomically decrements the order's remaining refundable
  balance, marks the refund executed, consumes the one-time approval token,
  appends an audit event, and updates counters.
- Conditional state transitions prevent concurrent executions from both
  consuming the same approval or decrementing the order balance twice.

DynamoDB TransactWriteItems provides all-or-nothing transactions. This
adapter targets a single Region; DynamoDB transactions do not provide
cross-Region atomicity. See AWS's transaction documentation:
https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html

The single STATS/COUNTERS item is appropriate for the current low-volume
operator dashboard. It can become a write hot key at higher throughput; shard
or asynchronously aggregate these counters before scaling the workload.

## Protected audit retention

The table enables a DynamoDB Stream with NEW_IMAGE. A separate
ShadowHunterAuditExporter Lambda subscribes to the stream and exports only
new items whose entity_type is AUDIT. It projects an allowlisted set of audit
fields, recursively redacts token/secret/credential-like keys, and writes
one JSON object per event under:

    s3://<AuditArchiveBucketName>/audit-events/YYYY/MM/DD/<event_id>.json

The object key is deterministic. The exporter uses PutObject with
If-None-Match: *, so a retry that sees an existing object is treated as a
successful idempotent replay (HTTP 412). A 409 conditional-write conflict is
retried by the stream event-source mapping. The bucket policy independently
denies PutObject calls that omit If-None-Match, preventing non-conditional
writes from creating replacement object versions. Individual failed records
are reported with ReportBatchItemFailures; exhausted batches are sent to the
encrypted SQS dead-letter queue and trigger a CloudWatch alarm.

The archive bucket has versioning, S3 Object Lock default retention, SSE-S3
encryption, bucket-owner-enforced ownership, public-access blocking, and a
bucket policy denying non-TLS requests. Retention is configurable through
AuditRetentionDays (default 365). AuditRetentionMode defaults to GOVERNANCE.
Governance mode can be bypassed only by a principal explicitly granted that
permission; the exporter has no such permission. Select COMPLIANCE only after
the legal retention period and regulatory requirements are confirmed; active
compliance retention cannot be shortened or bypassed.

The exporter has a separate IAM role. It can read only the DynamoDB stream,
send failed batches to the SQS DLQ, write to the audit-events prefix, and
write its own CloudWatch logs. It cannot read/list/delete S3 objects, change
Object Lock retention, bypass Governance mode, or read application table
items through DynamoDB GetItem. The application Lambda role is unchanged and
receives no S3 permissions.

### Delivery and recovery limits

DynamoDB Streams retains records for 24 hours. The mapping retries each
record up to 10 times and configures an on-failure SQS destination. The SQS
queue is retained for 14 days and managed-encrypted. Operators must alert on
the DLQ alarm and reconcile/redrive failed batches before stream retention or
DLQ retention expires. This path does not backfill audit records written
before the Stream is enabled. Enable the Stream and verify the exporter before
routing business writes to this table.

DynamoDB Streams plus S3 Object Lock is protected retention, not a claim that
all audit evidence is automatically complete. Monitor the DLQ and exporter
errors, periodically reconcile DynamoDB audit counts against the S3 archive,
and record manual recovery. A separate account/role should own archive read
access and retention changes.

## Provisioning

Review the template and estimated on-demand usage/cost before deploying:

    sam build --template-file infra/data/dynamodb.yaml --use-container

    sam deploy --guided --template-file .aws-sam/build/template.yaml

Select Environment=production, an approved AuditRetentionDays value, and AuditRetentionMode=GOVERNANCE (or COMPLIANCE only after legal review). Because the stack creates an IAM role, approve CAPABILITY_IAM.

The table is on-demand, encrypted with the AWS-managed DynamoDB KMS key,
configured with a NEW_IMAGE stream, 35-day point-in-time recovery and TTL
cleanup for expired A2A nonce claims, deletion protection in production, and
Retain policies for stack deletion/replacement.

After deployment, configure:
- SHADOW_HUNTER_STORE_BACKEND=dynamodb
- SHADOW_HUNTER_DYNAMODB_TABLE=<TableName output>
- AWS_REGION=<deployed region>

For local demos, leave the backend as sqlite. An optional
SHADOW_HUNTER_DYNAMODB_ENDPOINT supports DynamoDB Local or a local test
service.

## Application IAM permissions

The runtime role needs only these data actions on the table ARN and its
GSI1 index ARN:
- dynamodb:GetItem
- dynamodb:PutItem
- dynamodb:UpdateItem
- dynamodb:Query
- dynamodb:TransactWriteItems

Do not grant Scan, DeleteItem, table administration, or access to other
tables for the application runtime. The schema is single-table and all store
operations use point reads, indexed queries, puts, updates, and transactions.

## Boundaries

- The adapter is implemented but untested and not deployed.
- It updates an AWS-hosted demo refund ledger. It does not call a payment
  processor, bank, or external refund API.
- DynamoDB audit rows remain append-oriented; the separate S3 Object Lock archive
  is a retention copy, with configurable Governance/Compliance behavior.
- The stream/exporter/archive stack is authored but untested and undeployed.
- Historical DynamoDB rows created before stream enablement are not backfilled.
- The production table and archive are not provisioned by this repository change.
