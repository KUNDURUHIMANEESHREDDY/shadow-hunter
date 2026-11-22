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

## Reconciliation and DLQ recovery

The repository includes two operator-run commands. Both require a read-only
inspection role for reconciliation. Replay additionally requires the
narrowly-scoped SQS, DynamoDB Streams, and conditional S3 write permissions
in audit-recovery-policy.example.json.

### Compare DynamoDB audit identities with S3 archive keys

Install the AWS extra and run:

    python -m shadow_hunter.audit_reconcile --table-name shadow-hunter-production --bucket <archive-bucket> --prefix audit-events --region <region> --report-file audit-reconciliation.json

The command queries only event_id and created_at from GSI1's AUDIT partition
and lists JSON object keys under the configured S3 prefix. It does not read
archive object bodies. The report contains counts and bounded key samples,
not audit payloads. It detects missing archive keys, unexpected JSON keys,
invalid DynamoDB audit identities, and duplicate event IDs.

GSI1 is eventually consistent. Wait for the stream exporter to catch up, run
the reconciliation command, and repeat it before treating a mismatch as
permanent. This is key-level reconciliation, not a content hash or a proof
that an existing archive object's body is correct.

### Inspect and replay failed batches

The SQS on-failure destination for a DynamoDB Streams event source mapping
contains invocation metadata and the failed shard/sequence range; unlike an
S3 on-failure destination, it does not include the original stream event
payload. The replay command uses that metadata to fetch the original records
from DynamoDB Streams, while they remain inside the stream's 24-hour retention
window.

First inspect a bounded number of messages without writing or deleting:

    python -m shadow_hunter.audit_replay --queue-url <dlq-url> --bucket <archive-bucket> --prefix audit-events --region <region> --max-messages 5

The dry run temporarily receives messages, validates their sequence ranges,
fetches the records, then makes the messages visible again. It does not write
to S3 and does not delete DLQ messages.

After reviewing the output and obtaining the required operational approval,
replay explicitly:

    python -m shadow_hunter.audit_replay --queue-url <dlq-url> --bucket <archive-bucket> --prefix audit-events --region <region> --max-messages 5 --apply

The replay command uses the same conditional If-None-Match write as the stream
exporter. Existing objects are treated as successful idempotent replays. A DLQ
message is deleted only after every record in its original range has been
processed successfully. If any record is unavailable or any write fails,
the message remains in the queue for investigation/retry.

DynamoDB Streams records expire after 24 hours. A DLQ message retained for
14 days does not preserve the original records: once the stream range has
expired, this command cannot reconstruct it. Such gaps require a separate
recovery source (for example, a verified backup or an upstream audit copy);
do not claim that DLQ retention alone guarantees recovery.

### Recovery IAM boundary

The example policy grants:
- Query on only the table's GSI1 AUDIT index.
- DescribeStream, GetShardIterator, and GetRecords on the selected table stream.
- ListBucket only for the audit-events prefix.
- PutObject only under audit-events/.
- ReceiveMessage, DeleteMessage, ChangeMessageVisibility, and GetQueueAttributes
  only on the audit-export DLQ.

It does not grant S3 GetObject, DeleteObject, retention changes, DynamoDB
Scan, table administration, or application write access. Keep this recovery
identity separate from the exporter role and the application runtime role.

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
service. For isolated integration tests with no AWS account access, install
`python -m pip install -e ".[aws,dev]"` and run
`python -m pytest -q tests/test_dynamodb_integration.py`.
Moto intercepts AWS calls and creates an ephemeral in-memory table with PK/SK
and GSI1. It exercises the real Boto3 low-level transaction client without
deploying any cloud resources or contacting AWS.

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

- The adapter has Moto offline transaction-level integration coverage (`tests/test_dynamodb_integration.py`) and a **live, synthetic staging** AWS transaction smoke test (`scripts/smoke_aws_data.py`). Staging verified approval, demo refund execution and idempotent replay. Production use and real payment processing remain unverified.
- It updates an AWS-hosted demo refund ledger. It does not call a payment
  processor, bank, or external refund API.
- DynamoDB audit rows remain append-oriented; the separate S3 Object Lock archive
  is a retention copy, with configurable Governance/Compliance behavior.
- The stream/exporter/archive stack has been deployed in **staging**, with three correlated audit events exported to S3 and verified by object existence. Full reconciliation, independent archive content verification and production deployment remain pending.
- Historical DynamoDB rows created before stream enablement are not backfilled.
- The production table and archive are **not** provisioned. See `docs/cycles/2026-11-22-aws-staging-deployment.md` for staging stack names, live test evidence, cost caveats and release gates.



## Independent read-only archive verification

The key-reconciliation command above checks missing/orphan object keys but does
not read object bodies. The separate `shadow-hunter-audit-verify` command
checks content by querying source audit rows through GSI1 and fetching the
corresponding S3 object bodies. It compares exact canonical allowlisted and
redacted JSON bytes, and reports only object keys, event/trace IDs, SHA-256
hashes, and mismatch status.

Run it with the dedicated auditor role:

    shadow-hunter-audit-verify --table-name shadow-hunter-production --bucket <archive-bucket> --prefix audit-events --region <region> --trace-id <trace-id> --report-file audit-verification.json

Omit `--trace-id` to verify every visible audit row. The role requires only
`dynamodb:Query` on the table ARN and AUDIT GSI ARN plus `s3:GetObject` on
`audit-events/*`. With `--trace-id`, it queries only the base-table
`TRACE#<trace-id>` partition; a full verification queries the AUDIT GSI, as shown in `audit-verification-policy.example.json`.
It does not enumerate S3 keys or detect orphan objects; run
`shadow-hunter-audit-reconcile` separately for missing/orphan key comparison.
Because GSI1 is eventually consistent, run after the exporter catches up and
repeat if the requested trace is not visible. The content verifier is authored
but has not been run against AWS.
