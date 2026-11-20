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

## Provisioning

Review the template and estimated on-demand usage/cost before deploying:

    aws cloudformation deploy --template-file infra/data/dynamodb.yaml --stack-name shadow-hunter-data --parameter-overrides Environment=production --region <approved-region>

The table is on-demand, encrypted with the AWS-managed DynamoDB KMS key,
configured with 35-day point-in-time recovery, deletion protection in
production, and Retain policies for stack deletion/replacement.

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
- DynamoDB audit items are append-oriented, not WORM or independently
  tamper-evident. A separate protected retention/export sink remains required.
- The production table is not provisioned by this repository change.
