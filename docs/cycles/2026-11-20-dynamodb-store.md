# Engineering cycle — DynamoDB transactional persistence adapter

- Date: 2026-11-20
- Scope: AWS transactional store preserving the SQLiteStore interface
- Status: Authored and committed; untested and not deployed

## Changes

- Added a single-table DynamoDB adapter implementing the existing store contract.
- Added transactional tenant-scoped idempotency claims and refund request creation.
- Added transactional approval creation with a direct refund-to-approval pointer.
- Added conditional approval, rejection, expiry, and refund execution transitions.
- Refund execution atomically updates the order balance, refund status, approval capability state, audit event, and operator counters.
- Added trace-partitioned audit events and a GSI1 for recent audit events and approval listings.
- Public data projections omit capability token hashes.
- Added API backend selection with SQLite as the default and an explicit DynamoDB option.
- Added a CloudFormation table template with on-demand billing, AWS-managed KMS encryption, GSI1, 35-day PITR, production deletion protection, and Retain policies.
- Added a least-privilege IAM policy example and deployment documentation.
- Authored tests for missing DynamoDB table configuration and token-hash projection redaction.

## Design limitations

- Dashboard counters are stored in one stats item and can become a write hot key at higher throughput. Shard or asynchronously aggregate them before scaling.
- Audit events are append-oriented but not WORM/tamper-evident; a separately protected retention/export sink remains necessary.
- The adapter updates a DynamoDB demo ledger only. No payment provider is called.
- No AWS table was created.

## Verification

No tests, build, lint, format, CloudFormation validation, or deployment were executed. The repository operating contract requires this change to be reported as untested.

## Next task

Add the production API deployment package and IAM wiring, then validate the adapter against DynamoDB Local or an approved AWS test environment before routing production traffic to it.
