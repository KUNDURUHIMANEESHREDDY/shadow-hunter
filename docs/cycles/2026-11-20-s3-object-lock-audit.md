# Engineering cycle — S3 Object Lock audit retention

- Date: 2026-11-20
- Scope: Separate immutable-retention export path for DynamoDB audit events
- Status: Authored and committed; untested and not deployed

## Changes

- Enabled a NEW_IMAGE DynamoDB Stream on the current TTL-enabled application table.
- Added a dedicated exporter Lambda that processes only INSERT records with entity_type=AUDIT.
- The exporter allowlists audit fields, recursively redacts token/secret/credential-like keys, and omits DynamoDB keys and internal attributes.
- Added deterministic S3 object keys partitioned by UTC date and event ID.
- Added conditional PutObject with If-None-Match=*. Existing-object 412 responses are accepted as idempotent replay; 409 conditional-write conflicts are retried.
- Added an S3 bucket policy that denies audit-prefix PutObject requests without If-None-Match.
- Added partial-batch failure reporting for DynamoDB Streams.
- Added an encrypted, retained SQS dead-letter queue and CloudWatch alarm for failed batches.
- Added an S3 archive bucket with versioning, Object Lock default retention, SSE-S3, public-access blocking, bucket-owner-enforced ownership, TLS-only bucket policy, and Retain policies.
- Added configurable retention duration (default 365 days) and mode (default GOVERNANCE; COMPLIANCE is an explicit legal/compliance decision).
- Added a separate least-privilege exporter role. It has stream-read, DLQ-send, log-write, and prefix-only S3 PutObject permissions. It cannot read/list/delete archive objects or bypass/change Object Lock.
- Kept the API runtime role unchanged and table/GSI-only; it receives no S3 permissions.
- Preserved the existing DynamoDB TTL for expired Red/Blue replay nonces.
- Updated DynamoDB deployment instructions to use SAM packaging and authored archive tests.

## Limitations and recovery

- DynamoDB Streams retains records for 24 hours. The mapping retries records up to 10 times, then sends failed batches to a 14-day SQS DLQ. DLQ monitoring and timely redrive/reconciliation are operational requirements.
- The stream does not backfill audit rows created before it is enabled.
- Governance-mode retention can be bypassed by a separately authorized principal; the exporter role is not granted that permission. Compliance mode is irreversible for the active retention period and must not be selected without legal confirmation.
- DynamoDB audit rows and S3 Object Lock are not a substitute for monitoring, reconciliation, or a separately controlled archive-reader role.
- No AWS resources were created or deployed.

## Verification

No tests, build, SAM/CloudFormation validation, lint, formatting, or security scans were executed, consistent with docs/engineering-cycle.md.

## Next task

Add archive reconciliation/redrive procedures and evaluate the exact CloudFormation/SAM deployment behavior in an explicitly approved non-production AWS account before production use.
