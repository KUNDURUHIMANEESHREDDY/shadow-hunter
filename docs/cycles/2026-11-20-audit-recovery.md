# Engineering cycle — audit archive reconciliation and DLQ replay

- Date: 2026-11-20
- Scope: Operator recovery procedures for the S3 Object Lock audit archive
- Status: Authored and committed; untested and undeployed

## Changes

- Added a read-only audit reconciliation CLI that queries event_id/created_at from the AUDIT GSI and compares deterministic expected object keys with S3 JSON keys.
- The report includes mismatch counts and bounded key samples only; it does not read archived object bodies.
- Added a dry-run-first SQS DLQ replay CLI.
- The replay parser consumes the documented DynamoDB event-source mapping failure envelope and extracts the stream ARN, shard ID, and inclusive sequence range.
- The replay tool fetches that range from DynamoDB Streams, invokes the same allowlisted/redacting conditional S3 exporter, and deletes the DLQ message only after every record is handled successfully.
- Existing S3 objects are idempotent because the exporter uses If-None-Match; 412 is accepted, while write errors retain the DLQ message.
- Added unit tests for key-set comparison, failure envelope parsing, sequence range selection, and unavailable-boundary handling.
- Added a narrowly-scoped recovery IAM policy example and documented reconciliation, dry-run, apply, and retention limits.
- Added console entrypoints for both tools.

## Important recovery constraint

AWS sends only invocation metadata and the failed batch range to an SQS on-failure destination. It does not include the original DynamoDB Stream payload. Replay retrieves original records by sequence range from DynamoDB Streams. Streams retain records for 24 hours; a 14-day SQS DLQ retention does not extend that source-record window. Expired ranges cannot be replayed from the DLQ alone.

## Verification

No tests, package build, lint, formatting, SAM/CloudFormation validation, or AWS deployment were run, consistent with docs/engineering-cycle.md. No archive or queue was read or modified in AWS.

## Next task

Review the replay/reconciliation tools and recovery role in a non-production environment with explicit owner approval, then assess CloudFormation/SAM packaging and end-to-end stream failure/replay behavior before production deployment.
