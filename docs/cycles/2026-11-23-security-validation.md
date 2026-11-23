# Security boundary and audit-integrity verification — 23 November 2026

## Scope and authorization

Target: Shadow Hunter's own source and synthetic/local test environments.
No production customer data, credential guessing, third-party systems,
destructive cloud operation, or live load testing is in scope. The deployed
AWS staging API is `ap-southeast-2`; do not send authenticated or mutating
requests there without separate test-user provisioning and review.

This is an **engineering security validation**, not an independently
conducted penetration test, an OWASP ASVS certification, or release approval.

## Reproducible tests

From a Python 3.11+ environment with `pip install -e ".[server,aws,dev]"`:

```shell
python -m pytest -q tests/test_security_boundary_matrix.py tests/test_security_audit_gate.py
python -m pytest -q
python scripts/validate-repo.py
git diff --check
```

`test_security_boundary_matrix.py` checks:
- Three agent tools × two distinct tenant principals and same-tenant
  different-customer ownership, for **SQLite and Moto DynamoDB**.
- Denial of unauthorized reads **and writes**, no refund side effects,
  identical public payloads for missing vs foreign resources, with
  distinct internal audit reasons.
- Independent tenant-scoped idempotency keys and rejection of injected
  tenant/customer identity fields.
- TestClient HTTP boundary: missing/invalid/operator tokens on a
  customer tool, role confusion on operator APIs, spoofed body claims,
  unknown/SQL-like/path-like identifiers and denial without disclosure.

`test_security_audit_gate.py` uses isolated Moto DynamoDB/S3 fixtures to
cover: clean complete archive with pagination; altered bytes; missing archive
object; orphaned archive object; duplicate event IDs. Any integrity
counterexample must make the combined gate fail.

**Verification state at authoring:** source/tests are committed on a review
branch; the connected local machine stopped responding during the full-suite
baseline run. No test result is claimed until an actual completed run is
recorded with a commit SHA and environment.

## Full archive integrity check (read-only)

The previous byte verifier validates only DynamoDB-to-S3 content for
existing source rows; the separate reconciler finds missing and orphaned
objects. `scripts/security_audit_gate.py` combines both and fails unless
**both** results are clean.

With an authorized, read-only audit-verification AWS profile:

```shell
python scripts/security_audit_gate.py \
  --table-name shadow-hunter-staging \
  --bucket YOUR_STAGING_AUDIT_BUCKET \
  --region ap-southeast-2 \
  --report-file security-audit-report.json
```

Use the bucket name from the `shadow-hunter-data-staging` stack outputs.
The JSON report provides counts, sample object keys and SHA-256 comparisons,
not full event payloads. Do **not** commit generated reports that may
include business trace IDs. A failure is a release stop pending investigation;
allow for stream/GSI eventual consistency when interpreting recent records.

**Verification boundary:** Source-to-archive equality cannot prove that
both data sources were never altered together or that source events were
never omitted. Inspect Object Lock, bucket versioning, IAM privilege
separation, retention and exporter DLQ/CloudWatch separately. S3 Governance
mode allows an authorized bypass; it is not equivalent to Compliance mode
or independently signed event-chain attestations.

## Staging negative-test checklist (not yet proven)

1. Provision two non-production customers in distinct tenants and a
   separate operator through reviewed admin-only provisioning.
2. Obtain genuine customer, operator and delegated OBO access tokens
   from the deployed Cognito stack; validate MFA and verified actor claims.
3. Execute only approved synthetic customer tool reads and writes. Verify
   tenant and customer isolation, identical missing/foreign outward
   responses, no unauthorized DynamoDB state change, and correlated audit
   records in the archive.
4. Send a bounded, rate-limited negative API set (missing/expired/wrong
   audience JWT, wrong client, wrong scope, extra identity fields,
   unauthorized operator action). Preserve API Gateway/Lambda logs and
   redact credentials from reports.
5. Run the read-only full audit gate after exporter catch-up and confirm
   both missing/orphan counts and byte mismatches remain zero.
6. Independently inspect Object Lock default retention, bucket versioning,
   IAM and bypass permissions. Track issues before considering release.

No staging penetration test or full live audit reconciliation is claimed
until that evidence is attached. The existing synthetic staging smoke test
does not substitute for two-tenant authenticated identity testing.
