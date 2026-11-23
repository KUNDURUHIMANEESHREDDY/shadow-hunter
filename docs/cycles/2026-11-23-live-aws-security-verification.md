# Live AWS staging security verification — 23 November 2026

**Scope:** Owner-authorized Shadow Hunter staging resources in `ap-southeast-2`.
No production resources, payment processor, customer data, AWS deployment,
credential material, or user-pool modifications were involved.

## Confirmed live evidence

| Control | Evidence | Result |
|---|---|---|
| AWS sign-in | STS `GetCallerIdentity` succeeded following owner reauthentication | PASS |
| Staging data stack | CloudFormation `shadow-hunter-data-staging`: `CREATE_COMPLETE` | PASS |
| Audit-key completeness | DynamoDB AUDIT GSI: 3 rows; S3 archive: 3 JSON objects; missing 0, orphan 0, duplicate 0 | PASS |
| Audit-byte integrity | `scripts/security_audit_gate.py` compared all 3 canonical DynamoDB projections against actual S3 object bytes; 3 verified; 0 mismatches, 0 missing/read errors/invalid records | PASS |
| S3 object retention | Object Lock enabled, default **GOVERNANCE**, **1 day** (staging value) | PASS for staging configuration |
| S3 access settings | Bucket versioning enabled; BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets all true | PASS |
| Cognito MFA | `GetUserPoolMfaConfig`: `MfaConfiguration=ON`, `SoftwareTokenMfaConfiguration.Enabled=true` | PASS |
| Cognito pool and client settings | Revised `smoke_cognito_identity.py` completed default read-only inspection; V3 pre-token trigger, deletion protection, public customer/operator auth flows, trusted attribute write restrictions and agent client delegation contract | PASS |
| Local Cognito smoke contract | `python -m pytest -q tests/test_smoke_cognito_identity.py`: **14 passed in 0.71s** | PASS |

The first live identity check incorrectly failed because `DescribeUserPool`
omitted `EnabledMfas` even though the dedicated
`GetUserPoolMfaConfig` API confirms enabled software-token MFA. The smoke
runner and mocks were updated to read the authoritative MFA configuration.
The corrected **read-only live inspection passed**.

Before any disposable accounts were provisioned, the staging pool contained
**0 users**.

## Boundaries and remaining release blockers

1. **Actual MFA sign-in:** `--mfa` was **not executed**. The optional
   `pycognito` dependency was not installed in the connected environment.
   The attempt to install/run the test could not begin because the remote
   desktop tool reached its monthly usage limit. No synthetic test accounts
   were created, and there are no such accounts to clean up from this cycle.
2. **Cross-tenant live authorization:** No real customer or delegated OBO
   JWTs were issued for two separate synthetic tenants. Existing SQLite/Moto
   regression tests do not substitute for authenticated staging proof.
3. **AgentCore:** Staging Harness/Gateway has not been shown to perform
   authenticated end-to-end tool execution; no hosted-model operation was
   attempted in this cycle.
4. **Penetration testing:** The authorized bounded API negative checks
   performed in the previous cycle (unauthenticated protected routes 401)
   are not a comprehensive live penetration test.
5. **Archive assurance:** Exact 3/3 byte matches and full key reconciliation
   are point-in-time checks. They cannot rule out coordinated tampering of
   both sources, missing source events, or future stream lag. Governance
   retention can be bypassed by an authorized role; it is not Compliance.
6. **Production:** No production deployment or security release sign-off
   is authorized or claimed.

## Reproduce remaining authorized staging checks

In an environment with refreshed AWS authentication, reviewed synthetic
test-user permissions and the project dependencies:

```powershell
python -m pip install -e ".[aws,server,dev]"
python -m pip install pycognito
$env:PYTHONPATH = "src"
python scripts/smoke_cognito_identity.py
python scripts/smoke_cognito_identity.py --mfa
```

The `--mfa` runner creates/deletes disposable staging test users and
requires administrative Cognito permission. Confirm the pool has no leftover
`sh-smoke-` users if the process is interrupted. A later `--obo` test
requires a real OAuth authorization-code/PKCE customer token with the
required scopes; do not paste JWTs or secrets into logs or GitHub.

For another read-only full archive check:

```powershell
$env:PYTHONPATH = "src"
python scripts/security_audit_gate.py --table-name shadow-hunter-staging --bucket <STAGING_ARCHIVE_BUCKET_FROM_CLOUDFORMATION> --region ap-southeast-2
```

**Release recommendation:** security status remains **NO-GO** for
production until real MFA/OBO cross-tenant authorization and the bounded
authenticated staging test plan have verified outcomes.
