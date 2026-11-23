# Staging MFA and security rerun — 23 November 2026

This record supplements the [first live AWS security inspection](2026-11-23-live-aws-security-verification.md). Scope is owner-authorized staging in AWS `ap-southeast-2`. All test identities were synthetic, and no production resources or actual payment operations were used.

## Verified live outcomes

- AWS STS authentication succeeded with an assumed role; the existing identity stack was `UPDATE_COMPLETE`.
- Read-only Cognito configuration inspection passed, including mandatory software TOTP, client scopes/delegation configuration, and V3 pre-token Lambda.
- Installed optional `pycognito` on the authorized test computer and ran `scripts/smoke_cognito_identity.py --mfa`.
- **Real Cognito MFA PASS:** For both synthetic operator and synthetic customer, actual SRP sign-in required software-token enrollment, verified TOTP, then a second sign-in required a new TOTP challenge before access-token issuance. Cryptographic application operator-token verification passed; a read-only authenticated operator API request returned **HTTP 200**.
- The smoke runner deleted its disposable users in `finally`, and a separate Cognito `ListUsers` call afterward reported **0 users**.
- **Real application authorization smoke PASS:** `scripts/smoke_agentcore_staging.py --boundary-only`: health 200, public operator config 200, anonymous chat 401, anonymous delegated tool 401, anonymous operator overview 401, fabricated delegated token 401 (6/6 checks).
- **Full read-only audit gate PASS again:** 3 DynamoDB AUDIT records, 3 corresponding S3 archive objects, all 3 canonical bytes verified, no missing/orphaned/mismatched archive objects.
- **Local regression:** full isolated worktree suite **250 passed in 39.02s** on checked-out main `d665111` plus the local MFA-decoder patch; focused Cognito tests **13 passed**. The patch and test were subsequently committed to `main` in commits `175f3f2` and `99740c9`.

## MFA smoke runner issue fixed

The first `--mfa` execution failed inside `base64.b32decode` while calculating a TOTP value; Cognito had returned a valid Base32 secret without padding. The runner now normalizes and pads the secret to a multiple of 8 characters before decoding. This was a **test runner defect**, not an authentication bypass. A regression test covers an unpadded Base32 secret; the rerun completed successfully. No test credentials, tokens, TOTP seeds, or sensitive audit contents were committed.

## Still not verified

- **Two-tenant authenticated staging tests:** The passing local cross-tenant matrix and live anonymous boundary checks do not replace genuine separate scoped customer sessions and delegated tool tokens. Do not claim live cross-tenant sign-off.
- **Customer OAuth OBO exchange:** `--obo` was not run; it requires a real synthetic customer OAuth authorization-code/PKCE access token with the required customer/refunds resource scopes. SRP JWTs issued for MFA smoke have no equivalent OAuth resource scopes. Do not fabricate a subject JWT or bypass the scope contract.
- **AgentCore authenticated Harness/Gateway:** The staging health response returned `agentcore_configured=false` and `demo_mode=false`; managed end-to-end flow cannot be declared operational from these checks. No hosted-model inference was invoked.
- **Comprehensive penetration test:** Only bounded non-destructive denial-path checks and local regression tests were executed. An independent, authorized, scoped penetration engagement with documented methodology and findings is still needed for release assurance.
- **Archive limitations:** 3/3 content equivalence is point-in-time and cannot show that source events were never omitted or that both source/archive cannot be jointly modified. Staging Object Lock uses one-day Governance retention, not production Compliance policy.

**Release decision: NO-GO for production** until the remaining authenticated OBO, real two-tenant access isolation, AgentCore operational, and independent penetration-test gates have explicit pass evidence. No deployment, payments or production changes were made.
