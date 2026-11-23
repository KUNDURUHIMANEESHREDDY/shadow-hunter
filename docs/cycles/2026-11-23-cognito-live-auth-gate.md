# Staging Cognito live-auth verification gate — 23 November 2026

## Live staging follow-up (23 November 2026)

- The AWS CLI session was successfully reauthenticated and verified using the real STS GetCallerIdentity API (staging role `AccountFullAccessRole`).
- Cognito `DescribeUserPool` and `GetUserPoolMfaConfig` confirm `MfaConfiguration=ON`, software-token MFA enabled, Cognito Essentials, and V3_0 pre-token Lambda.
- The original read-only smoke runner used a nonexistent `DescribeUserPool.EnabledMfas` field; corrected it to use `GetUserPoolMfaConfig.SoftwareTokenMfaConfiguration.Enabled`. The corrected read-only staging inspection passed for the pool, clients, and delegation configuration; the updated 12 targeted offline tests passed.
- A subsequent `--mfa` live SRP attempt was **not successful**. The runner reported an unexpected `Error`; it did not establish successful MFA token issuance or an authenticated operator API request. Do not present this as an MFA pass.
- The connected desktop tool reached its monthly usage cap before troubleshooting the SRP error or independently confirming disposable test-user cleanup. Check the staging pool for any remaining `sh-smoke-` accounts and remove any orphaned test accounts before another run.
- The `--obo` derived-token path was not run because it requires a properly OAuth-scoped customer access token. AgentCore Gateway/Harness managed OBO remains a separate unverified gate.
- No production AWS resources were modified during this follow-up.

## Current evidence and limits

- The existing AWS staging identity, data and API stacks were deployed on 22 November.
- This cycle adds a **staging-only** live identity smoke runner and offline contract tests.
- During this cycle, the AWS CLI returned: **"Your session has expired. Please reauthenticate using 'aws login'."** No Cognito user, MFA challenge, M2M access token, or delegated token was issued by AWS in this cycle.
- The runner has **not** passed a live AWS execution. Source and mock tests are not proof of real identity issuance.
- AgentCore Gateway/Harness is still not deployed. A direct Cognito token exchange is a prerequisite test, **not** proof that AgentCore forwarded an OBO token.
- No production resources or identity configurations were changed. No human operator/customer accounts were created.

## What the runner checks

\`scripts/smoke_cognito_identity.py\` is pinned to the existing **Sydney staging** stack and API. It refuses production stack names and verifies the real CloudFormation stack is CREATE_COMPLETE or UPDATE_COMPLETE before doing anything else.

- Default **read-only**: AWS Cognito issuer, user pool MFA ON, TOTP enabled, pre-token V3_0 trigger, protected pool, human app-client PKCE/authorization-code-only configurations, explicit email-only write permissions, and confidential M2M agent-client delegation/scopes.
- \`--mfa\` **creates disposable staging users** (one operator, one customer) with admin-provisioned trusted attributes, suppressed invitations and random passwords. It uses actual SRP sign-in, TOTP setup and verification, then a second SRP sign-in that must require a TOTP code before access-token issuance. It verifies the issued operator JWT through the application JWKS verifier and a safe read-only operator API request. Both test users are deleted in \`finally\`; test recovery should verify cleanup if IAM or network failures interrupt deletion.
- \`--obo\` requires a **real Cognito OAuth authorization-code customer access token** that already contains both \`shadow-hunter/customer\` and \`shadow-hunter-api/refunds\` scopes and trusted tenant/customer claims. It obtains an M2M actor token, requests Cognito GetDerivedToken with a subject and actor token, verifies the derived token using the actual JWKS and application's CognitoJWTAuthenticator, and tests principal preservation and customer/operator/delegated role separation.

**Why a separate OAuth subject token?** Cognito's SRP API sign-in does not automatically grant app resource-server scopes. Token exchange can only down-scope; it cannot manufacture \`shadow-hunter-api/refunds\` when missing. No fake or self-signed token should ever be treated as evidence here.

## How to complete after AWS reauthentication

Run in the existing staging repository checkout. Do not paste credentials or JWTs into git, chat, command history, logs, or tickets.

1. Reauthenticate the *authorized* AWS profile with \`aws login\` in an interactive session, then check \`aws sts get-caller-identity\`. No production deployment authorization is implied.
2. Install optional test-only dependency \`python -m pip install pycognito\` (the repo's existing AWS/server extras are also required) and make the application importable (e.g. \`python -m pip install -e ".[aws,server,dev]"\` in a virtualenv).
3. Run \`python scripts/smoke_cognito_identity.py\` for read-only deployed configuration inspection.
4. Run \`python scripts/smoke_cognito_identity.py --mfa\` to test real password + TOTP challenges, cryptographic JWT validation and read-only operator API access. It may take a TOTP period to avoid OTP reuse. Confirm no synthetic smoke users remain afterward.
5. Use a reviewed customer OAuth authorization-code+PKCE login with scopes \`openid email shadow-hunter/customer shadow-hunter-api/refunds\` and a registered callback. Hold the short-lived access token only in the \`SHADOW_HUNTER_SMOKE_CUSTOMER_ACCESS_TOKEN\` environment variable of the local process (no file, source code, or persistent secret storage). Run \`python scripts/smoke_cognito_identity.py --obo\`, then promptly clear the environment variable. Never print the token. Production accounts/customer data are out of scope.
6. Review any failures and make a separate decision before enabling the actual AgentCore Gateway/Harness live OBO route. Only then run true Gateway-to-API authenticated end-to-end tests.

## Explicit release blockers

- A human-authorized AWS reauthentication is required. The assistant cannot restore an expired AWS sign-in silently.
- No real staged operator/customer MFA flow or OBO token has been verified yet.
- The customer OAuth callback and secure end-user login flow need validation before obtaining a scoped customer token; an SRP token cannot replace it.
- AgentCore Gateway/Harness outbound OAuth token-exchange and actor identity remain separate end-to-end tests.
- Live tests may incur ordinary AWS charges; the runner has no payment/refund execution path.

Official AWS references:
- Cognito MFA/TOTP: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa-totp.html
- Cognito derived-token exchange: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-token-exchange.html
- GetDerivedToken API: https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetDerivedToken.html
