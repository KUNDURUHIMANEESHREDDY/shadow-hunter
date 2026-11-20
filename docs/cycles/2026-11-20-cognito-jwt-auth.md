# Engineering cycle — Cognito JWT and OBO authorization

- Date: 2026-11-20
- Scope: Application-side JWT verification and trusted identity mapping
- Status: Authored and committed; untested by repository operating contract

## Changes

- Added CognitoJWTAuthenticator with RS256 signature verification against the configured Cognito user-pool JWKS endpoint.
- Added issuer, expiry, issued-at, subject, token-use, and bounded-clock-skew validation.
- Added separate customer and Gateway-tool token profiles.
- Customer profile requires the configured app-client ID, customer scope, and trusted tenant_id / customer_id claims.
- Gateway profile requires the target resource audience, delegated refund scope, and exact configured act.sub actor identity.
- Operator profile requires the configured Cognito app client and operator group.
- Added an explicit SHADOW_HUNTER_AUTH_MODE selector. Unknown modes fail closed; Cognito mode does not fall back to local opaque tokens.
- Changed /v1/agent/tools/{tool_name} to accept only the delegated Gateway-token profile in Cognito mode.
- Preserved environment-backed opaque token authentication for local development.
- Added PyJWT with cryptography support to the server and development extras.
- Authored RSA/JWKS-backed tests covering valid claims, wrong client, missing scopes/claims, wrong audience, wrong actor, and operator-group separation.
- Updated architecture, deployment instructions and README status.

## Security notes

- JWT payload fields are never trusted until the signature and standard claims have been validated.
- Only RS256 is accepted and keys are selected by JWT kid from the configured Cognito JWKS.
- The verifier rejects ID tokens, missing OBO audience, missing actor claims, missing required scopes, and missing business identity claims.
- JWKS fetch/key errors fail closed. The PyJWT JWKS client uses a bounded key cache and short network timeout.
- The expected agent act.sub is an explicit deployment setting; it must match the actor identity Cognito actually issues.
- Tenant/customer claims must be emitted by a trusted Cognito pre-token-generation V2 trigger for both normal and token-exchange access tokens.
- The customer subject token must already contain the downstream refund scope. Cognito token exchange cannot add scopes that are absent from the subject token.
- No Cognito user pool, trigger, app client, OBO provider, Harness, Gateway, policy engine, or AWS resource was created or deployed.

## Verification

No tests, build, lint, formatting, or security scans were executed, consistent with docs/engineering-cycle.md. These changes are therefore untested.

## Next task

Configure the Cognito claim-issuance and OBO provider, then verify the real JWT shape end to end. After that, implement AWS data-plane infrastructure and service deployment.
