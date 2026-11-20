# Engineering cycle — AgentCore end-user JWT forwarding

- Date: 2026-11-20
- Scope: First implementation slice for the Harness end-user identity boundary
- Status: Authored and committed; untested by repository operating contract

## Changes

- Changed the AgentCore Harness adapter to require a compact JWT access token.
- Replaced its default SigV4 invocation with a per-invocation unsigned Boto3 client.
- Added a request-scoped \`before-send\` handler that adds \`Authorization: Bearer\` only for the expected regional AgentCore data-plane hostname.
- Kept the bearer token out of the request body, response, persistent storage, and application logs.
- Created a fresh SDK client per invocation to prevent per-user bearer headers from being shared between concurrent requests.
- Updated \`/v1/agent/chat\` to forward the already-authenticated caller token into the Harness adapter.
- Added a \`CUSTOM_JWT\` authorizer to the Harness configuration example.
- Added a Gateway target outbound OAuth \`TOKEN_EXCHANGE\` example and documented Cognito RFC 8693 prerequisites.
- Updated architecture and deployment documentation.
- Added adapter tests for JWT-shaped tokens and rejection of opaque local demo tokens.

## Security and implementation boundaries

- This change only establishes the API-to-Harness Bearer JWT hop. AgentCore must still validate the JWT against the deployed Harness authorizer.
- The Harness-to-Gateway request uses the Harness execution role; the Gateway target must separately use AgentCore Identity OBO token exchange to obtain a target-scoped token.
- The FastAPI \`TokenAuthenticator\` remains a development-only environment map. It does not validate Cognito or derived OBO JWT signatures, issuers, audiences, scopes, or actor claims.
- The application JWT verifier and trusted tenant/customer claim mapping are the next implementation task.
- No Cognito app client, OAuth credential provider, Gateway, Harness, API target, or AWS resource was created or deployed.

## Verification

No tests, build, lint, format, or security scans were executed, in accordance with \`docs/engineering-cycle.md\`. Repository file reads and commit-head verification are integrity checks only, not runtime verification.

## Next task

Implement application-side JWT verification and claim mapping for both the customer API boundary and the derived OBO token at the governed tool boundary. Require issuer, signature, expiry, audience, scope, subject, and expected \`act\` claim validation before constructing a \`Principal\`.
