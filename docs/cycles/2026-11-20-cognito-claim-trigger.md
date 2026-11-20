# Engineering cycle — Cognito identity claim issuance

- Date: 2026-11-20
- Scope: Cognito pre-token-generation handler and deployable SAM template
- Status: Authored and committed; untested and not deployed

## Changes

- Added a V2/V3 Cognito pre-token-generation handler for tenant/customer claims.
- The handler maps trusted custom user-pool attributes to the application claim names consumed by CognitoJWTAuthenticator.
- Added TokenGeneration_TokenExchange support so the derived OBO token receives the resolved user's identity claims.
- M2M ClientCredentials actor tokens are passed through unchanged.
- Missing tenant/customer attributes fail token issuance rather than create an under-specified authorization token.
- Existing claim overrides and group configuration are preserved; the function does not modify scopes.
- Added a SAM template for the Lambda function and a resource-based invoke permission scoped to the existing user pool.
- Added tests for normal authentication, OBO exchange, M2M passthrough, preservation, missing claims, and unsupported V1 trigger events.

## Verification

No tests, SAM build, deployment, lint, or security checks were executed. The stack has not been deployed and no Cognito user pool has been modified.

## Next task

Wire the deployed user pool's V3_0 pre-token trigger, OBO OAuth credential provider, Harness CUSTOM_JWT authorizer, and Gateway target configuration. Then verify real issued tokens before moving to the production AWS data plane.
