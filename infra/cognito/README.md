# Cognito identity configuration for Shadow Hunter

This package supplies the Cognito pre-token-generation Lambda. It does not
create a user pool, app clients, resource server, OAuth credential provider,
Harness, Gateway, or any other AWS resource.

## What the trigger does

The handler in `src/shadow_hunter/cognito_pretoken.py` copies only these values
from the authenticated Cognito user-pool attributes into access-token claims:

- `custom:tenant_id` becomes `tenant_id`.
- `custom:customer_id` becomes `customer_id`.

The same logic runs for user authentication and
`TokenGeneration_TokenExchange`. If either trusted attribute is absent or
malformed, Cognito token issuance fails closed. The handler ignores client
metadata and prompt content. It preserves other pre-token claim overrides and
does not change scopes or group membership.

M2M `TokenGeneration_ClientCredentials` events are returned unchanged because
they represent the agent actor, not an end customer. Cognito issues the
delegated `act.sub` from the actor-token exchange; the Lambda does not invent
or override it.

## Deployment

1. Create the Cognito user pool with `custom:tenant_id` and
   `custom:customer_id` attributes. Populate them only from a trusted
   registration or tenant-provisioning workflow.
2. Build and deploy the Lambda and invocation permission:

   `sam build --template-file infra/cognito/pre-token-generation.yaml`

   `sam deploy --guided --template-file .aws-sam/build/template.yaml`

   Supply the existing `UserPoolId` parameter.
3. In the Cognito user-pool console, associate the Lambda as the Pre token
   generation trigger. Select event version `V3_0` so user access tokens and
   M2M actor-token events use the access-token customization event model.
   The handler passes M2M ClientCredentials events through unchanged.
4. Register a Cognito resource server and authorize the customer app client to
   request both `shadow-hunter/customer` and `shadow-hunter-api/refunds`.
5. Configure the token-exchange client for
   `ALLOW_TOKEN_EXCHANGE_DELEGATION`. Ensure the issued OBO token has the
   resource audience and refund scope.
6. Verify a normal customer token and a derived OBO token contain the expected
   tenant/customer claims. Verify the derived token has `aud`, `scope`, and
   `act.sub` values matching Shadow Hunter's environment configuration.
7. Configure `SHADOW_HUNTER_AUTH_MODE=cognito` only after those checks pass.

The user pool must be on an eligible Cognito feature plan and token exchange
must be enabled for the account. OBO scopes are the intersection of requested
scopes, scopes in the subject token, and scopes allowed for the exchange
client. A token exchange cannot grant more scope than the subject token
already carries. A pre-token trigger can customize the issued access-token
claims/scopes, but it cannot bypass this token-exchange down-scoping boundary.

## Security boundaries

- The Lambda role needs only standard CloudWatch Logs permissions.
- Cognito invokes the function through a resource-based Lambda permission
  scoped to the selected user pool.
- The function does not call other services, read secrets, or use client
  metadata to derive authorization claims.
- This is a configuration template. No deployment has been performed.

## Official references

- Cognito pre-token-generation trigger:
  https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-token-generation.html
- Cognito token exchange:
  https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-token-exchange.html
