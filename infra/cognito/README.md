# Cognito production identity for Shadow Hunter

This is a production-only identity configuration. The CloudFormation stack accepts only Environment=production. It does not create a staging or development User Pool.

## Production identity stack

infra/cognito/identity-stack.yaml provisions:

- Cognito User Pool with mandatory software-token MFA, admin-only user creation, 14-character password policy, email verification, and active deletion protection.
- Immutable custom:tenant_id and custom:customer_id attributes.
- V3_0 pre-token-generation Lambda.
- Separate public customer and operator authorization-code clients.
- Dedicated confidential M2M agent client with ALLOW_TOKEN_EXCHANGE_DELEGATION.
- Resource-server scopes shadow-hunter/customer, shadow-hunter-api/refunds, and shadow-hunter-agent/actor.
- shadow_hunter_operators group and Cognito hosted domain.
- SES-backed developer email configuration for production invitations and verification messages.

All production values are required inputs, not guessed defaults:

- UserPoolTier: ESSENTIALS or PLUS. Cognito token exchange requires an eligible tier and account-level token exchange enablement.
- CognitoDomainPrefix: globally unique Cognito prefix in the selected production Region.
- SesSourceArn: verified SES identity ARN in the same Region as the User Pool.
- SesFromAddress: sender address belonging to that verified SES identity.
- CustomerCallbackUrl and CustomerLogoutUrl: HTTPS URLs owned by the customer application.
- OperatorCallbackUrl and OperatorLogoutUrl: HTTPS URLs owned by the operator console.

The User Pool uses EmailSendingAccount DEVELOPER so SES-backed email and the custom invitation message are valid. The SES identity must be verified and usable in the User Pool Region; SES account sending limits and production access are account-level concerns and cannot be verified offline.

The customer and operator clients are public authorization-code clients without client secrets. The customer client can request the customer scope and the delegated refund scope; the operator client receives only openid/email scopes. The dedicated agent client is confidential, has client credentials enabled, and receives the actor and delegated API scopes. Its generated secret is not emitted as a CloudFormation output. Do not put it in source control, parameters, command history or logs. AgentCore must obtain it through an external Secrets Manager reference.

## Trusted user provisioning

The User Pool defines immutable tenant/customer attributes. The browser clients cannot write them. A trusted administrative provisioning process must assign custom:tenant_id and custom:customer_id for each customer before token issuance. The pre-token trigger fails customer and delegated-user token issuance if either trusted attribute is absent or malformed.

Operator users are a separate identity class. Cognito's V3 pre-token event includes server-managed group information. A member of shadow_hunter_operators passes through unchanged: the trigger never adds customer tenant/customer claims to operator tokens, even when those attributes exist. The API independently requires the separate operator app-client ID and operator group claim. Ordinary users without both tenant/customer attributes are rejected.

The operator group is created empty. Add members only through a trusted administrative workflow; never accept group membership from client metadata or prompts.

## AgentCore on-behalf-of token exchange

The intended identity flow is:

1. Customer app authenticates a customer and obtains a Cognito access token with shadow-hunter/customer and shadow-hunter-api/refunds scopes.
2. Harness validates the original customer token through CUSTOM_JWT.
3. AgentCore Gateway receives the delegated request.
4. AgentCore Identity obtains an M2M actor token from the confidential agent client using client credentials and shadow-hunter-agent/actor.
5. Gateway target exchanges the subject access token and actor token using TOKEN_EXCHANGE.
6. The target API receives a resource-scoped token with aud=shadow-hunter-api, scope shadow-hunter-api/refunds, the customer subject, and act.sub identifying the agent.
7. Shadow Hunter independently validates signature, issuer, expiry, token_use, exact resource audience, refund scope, subject, actor, tenant, customer, and policy.

Important Cognito compatibility detail: the Gateway target must set customParameters.subject_token_type to urn:ietf:params:oauth:token-type:access_token. AgentCore's generic default subject token type is JWT, whereas this Cognito token-exchange endpoint expects the access-token type. The target example also sets audience=shadow-hunter-api and requests only shadow-hunter-api/refunds.

The AgentCore Identity provider must use TOKEN_EXCHANGE, actorTokenContent M2M, and actorTokenScopes ["shadow-hunter-agent/actor"]. See infra/agentcore/cognito-obo-provider.example.json and infra/agentcore/gateway-target-oauth.example.json. The first example uses an external Secrets Manager secret reference; it contains no credentials.

Cognito token exchange is account-level functionality. The account must enable it, the pool must use Essentials or Plus, and the M2M client must allow ALLOW_TOKEN_EXCHANGE_DELEGATION. The pre-token trigger does not create additional scopes. Derived scopes are constrained by requested scopes, subject-token scopes, and scopes permitted for the exchange client.

## Offline verification

The repository includes a local synthetic identity contract test. It generates ephemeral RSA keys, signs synthetic Cognito-shaped access tokens, invokes the real pre-token handler, and verifies the real CognitoJWTAuthenticator for customer, operator, and delegated-agent profiles. It also tests wrong actor, wrong audience, missing tenant attributes, and separate operator-client enforcement.

Run locally:

    python -m pytest tests/test_auth.py tests/test_cognito_pretoken.py tests/test_production_identity_contract.py -q

These tests do not contact Cognito, use a real User Pool, or prove that AWS issued the synthetic tokens. They are offline contract tests only.

Validate and package the production templates locally:

    sam validate --lint --template-file infra/cognito/pre-token-generation.yaml
    sam validate --template-file infra/cognito/identity-stack.yaml
    sam validate --lint --template-file infra/data/dynamodb.yaml
    sam validate --lint --template-file infra/app/template.yaml

    sam build --template-file infra/cognito/pre-token-generation.yaml
    sam build --template-file infra/cognito/identity-stack.yaml
    sam build --template-file infra/data/dynamodb.yaml
    sam build --template-file infra/app/template.yaml

Use a current standalone cfn-lint release for the identity template: the cfn-lint schema bundled with older SAM CLI distributions may not recognize the newer ALLOW_TOKEN_EXCHANGE_DELEGATION enum.

## Existing User Pool

infra/cognito/pre-token-generation.yaml is an add-on for an already provisioned production User Pool. It only deploys the trigger Lambda and its invoke permission. It does not configure the User Pool's clients, scopes, email, domain, or LambdaConfig. Do not mix the new-pool and existing-pool paths.

## Offline implementation status

The identity stack and AgentCore examples are infrastructure code only. The templates can be validated and packaged without an AWS account. No AWS account, User Pool, SES identity, app client, domain, secret, AgentCore provider, or other cloud resource is created by the local tests/builds. Real token issuance and account-level token-exchange enablement remain unverified until a production account is explicitly brought into scope.

## Official references

- Cognito pre-token-generation trigger: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-token-generation.html
- Cognito token exchange: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-token-exchange.html
- Cognito User Pool: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html
- Cognito User Pool Client: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolclient.html
- Amazon Cognito SES email configuration: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-email.html
- AgentCore OBO token exchange: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/on-behalf-of-token-exchange.html
