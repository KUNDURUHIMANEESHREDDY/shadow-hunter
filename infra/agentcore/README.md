# Amazon Bedrock AgentCore integration

Shadow Hunter targets the AgentCore managed Harness, not the legacy Amazon
Bedrock Agents Classic APIs. AWS documentation states that Agents Classic
stopped accepting new customers on 30 July 2026 and recommends AgentCore for
equivalent managed-agent functionality. The AWS Builder Center challenge page
currently says full details are coming soon. Reconcile this integration with
any additional event-specific instructions before final submission.

## Security path

1. Configure a Cognito User Pool (or compatible OIDC provider) and a CUSTOM_JWT
   authorizer on the AgentCore Harness. AWS documents that SigV4 calls do not
   propagate end-user identity into downstream tools. Use a Bearer JWT for
   end-user Harness invocation when per-user tool authorization is required.
   The current Boto3 adapter uses SigV4 and is an integration scaffold only;
   it does not yet forward/validate production customer JWTs.
2. Deploy the Shadow Hunter API behind a public HTTPS endpoint and a real
   Cognito/JWT or equivalent authorizer.
3. Create an AgentCore Gateway with an OpenAPI target based on openapi.yaml.
   Name the target RefundTools and configure secured inbound and outbound auth.
4. Attach an AgentCore Policy Engine to that Gateway in ENFORCE mode.
5. Replace the Gateway ARN placeholder in
   policies/refund_policy.cedar.template with the actual Gateway ARN and add
   the policy to the engine. The policy permits only the three read/request
   tools. Default deny applies to unlisted operations.
6. Configure the Harness using
   app/refund-assistant/harness.yaml.example. Replace the execution-role and
   Gateway ARN values, copy the file to harness.yaml, and keep allowedTools
   restricted to the Gateway server.
7. Deploy the Harness and set SHADOW_HUNTER_HARNESS_ARN and AWS_REGION for the
   Shadow Hunter API. The API /v1/agent/chat route invokes the Harness using
   boto3's InvokeHarness operation.
8. Verify in AWS that the Gateway Policy Engine is attached in ENFORCE mode
   and that the only Harness tools are those from the governed Gateway.

## Local application

Install the server and AWS extras with the project instructions in the root
README. Without SHADOW_HUNTER_HARNESS_ARN, the chat API returns 503 and makes
no external call. The policy and approval API can still be exercised locally
with the SQLite demo store and configured local bearer tokens.

The checked-in Harness YAML is a template, not a deployed resource
definition. The API adapter invokes an existing Harness; it does not create
cloud resources.

## Important boundaries

- Do not expose execute_refund as an agent tool. Refund execution is an
  operator-only API action that requires the one-time approval capability.
- The Cedar policy is an outer allowlist. Application and downstream checks
  enforce customer identity, tenant ownership, eligibility, currency,
  refundable balance, idempotency, and human approval.
- The local SQLite side effect updates only a demo ledger. No payment provider
  or banking rail is called.
- Configure a CUSTOM_JWT inbound authorizer for an end-user Harness. See
  https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/harness-security.html.
- Do not use the AgentCore Gateway tutorial's NONE authorizer in production.
- Do not deploy until account, region, IAM role, model access, cost limits,
  public endpoint, and identity propagation have been reviewed.

## Official references

- AgentCore Harness: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/harness.html
- Harness tools and Gateway: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/harness-tools.html
- InvokeHarness: https://docs.aws.amazon.com/bedrock-agentcore/latest/APIReference/API_InvokeHarness.html
- Harness security and inbound OAuth: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/harness-security.html
- AgentCore Gateway: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-create.html
- Policy in AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-getting-started.html
- Agents Classic maintenance mode: https://docs.aws.amazon.com/bedrock/latest/userguide/agents-classic-maintenance-mode.html
- Hackathon: https://builder.aws.com/build/hackathons/61c39fba-1383-37e7-bd5c-3f9d889d89fc/agents-your-rules-bedrock-managed-agents-build
