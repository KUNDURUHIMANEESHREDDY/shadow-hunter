# Architecture and integration decisions

## Product boundary

The first workload is a support/refund agent. The only consequential operations are order lookup, eligibility evaluation, refund request creation, approval, and refund execution. Do not build a generic multi-agent platform before the first workload is correct.

## Trust boundaries

1. User identity is established outside the model.
2. User prompts and retrieved/tool-returned text are untrusted data.
3. The model can propose a tool call but cannot grant permission.
4. A gateway/application authorizer evaluates principal, action, resource, tenant, canonical arguments, and policy version.
5. The downstream tool independently enforces authorization and business invariants.
6. The approval service issues a short-lived, single-use capability for a canonical action digest.
7. Audit storage records the decision and resulting side effect independently of model-generated explanations.

## AWS integration

The event description names Amazon Bedrock Managed Agents. Use the required event-compatible runtime and validate current service/API availability before implementing. Amazon Bedrock AgentCore Gateway can expose tools and AgentCore Policy can evaluate Cedar policies at the gateway. Verify that the target Managed Agents runtime can invoke tools through this integration; if not, document the exact supported bridge and keep the policy enforcement adapter external to the model.

Do not assume product naming, preview status, service regions, or API contracts from older tutorials. Check AWS documentation and the live AWS account/region during implementation.

## Policy decision contract

Every proposed action is normalized to a canonical record:

- request_id and trace_id
- organization_id / tenant_id
- authenticated principal and role claims
- agent_id and workload
- tool identifier and version
- resource type and canonical resource identifier
- canonical, schema-validated arguments (sensitive fields redacted in logs)
- policy bundle ID/version and evaluation timestamp
- decision: ALLOW | DENY | ESCALATE
- reason codes and matched policy identifiers
- approval reference (when applicable)

Unknown or malformed fields do not broaden permissions. A missing tenant, principal, resource, action, policy result, or required context must fail closed.

## Approval protocol

1. Create a pending request for an exact normalized action and parameter digest.
2. Bind it to tenant, requesting principal, action, resource, policy version, expiry, nonce, and intended tool.
3. Authenticate the approver separately and verify approver authority.
4. On approval, issue a short-lived single-use token/capability.
5. Before execution, revalidate policy, action digest, resource state, expiry, and nonce atomically.
6. Mark the nonce consumed in the same transaction as the state transition or use an idempotent execution record.
7. A parameter change requires a new approval.

## Reliability and security requirements

- Fail closed for policy engine timeouts and errors.
- Downstream tools must not trust the agent's user ID or tenant claims; derive verified identity from authenticated context.
- Enforce tenant/resource access in data queries, not only at UI/API.
- Use idempotency keys and state transitions for refunds.
- Protect approval and audit endpoints with separate roles.
- Use encryption at rest/in transit and a managed secret store.
- Avoid raw prompts, access tokens, payment details, and unnecessary PII in logs.
- Audit storage is not called immutable unless retention/WORM controls are configured and tested.
- Define request, tool, token, time, and spend ceilings.

## Open architecture decisions

- Exact Bedrock Managed Agents API/runtime and compatibility with AgentCore Gateway Policy.
- AWS region availability and promotional-credit eligibility.
- Whether the first data store is DynamoDB or PostgreSQL; choose based on transaction and tenant-isolation needs.
- Audit retention and immutable export mechanism.
- Authentication mode for end customers and support operators.
- Model/provider budget and cycle cap.
