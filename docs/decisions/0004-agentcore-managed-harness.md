# ADR 0004: Use the AgentCore managed Harness for the AWS challenge

- Status: Accepted as the current integration target; deployment pending
- Date: 2026-11-19

## Context

The AWS Builder Center challenge is titled "Agents, your rules: Bedrock Managed Agents build." The current AWS Bedrock documentation states that Amazon Bedrock Agents Classic stopped accepting new customers on 30 July 2026 and recommends Amazon Bedrock AgentCore for equivalent managed-agent functionality.

AgentCore now provides a managed Harness with a declared model, system prompt, tool set, limits, and a managed orchestration loop. Harnesses can attach an AgentCore Gateway as a governed tool source. AgentCore Policy uses Cedar and can be attached to a Gateway in ENFORCE mode.

## Decision

Target the AgentCore managed Harness and Gateway rather than the legacy Agents Classic InvokeAgent API. Invoke the Harness with the bedrock-agentcore InvokeHarness operation. Expose only order lookup, eligibility lookup, and refund-request creation through the Gateway. Keep refund execution operator-only and require a separate action-bound approval capability.

## Consequences

- No Bedrock Agents Classic client or API is used.
- Harness and Gateway resource creation is not performed by application startup.
- The repository carries a Harness configuration example, OpenAPI target contract, and Cedar template.
- The Gateway Policy Engine must be attached in ENFORCE mode before the Harness is deployed or exposed to users.
- Exact resource ARNs, IAM roles, public API endpoint, region, model access, and identity propagation remain deployment-time configuration.
- The event page still says full details are coming soon; reconcile any further published challenge requirements before submission.
- No AWS deployment or resource creation is claimed by this ADR.
