# Cloud service and billing research — 18 November 2026

## AWS hackathon

The AWS Builder Center event listing describes the challenge as building an agent on **Amazon Bedrock Managed Agents** that follows developer-defined rules, stays within defined boundaries, and resists attempts to push it outside those boundaries. The same page says full details are coming soon. Do not treat unpublished rules or judging details as known.

Source: https://builder.aws.com/build/hackathons/61c39fba-1383-37e7-bd5c-3f9d889d89fc/agents-your-rules-bedrock-managed-agents-build

## AWS AgentCore Policy and Gateway

AWS announced AgentCore Policy general availability on 3 March 2026. It integrates with AgentCore Gateway, intercepting agent-tool traffic and evaluating Cedar policies before tool access is allowed or denied. Gateway can expose tools through MCP and invoke Lambda or REST targets. This is a strong policy-enforcement option, but the project's required Bedrock Managed Agents integration path still needs an end-to-end compatibility test.

Sources:
- https://aws.amazon.com/about-aws/whats-new/2026/03/policy-amazon-bedrock-agentcore-generally-available/
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-create.html
- https://aws.amazon.com/bedrock/agentcore/faqs/

## GitHub Actions compute

GitHub's current billing documentation states:
- Standard GitHub-hosted runner usage is free for public repositories.
- For private repositories, hosted-runner compute draws from the plan's monthly included compute usage; excess usage is billed.
- Self-hosted runner compute is currently free under the published Actions billing page.
- GitHub Free includes 2,000 standard runner minutes, 500 MB artifact storage, and 10 GB cache per repository.
- Baseline GitHub-hosted rates include Linux 2-core at USD 0.006/minute and Windows 2-core at USD 0.010/minute.

At 24 runs/day × 30 minutes × 10 days, the maximum requested runtime is 7,200 runner-minutes. For a private repo using Linux 2-core hosted runners, assuming the entire Free allowance is available, the calculation would be 7,200 - 2,000 = 5,200 excess minutes × USD 0.006 = USD 31.20. Actual charges depend on other usage, runner type, and the billing account's current allowances/rates.

A self-hosted runner avoids GitHub-hosted compute charges but consumes local machine availability, electricity, hardware, and network resources. A personal Windows machine must be isolated and secured before it is used as an unattended runner.

Sources:
- https://docs.github.com/en/actions/concepts/billing-and-usage
- https://docs.github.com/en/billing/concepts/product-billing/github-actions

## GitHub Copilot AI usage

GitHub's plans page states Copilot CLI and agent features consume GitHub AI Credits. AI credits are separate from Actions runner minutes. The Free plan offers limited chat and agent usage; sustained unattended development cannot be assumed to fit within a free allowance.

Sources:
- https://github.com/features/copilot/plans
- https://docs.github.com/en/copilot/concepts/billing-and-usage/individuals/billing

## Design decision

Keep the repository private. Use a self-hosted runner only after it is registered with a dedicated restricted identity and the agent's model authentication and usage ceiling are verified. Keep scheduled automation disabled until then.
