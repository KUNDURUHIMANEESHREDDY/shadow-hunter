# Gate 1 — Governed AgentCore Harness tool invocation

**As inspected 23 November 2026:** AWS identity/data/API staging stacks exist
in `ap-southeast-2`, but `ListHarnesses`, `ListGateways`,
`ListPolicyEngines` and `ListOauth2CredentialProviders` each returned
zero resources. This is **not a passing live AgentCore deployment**.

The Harness application adapter now reads only the final completed assistant
message, discards streamed tool parameters and intermediate observations, and
returns bounded, explicitly *unverified* tool-event counts. The separate
`scripts/verify_harness_tool_e2e.py` deliberately requires two evidence
sources before claiming an actual governed tool invocation:

1. Streaming harness events include at least one observed tool use and tool
   result, with a successfully completed final assistant message.
2. A matching `POLICY_DECISION ALLOW` event for `get_order` exists in the
   operator audit endpoint under the same trace ID.

Model prose alone is **never** execution proof. The correlation check may
expose configuration defects if an AgentCore Gateway target does not preserve
trace IDs; do not bypass it by trusting the model.

## Deployment prerequisite (staging only)

- Owner approval for potentially billable AgentCore, Bedrock, policy and
  Identity resources, with a verified budget, notification recipient and
  service-cost restrictions.
- Exact scoped staging roles and resource identifiers.
- Deploy and verify the Gateway, Cedar Policy Engine in ENFORCE mode,
  OBO credential provider, HTTP OpenAPI target and Harness in that order.
  The examples are in `infra/agentcore/`.
- Run existing `scripts/preflight_agentcore_staging.py` and
  `scripts/verify_agentcore_staging.py` first.
- Set the validated Harness ARN in the staging API stack.
- With separately issued real synthetic customer and operator JWTs and a
  fixture order owned by the customer:

```bash
python scripts/verify_harness_tool_e2e.py \\
  --synthetic-order-id SYNTHETIC_ORDER_ID --invoke-model
```

This command invokes an LLM and may incur cloud charges, so no automatic
scheduled or CI job calls it. It prints only generic success/failure
messages; no tokens, order contents, or provider error bodies.
