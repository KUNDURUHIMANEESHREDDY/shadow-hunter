# Engineering cycle — hosted NVIDIA NIM Red/Blue agents

- Date: 2026-11-20
- Scope: Replace the Red/Blue deterministic-only runtime with two hosted NVIDIA NIM reasoning adapters while retaining deterministic gateway enforcement
- Status: Authored and committed; untested and not deployed

## Changes

- Added a standard-library HTTP client for NVIDIA's hosted OpenAI-compatible API.
- Fixed the base URL to `https://integrate.api.nvidia.com/v1` and the request path to `/chat/completions`.
- Configured Red to use `nvidia/nemotron-3.5-lightning-30b-a3b` and Blue to use `nvidia/nemotron-3.5-bolt-e4b`, with server-side model overrides.
- Red can select only among existing bounded scenarios and can mutate only a short hypothesis/description and existing natural-language reason text. It cannot invent tools, order IDs, amounts, currencies, expected outcomes or mutate legitimate controls.
- Blue uses NVIDIA JSON-schema structured output. Its categories/indicators are validated and combined with deterministic checks; the risk score cannot fall below the deterministic score.
- Preserved ToolGateway and PolicyEngine as the only authorization authority. Blue's recommendation is never used to override the actual policy decision.
- Added model identifiers and per-round Red/Blue seeds to the redacted evidence. The seed scheme is deterministic for the same inputs; NVIDIA describes generation repeatability as best-effort.
- Added bounded non-streaming requests, a short timeout, prompt/output caps, no provider retries, no local-model fallback and a three-round synchronous API cap.
- Added environment and AWS Secrets Manager configuration for the NVIDIA API key and the distinct A2A keys; the Lambda role receives GetSecretValue only for explicitly configured secret ARNs.
- Updated the operator console to show both models, Red strategy summary, Blue analysis, risk and gateway outcome.
- Kept the separate AgntID/Ollama MCP demonstration isolated from this operator evaluation path.

## Security boundaries

- Only synthetic sandbox data is sent to NVIDIA; no production customer/order records are included.
- Provider credentials and HMAC keys are not placed in prompts, browser code, source control or audit results.
- Red/Blue output remains untrusted and strictly schema/allowlist checked.
- Provider failure, timeout, malformed output or invalid schema stops the run; there is no local fallback.
- The model pair cannot alter server-side identity, tenant ownership, tool allowlist, policy, approval state or execution permission.
- The local AgntID/Ollama demo is a separate integration harness and is not called by this evaluator.
- No NVIDIA API request, secret provisioning, AWS resource creation or deployment occurred in this cycle.

## Verification

No tests, build, SAM validation, lint, formatting or security scans were executed, consistent with `docs/engineering-cycle.md`. Behavior-focused tests were authored but remain unexecuted.

## Next task

Run a credentialed, one-round synthetic evaluation against the hosted NVIDIA API after the owner provisions an NVIDIA API key and unique A2A signing keys. Then inspect actual response shape/latency/rate limits and adjust request budgets before enabling larger benchmark runs.