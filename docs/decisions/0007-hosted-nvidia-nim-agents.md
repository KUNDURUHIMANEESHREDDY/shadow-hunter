# Decision 0007 — hosted NVIDIA NIM for Red/Blue reasoning

- Date: 2026-11-20
- Status: Accepted

## Context

The authenticated Red/Blue evaluation harness needs model-assisted adversarial
planning and defensive reasoning. The project owner selected hosted NVIDIA NIM
and explicitly rejected local-model inference for this evaluation path.

The deterministic ToolGateway and PolicyEngine must remain outside the model
boundary. Evaluations must remain isolated from live customer data and retain
enough metadata for reproducibility analysis.

## Decision

Use two hosted NVIDIA API Catalog models through the OpenAI-compatible endpoint:

- Red: `nvidia/nemotron-3.5-lightning-30b-a3b`
- Blue: `nvidia/nemotron-3.5-bolt-e4b`

The fixed API base is `https://integrate.api.nvidia.com/v1`; the runtime posts
to `/chat/completions`.

Red may choose only from an application-owned scenario catalogue and vary
bounded natural-language text. Blue performs model-assisted threat analysis
alongside deterministic signals. Every proposal still goes through the existing
ToolGateway and PolicyEngine. Model output cannot grant or revoke authorization.

Use environment credentials for local development and resource-scoped AWS
Secrets Manager ARNs for hosted deployment. Store configured model IDs and
per-round seeds with evaluation evidence. Keep the evaluation restricted to
synthetic data and cap the synchronous operator run at three rounds.

## Consequences

- The Red/Blue evaluator requires hosted NVIDIA credentials; it has no Ollama
  or local-model fallback.
- NVIDIA provider availability, trial terms, rate limits, latency, model
  updates and best-effort seed reproducibility are external dependencies.
- Only synthetic scenario data may be sent through this model adapter until a
  separate customer-data privacy/vendor review is approved.
- The separate AgntID/Ollama MCP demo remains independent and is not invoked by
  this evaluation path.
- Deterministic authorization, human approval and audit boundaries remain
  unchanged.
- The adapter and behavior tests are authored but remain untested until a
  credentialed request and the permitted project verification process are run.
