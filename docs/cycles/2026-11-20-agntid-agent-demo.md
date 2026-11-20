# Engineering cycle — AgntID pass-through and Ollama live-agent runner

- Date: 2026-11-20
- Scope: Prepare the real agent execution path and internal MCP upstream service
- Status: Authored and committed; untested and not deployed

## Changes

- Added customer-token pass-through through the existing Cognito JWT verifier; delegated OBO remains the default profile.
- Kept the customer-mode agent ID as fixed server-side audit attribution, not proof of agent identity.
- Added UUID-only trace correlation via `X-Shadow-Hunter-Demo-ID`.
- Added exact host/origin allowlisting via MCP SDK TransportSecuritySettings; localhost-only remains default.
- Added an Ollama tool-calling runner using the official MCP Python SDK v2 Client and Streamable HTTP transport.
- The model sees read tools only. A separate write probe targets only a disposable order-demo record and cannot execute a refund.
- Evidence distinguishes explicit AgntID denial, backend policy outcome, and unattributed MCP errors.
- Added behavior tests, a non-root Docker image, an internal Kubernetes ClusterIP target, setup docs and threat-model updates.

## Verification

Tests/build/lint/security checks were not run under the repository's active engineering-cycle rules. Docker image build, Kubernetes deployment, AWS changes and a live AgntID/Ollama run were not performed. AgntID workspace values, Cognito test credentials and cluster access are unavailable in this session.
