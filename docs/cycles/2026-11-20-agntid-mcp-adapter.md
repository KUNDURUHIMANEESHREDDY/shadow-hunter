# Engineering cycle — authenticated MCP server for AgntID upstream

- Date: 2026-11-20
- Scope: Add a Streamable HTTP MCP adapter over the existing Shadow Hunter ToolGateway
- Status: Authored and committed; untested under the repository operating contract

## Changes

- Added the official MCP Python SDK v2 as a server and development dependency.
- Added a Streamable HTTP MCP server mounted at /mcp/ in the existing FastAPI app.
- Registered only get_order, check_refund_eligibility, and create_refund_request.
- Routed all tool calls through the existing ToolGateway; did not duplicate policy or business logic.
- Added an ASGI authentication boundary that checks exactly one Bearer token on every HTTP request.
- Reused authenticate_gateway_tool for both local opaque development tokens and the existing strict Cognito delegated-token profile.
- Assigned agent attribution from the verified Cognito act.sub configuration or a local server-side development setting; ignored clientInfo and caller-supplied metadata.
- Generated fresh request and trace IDs for each tool call and passed the trusted agent ID into ToolGateway.
- Added behavior tests for missing/duplicate/invalid credentials, verifier failures, identity isolation, missing MCP request context, and server-assigned agent attribution.
- Documented the AgntID upstream boundary and the unverified credential-compatibility requirement.

## Security boundaries

- No operator-only endpoint or refund execution capability is exposed as an MCP tool.
- Missing authentication, invalid identity, token-verifier failure, or absent request context never invokes ToolGateway.
- The original MCP Bearer token is not forwarded to the application gateway or stored in audit evidence.
- Cognito mode continues to require the existing RS256, issuer, expiry, audience, scope, subject, and act.sub checks.
- Local opaque tokens and the local agent identity are for development only.
- The official SDK Streamable HTTP server keeps its localhost-only host protection. A public deployment requires an explicit host allowlist, TLS, and separate review.
- AgntID tenant setup, proxy registration, credential exchange, and end-to-end runtime verification are not part of this commit.
- No AWS resources were created or deployed.

## Verification

No tests, build, lint, formatting, or security scans were executed, consistent with docs/engineering-cycle.md. The tests are authored but remain unexecuted. Repository reads and Git commit inspection are not runtime verification.

## Next task

Obtain the challenge-specific AgntID upstream credential and deployment contract. Confirm whether the proxy can pass through or exchange into the existing Cognito delegated-token profile. Then connect a registered agent through the AgntID proxy and verify one allowed and one denied MCP tool call with correlated audit evidence.
