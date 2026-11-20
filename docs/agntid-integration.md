# AgntID MCP integration

## Integration boundary

Shadow Hunter now exposes an authenticated Model Context Protocol server over
Streamable HTTP at:

~~~text
http://127.0.0.1:8000/mcp/
~~~

The endpoint is intended to be configured as the upstream MCP server behind
AgntID's embedded MCP proxy. AgntID remains the per-action intent and credential
enforcement layer. Shadow Hunter remains the application authorization and
business-rule layer.

The server advertises exactly three tools:

- get_order(order_id)
- check_refund_eligibility(order_id)
- create_refund_request(order_id, amount_minor, currency, reason, idempotency_key)

Each handler delegates to the existing ToolGateway. The gateway still enforces
customer ownership, tenant boundaries, eligibility, amount limits, idempotency,
and approval requirements. Refund execution is not exposed as an MCP tool.

## Authentication contract

Every Streamable HTTP request must include exactly one Authorization Bearer
header. The adapter calls the same authenticate_gateway_tool method used by
the existing FastAPI tool route. Missing, malformed, duplicate, invalid, or
unverifiable credentials are rejected before MCP parses or dispatches a
request. Authentication failures return a generic 401 response and do not
include token or verifier details.

In Cognito mode, only the existing delegated Gateway token profile is accepted:
RS256 signature, Cognito issuer, expiration, resource audience, configured
refund scope, subject, and the expected act.sub agent identity. The authenticated
subject, tenant, and customer values are passed to ToolGateway from verified
server-side claims. The act.sub value, already checked by CognitoJWTAuthenticator,
is recorded as the server-assigned agent ID.

In local mode, the existing opaque customer-token map is accepted for local
development only. The recorded agent ID comes from
SHADOW_HUNTER_MCP_LOCAL_AGENT_ID (default: shadow-hunter-local-agent). Local
opaque tokens must never be used for a remote or production deployment.

MCP clientInfo, prompt text, tool arguments, and arbitrary metadata are not
identity sources. The original bearer token is not passed into ToolGateway,
stored in SQLite, or included in audit details. In-memory or non-HTTP calls
have no authenticated request context and return DENY.

## AgntID credential compatibility is not yet verified

The event-specific AgntID account, proxy, agent registration, upstream target,
and credential mode have not been configured in this repository. Public AgntID
material describes pass-through and AgntID-issued credentials, but the exact
challenge runtime contract for the upstream MCP Authorization header has not
been confirmed.

Therefore, the current Cognito deployment accepts only the configured
Shadow Hunter delegated OBO token. AgntID must either pass through that token or
exchange into a token profile that satisfies the existing Cognito verifier.
If AgntID presents a different token type, this adapter deliberately rejects
it with 401. Do not weaken authentication or forward an MCP-server token to a
different downstream resource to make the connection work. Implement an
explicit verifier/credential-exchange adapter only after the event team confirms
the issuer, audience, claims, trust chain, and lifecycle of the credential.

## Local setup

Install the server and development extras:

~~~bash
python -m pip install -e ".[server,dev]"
~~~

Configure local customer tokens using the existing
SHADOW_HUNTER_CUSTOMER_TOKENS JSON environment variable, start the API, and
connect an MCP client to the endpoint above with a mapped bearer token:

~~~bash
shadow-hunter-api
~~~

The default server bind remains 127.0.0.1. The official MCP SDK's Streamable
HTTP transport is left with its localhost-only host protection. Do not expose
the endpoint through a public hostname until an explicit host allowlist, TLS,
network boundary, and AgntID upstream identity contract have been reviewed.

For Cognito operation, configure SHADOW_HUNTER_AUTH_MODE=cognito and all
required SHADOW_HUNTER_COGNITO_* settings documented in
infra/agentcore/README.md. Configure the Cognito act.sub value to the trusted
agent identity expected for this MCP route. The MCP endpoint uses the same
delegated-token audience and scope checks as the existing Gateway tool route.

## Operational behavior

- Authentication is rechecked on every HTTP request, including session and
  tool requests.
- Each tool call receives fresh request and trace IDs; the result includes
  the trace ID for the operator audit explorer.
- The SDK session manager is started by the parent FastAPI application's
  lifespan.
- The MCP server does not create AWS resources, deploy an AgntID proxy, or
  register an agent in AgntID.
- The local SQLite database and demo refund ledger remain non-production.
