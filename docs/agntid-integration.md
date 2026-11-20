# AgntID MCP integration and live-agent runbook

## Integration boundary

Shadow Hunter exposes three MCP tools through its existing ToolGateway:
`get_order`, `check_refund_eligibility`, and `create_refund_request`.
Refund execution remains operator-only and is not exposed to the agent.

AgntID describes per-call authorization in the MCP execution path. Its public
FAQ says it can coexist with an MCP gateway, supports pass-through credentials,
and keeps backend user-level authorization in place. Its Kubernetes pattern
uses an embedded proxy in the agent pod.

Public references:
- https://agntid.ai/
- https://agntid.ai/faq
- https://agntid.ai/blog/mcp-server-authentication
- https://agntid.ai/blog/mcp-gateway-vs-embedded-proxy

The public material does not publish the challenge workspace's proxy image,
install values, sidecar port, broker-token claim schema, or denial headers.
Obtain these from your workspace; this repo does not guess them.

## Identity modes

Set `SHADOW_HUNTER_MCP_AUTH_PROFILE=customer` for Cognito customer-token
pass-through. Shadow Hunter still verifies the original access token's RS256
signature, issuer, expiry, customer app client, customer scope, subject, and
trusted tenant/customer claims. `SHADOW_HUNTER_MCP_AGENT_ID` is only a
server-side attribution label; it does not prove agent identity.

The default `gateway` profile retains the existing delegated OBO checks:
Cognito issuer, RS256 signature, expiry, target audience, refund scope,
subject, and expected `act.sub`. Do not disable JWT checks or trust MCP
client metadata as identity.

## Deploy the internal upstream MCP service

Build/publish an image and replace the tag in the deployment manifest:

~~~bash
docker build -t ghcr.io/KUNDURUHIMANEESHREDDY/shadow-hunter:demo .
docker push ghcr.io/KUNDURUHIMANEESHREDDY/shadow-hunter:demo
~~~

Create the Cognito secret with real test-pool values (never commit the values):

~~~bash
kubectl create secret generic shadow-hunter-cognito \
  --from-literal=SHADOW_HUNTER_COGNITO_ISSUER='https://cognito-idp.REGION.amazonaws.com/POOL_ID' \
  --from-literal=SHADOW_HUNTER_COGNITO_CUSTOMER_CLIENT_ID='CUSTOMER_APP_CLIENT_ID' \
  --from-literal=SHADOW_HUNTER_COGNITO_CUSTOMER_SCOPE='shadow-hunter/customer' \
  --from-literal=SHADOW_HUNTER_COGNITO_TOOL_AUDIENCE='REGISTERED_RESOURCE_AUDIENCE' \
  --from-literal=SHADOW_HUNTER_COGNITO_TOOL_SCOPE='shadow-hunter-api/refunds' \
  --from-literal=SHADOW_HUNTER_COGNITO_ACTOR_SUB='EXPECTED_DELEGATED_AGENT_SUB'
~~~

The shared Cognito authenticator still requires the OBO config values above
even when this MCP route selects customer pass-through. The service uses an
ephemeral SQLite sandbox. Its demo order is seeded with tenant `demo-tenant`
and customer `demo-customer`; the test user's trusted claims must match.
Seed through the existing authenticated operator endpoint:

~~~bash
curl -X POST "$SHADOW_HUNTER_API_URL/v1/operator/demo/seed" \
  -H "Authorization: Bearer $SHADOW_HUNTER_OPERATOR_TOKEN"
~~~

Apply the internal ClusterIP service:

~~~bash
kubectl apply -f infra/kubernetes/shadow-hunter-mcp.yaml
kubectl rollout status deployment/shadow-hunter-mcp
~~~

## Configure AgntID

Register the agent and embedded proxy using the actual AgntID workspace
instructions. Add the Shadow Hunter upstream MCP server:

~~~text
http://shadow-hunter-mcp.default.svc.cluster.local:8000/
~~~

Configure task intent to allow `get_order` and
`check_refund_eligibility`, and deny `create_refund_request`. Configure
the proxy to pass through the original Cognito customer access token where
supported and forward `X-Shadow-Hunter-Demo-ID` if custom header forwarding
is supported. The exact sidecar image/port/local proxy URL must come from
the workspace; do not guess them.

## Run the real Ollama agent

~~~bash
python -m pip install -e ".[server]"
export AGNTID_MCP_URL='THE_PROXY_MCP_URL_FROM_YOUR_WORKSPACE'
export AGNTID_MCP_HEADERS_JSON='{"Authorization":"Bearer YOUR_COGNITO_CUSTOMER_ACCESS_TOKEN"}'
export AGNTID_DEMO_SANDBOX=true
export AGNTID_DEMO_ORDER_ID=order-demo-001
export OLLAMA_BASE_URL=http://127.0.0.1:11434
export OLLAMA_MODEL='qwen3.5:4b'
shadow-hunter-agntid-demo --output agntid-demo-evidence.json
~~~

The runner gives Ollama only two read-tool schemas and requires at least one
successful ALLOW. It then sends a separate `create_refund_request` probe
through the same AgntID proxy. It is restricted to an `order-demo-*` record,
one minor unit and a unique idempotency key. It cannot execute a refund.
On PowerShell use `$env:NAME = 'value'` instead of `export NAME=value`.

The runner also sends a UUID `X-Shadow-Hunter-Demo-ID` correlation header.
If AgntID forwards it, backend trace IDs share the report's run ID; otherwise
the report records individual tool trace IDs.

## Evidence interpretation

- `AGNTID_DENIED`: only when a configured AgntID decision header explicitly
  says DENY/BLOCK/BLOCKED.
- `SHADOW_HUNTER_BACKEND_DENIED`: the call reached Shadow Hunter and its
  policy denied it. This is not proof of AgntID blocking.
- `AGNTID_DID_NOT_BLOCK`: the write probe reached the backend with ALLOW
  or ESCALATE; it can create only a pending sandbox approval.
- `MCP_ERROR_UNATTRIBUTED`: no AgntID decision header or backend trace
  identifies the source; confirm it in AgntID's per-call audit view.

Configure `AGNTID_DECISION_HEADER` and `AGNTID_TRACE_HEADER` only with
the exact names supplied by the workspace. The runner reads only these
headers, never all response headers or credentials. A successful demo needs
an ALLOW read with Shadow Hunter trace evidence and a separate AgntID DENY
event with an AgntID trace/evidence ID. Backend DENY or generic MCP error
does not prove AgntID enforcement.

This commit prepares the application and demo runner; it does not register
the AgntID account, deploy a cluster, create AWS resources, or run the model.
Those steps need workspace values, cluster access, a Cognito test token,
the sandbox seed, and Ollama reachable from the runner host.
