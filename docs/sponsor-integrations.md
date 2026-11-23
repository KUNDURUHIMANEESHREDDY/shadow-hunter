# Opt-in Diwali Festiverse sponsor integrations

This is an implementation guide, **not evidence of live provider connectivity**.
The event's sponsor-tool integration criterion names Lyzr, AdaL, Finch, BAND
and Agent37. Shadow Hunter remains an independent AWS/AgentCore security
platform. The integration paths below do not replace the deterministic
policy gateway or AWS staging release gates.

## Vendor-specific functionality

| Sponsor | Implemented deliverable | Live status |
|---|---|---|
| Lyzr | Real v3 inference chat HTTP client; operator-only synthetic security-scenario advisory | Needs Lyzr credentials, agent ID and a real successful provider test |
| BAND | Real Agent REST message API; operator-only publication of an existing audited, redacted policy decision | Needs BAND credentials, an authorized room, and a real successful provider test |
| Finch | Locally reviewable `.agents/skills/shadow-hunter-audit-review/SKILL.md` package | Not uploaded/published/verified in Finch; user-controlled account and publisher authorization needed |
| AdaL | `docs/adal-demo-script.md` ready for manual video production | No backend API integration or video export; AdaL is a video tool |
| Agent37 | No integration: deploying a second agent cloud is not needed for the security architecture | Not configured |

### Lyzr: advisory inference

Use the exact official endpoint `POST https://agent-prod.studio.lyzr.ai/v3/inference/chat/`.
Set these process environment variables through your secret manager or protected
development environment, **never Git**:

- `SHADOW_HUNTER_LYZR_API_KEY`
- `SHADOW_HUNTER_LYZR_AGENT_ID`
- `SHADOW_HUNTER_LYZR_USER_ID` (your agent-studio user identifier)

Only an authenticated operator may call `POST /v1/operator/sponsors/lyzr/advise`
with body `{"scenario":"Synthetic policy question with no customer data"}`.
The route audits the request before the remote call, bounds response sizes and
time, rejects redirects, and labels the result `advisory_only`.
**Do not send real order notes, personal data, JWTs, provider keys, secrets,
live audit records or refund execution instructions to Lyzr.** Treat its
response as untrusted text. No Lyzr SDK/tool is given an authorization path.

### BAND: reviewed cross-agent communication

Set `SHADOW_HUNTER_BAND_API_KEY` and `SHADOW_HUNTER_BAND_CHAT_ID`.
Optionally set `SHADOW_HUNTER_BAND_MENTION_AGENT_ID` to mention an
authorized collaborating peer. BAND's documented Agent REST API is used for
`POST /api/v1/agent/chats/{chat_id}/messages` with `X-API-Key`.

An authenticated operator calls
`POST /v1/operator/sponsors/band/publish-trace` with body
`{"trace_id":"an-existing-audit-trace-id"}`.
The server reads the persisted `POLICY_DECISION` record, selects its last
decision, validates the decision and reason code, and publishes **only**
`ALLOW/DENY/ESCALATE` and a bounded reason code. Neither body nor client
can submit an arbitrary decision, message, customer ID or refund amount.
Publication is separately audited; successful HTTP delivery only means BAND
accepted the message, not that a peer acted on it. A **bounded inbound demonstration worker** is also available via:
`python -m shadow_hunter.band_worker --once` or explicitly
`python -m shadow_hunter.band_worker --forever` for fixed-room polling. Even in\n`--forever` mode, the worker defaults to **20 processed messages or 600\nseconds maximum**, whichever comes first; both limits have bounded CLI\noverrides. One process per room/identity; no auto-launch on the API server.
It uses Band's documented `GET messages/next`, claim, reply (with sender
mention), processed and failed APIs. Start it as a separate process with
both BAND and Lyzr configurations present. To request Lyzr analysis, a
peer must mention your BAND agent in the configured room and send exactly
one of `scenario:cross-tenant-read`, `scenario:oversized-refund`,
`scenario:unknown-tool`, or `scenario:approval-replay`.

This worker forwards only **checked-in, synthetic scenario descriptions** to
Lyzr; arbitrary BAND content is rejected and never executed. It is a
proof-of-integration room worker, **not** a full production BAND SDK
WebSocket listener. In particular room discovery, notification subscriptions,
reconnection, resilient concurrency, operator event correlation and live
credentialed E2E testing remain gaps. Use the official Band SDK for a
production receive/reconnect implementation.

### Finch: reusable reviewed capability

The checked-in skill is a source package for manual review and potential
Finch publication. **Listing is not automatic**: Finch's approved CLI/MCP
publication workflow requires the publisher's account/wallet/signature and
a verified package fingerprint. Do not upload unreviewed third-party scripts.
Perform the security/permission review described in `docs/skill-review.md`
and Finch's official docs first. No CLI wallet access, purchase or remote
MCP identity is used by this app.

### AdaL: demo production

AdaL currently documents a macOS-based video editor rather than a general
server-to-server runtime. The storyboard in `docs/adal-demo-script.md`
is ready for use with real screen captures, but no video or provider
authentication is claimed.

## Operator endpoints

`GET /v1/operator/sponsors/status` returns configuration flags, not keys,
account IDs, room IDs or token values. All three endpoints require a real
operator bearer token. Provider failures return sanitized 502 or 503 errors.
They do not fall back to authorizing a blocked tool.

## Test and release checklist

```bash
python -m pytest -q tests/test_sponsors.py
python -m pytest -q
python scripts/validate-repo.py
```

Mock tests verify request contracts, deny-by-default auth, redacted data,
source-bound BAND decisions, no token echo, audit and invalid outputs. They
**cannot prove** Lyzr/BAND keys, live peer receipt, Finch publication or AdaL
video export. Validate provider calls with a consented test account and
synthetic data, bounded spending, and captured trace evidence.

The pre-existing AWS gates still block production: AgentCore Harness/Gateway/
Cedar Policy live deployment, authenticated Cognito MFA and OBO end-to-end,
read-only audit archive verification and full staging security review.
See `docs/cycles/2026-11-23-agentcore-staging-gates.md` and
`docs/cycles/2026-11-23-cognito-live-auth-gate.md`.
