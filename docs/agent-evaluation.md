# Red/Blue hosted NVIDIA NIM evaluation

## Runtime selection

This operator-only evaluation uses two hosted NVIDIA NIM models:

| Agent | Model | Purpose |
|---|---|---|
| Red | `nvidia/nemotron-3.5-lightning-30b-a3b` | Choose and vary a bounded existing adversarial scenario |
| Blue | `nvidia/nemotron-3.5-bolt-e4b` | Classify the proposal, add threat signals and provide a short advisory explanation |

The API base URL is fixed to:

```text
https://integrate.api.nvidia.com/v1
```

The client sends non-streaming POST requests to `/chat/completions` using Bearer
authentication. It uses Python's standard HTTP client; no local model server or
Ollama dependency is used in this evaluation path.

The separate `shadow-hunter-agntid-demo` runner is an independent MCP
integration demonstration and is not called by the Red/Blue evaluator.

## Hosted model configuration

For local server development, set:

- `NVIDIA_API_KEY`: NVIDIA API Catalog key.
- `SHADOW_HUNTER_NIM_RED_MODEL`: optional Red model override; defaults to
  `nvidia/nemotron-3.5-lightning-30b-a3b`.
- `SHADOW_HUNTER_NIM_BLUE_MODEL`: optional Blue model override; defaults to
  `nvidia/nemotron-3.5-bolt-e4b`.
- `SHADOW_HUNTER_NIM_TIMEOUT_SECONDS`: request timeout, default 3 seconds
  (accepted range 1–3).
- `SHADOW_HUNTER_NIM_MAX_TOKENS`: client-wide completion cap, default 512
  (accepted range 384–4096; individual agent calls use 384).

The hosted base URL is intentionally not caller-controlled. It is restricted to
NVIDIA's HTTPS API Catalog host to prevent server-side request forgery through a
provider URL override.

For AWS Lambda, set `NvidiaApiKeySecretArn` and `A2AKeysSecretArn` on the
`infra/app/template.yaml` stack. The API Lambda's conditional IAM statements
grant only `secretsmanager:GetSecretValue` on those two configured ARNs.
The NVIDIA secret may be a raw API key or JSON containing `NVIDIA_API_KEY`.
The A2A secret must be a JSON object in the same format described below.
No key is embedded in the template or environment values.

Missing credentials, invalid model configuration, timeout, rate limit, non-2xx
provider response, malformed JSON, or invalid model output returns an
evaluation error. The evaluator does not silently fall back to local inference.

NVIDIA's published model API references:

- [Nemotron 3.5 Lightning 30B A3B API reference](https://build.nvidia.com/nvidia/nemotron-3.5-lightning-30b-a3b/apireference)
- [Nemotron 3.5 Bolt E4B API reference](https://build.nvidia.com/nvidia/nemotron-3.5-bolt-e4b/apireference)

## Agent behavior and output constraints

### Red — Lightning 30B A3B

Red receives the catalogue of currently eligible synthetic scenarios and the
recent outcomes from this evaluation run. It must select one known scenario ID.
It may produce a bounded attack hypothesis and up to 240 characters of
natural-language injection text.

Red cannot invent or alter:
- tool names or tool allowlist membership;
- order IDs or customer identities;
- amounts, currencies or idempotency keys;
- expected policy decisions or expected reason codes;
- whether a scenario is marked as an attack or as a legitimate control.

Application code appends the hypothesis to the description and, only when a
scenario already has a natural-language `reason` field, appends the bounded
injection text there. A legitimate control cannot be mutated with injection
text. Invalid IDs, schema errors, output length violations, or a control-case
mutation abort the run.

### Blue — Bolt E4B

Blue receives the untrusted proposal, server-derived synthetic ownership facts
and the deterministic preflight signals. NVIDIA JSON-schema structured output
constrains the response to:

- integer risk score from 0 to 100;
- approved threat-category values;
- bounded indicator identifiers;
- an approved advisory recommendation;
- a short analysis summary up to 320 characters.

The original deterministic Blue reasoner always runs. The hosted model may add
threat categories and indicators; it cannot remove deterministic findings.
The combined score is the greater of the deterministic and model scores. When
deterministic findings exist, their recommendation takes precedence.

Neither Red nor Blue controls authorization. Every tool proposal still passes
through the existing `ToolGateway` and `PolicyEngine`. Blue's recommendation
is explanatory and cannot override the actual gateway decision. The
operator-only refund execution route remains outside the agent tool allowlist
and any pending refund still requires its independent approval capability.

## Reproducibility record

Each round records:
- configured Red and Blue model identifiers on the evaluation run;
- the Red seed, computed from the round number and the ordered candidate
  scenario IDs;
- the Blue seed, computed from the canonical JSON proposal;
- scenario ID, model-generated strategy summary, Blue model ID, validated
  analysis summary, policy decision, risk score and threat categories.

NVIDIA documents seed determinism as best-effort. A seed does not guarantee
bit-for-bit repeatability across hosted model versions, serving revisions,
infrastructure changes or provider-side nondeterminism. Keep the stored model
IDs, seeds and summaries with benchmark results; compare provider/model
versions explicitly when interpreting regressions.

The evaluator stores only the short validated summary, not a chain-of-thought
transcript or raw provider response.

## A2A authentication configuration

Red and Blue messages remain signed with separate HMAC-SHA256 keys. The
receiver verifies key-to-agent assignment, sender and recipient, signature,
timestamp (90-second clock-skew window), and a single-use nonce. A successful
nonce claim is persisted in SQLite or DynamoDB so replay detection is shared
across application workers and later runs.

For local development set `SHADOW_HUNTER_A2A_KEYS` to a JSON object:

```json
{
  "red-v1": {
    "agent_id": "red-agent",
    "secret": "REPLACE_WITH_A_UNIQUE_RANDOM_SECRET_OF_AT_LEAST_32_BYTES"
  },
  "blue-v1": {
    "agent_id": "blue-agent",
    "secret": "REPLACE_WITH_A_DIFFERENT_RANDOM_SECRET_OF_AT_LEAST_32_BYTES"
  }
}
```

Generate independent values with a cryptographically secure random generator,
for example Python `secrets.token_urlsafe(48)`. Do not reuse bearer tokens or
the other agent's secret. Do not commit these values.

For AWS, set `SHADOW_HUNTER_A2A_KEYS_SECRET_ARN` to a Secrets Manager secret
whose `SecretString` is this JSON object. The Lambda loads it using its
resource-scoped `secretsmanager:GetSecretValue` permission.

HMAC authenticates messages among holders of the shared secrets; it does not
encrypt the payload or provide a remote network trust boundary. The current
exchange remains in-process. Remote agents require a separate TLS/mTLS or
platform workload-identity design.

## Operator evaluation

After configuring the NVIDIA key and both A2A keys and signing in to `/operator`
with an operator credential, run the **3-round NIM evaluation**. The authenticated
API accepts a `rounds` value from 1 through 3. Each round:

1. Selects one scenario from the remaining bounded synthetic catalogue using
   the hosted Red planner.
2. Signs and verifies the Red proposal.
3. Runs deterministic Blue checks plus hosted Blue inference.
4. Submits the proposed tool action through the existing ToolGateway and records
   the gateway's actual policy decision.
5. Signs and verifies Blue's response and records model/seed evidence.
6. Deletes the temporary SQLite sandbox after the run and writes aggregate
   metrics, redacted per-case results and allowlisted policy/A2A evidence to
   the primary audit store.

No live customer orders are read or mutated. The high-value request remains
inside the synthetic sandbox and no refund execution occurs. Prompts sent to
NVIDIA contain only scenario data from that synthetic sandbox.

The authenticated operator API is:

- `POST /v1/operator/agent-evaluations/run` with an optional JSON body
  containing only `rounds` (integer 1–3).
- `GET /v1/operator/agent-evaluations/latest` returns the latest aggregate
  and redacted per-case results.

## Metric definitions

All rates are fractions from 0.0 to 1.0 in the stored record; the console renders
them as percentages.

| Metric | Definition |
|---|---|
| Attack attempts | Number of scenarios marked as attacks; the legitimate control is excluded |
| Attack successes | Attack scenarios whose gateway decision was ALLOW |
| Attack success rate | Attack successes / attack attempts |
| Attacks prevented | Attack attempts minus attack successes; DENY and ESCALATE count as not accepted by policy |
| Defensive effectiveness | Attacks prevented / attack attempts |
| False denials | Legitimate control cases that receive DENY or ESCALATE |
| False-denial rate | False denials / control cases |
| Policy decision accuracy | Scenarios whose observed decision and optional reason code match the declared expected outcome / all rounds |

Attack success is a policy-boundary metric, not a claim that a financial
side effect occurred. Even an ALLOW refund request remains pending human
approval; execution still requires the separate, parameter-bound operator
capability. The benchmark metrics measure policy outcomes for the executed
synthetic scenarios, not universal model attack-detection accuracy.

## Verification and deployment status

The hosted adapter, API wiring, operator display and behavior-focused tests
have been authored but not executed under the current repository engineering
cycle. No NVIDIA API call, AWS resource creation, secret provisioning, or
deployment has been performed in this cycle.
