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
- `SHADOW_HUNTER_NIM_TIMEOUT_SECONDS`: per-request timeout ceiling, default
  8 seconds (accepted range 1–12). The synchronous evaluation route divides a
  24-second provider-call budget across two sequential NIM calls per requested
  round. That yields a 4-second cap per call at three rounds, 6 seconds at two
  rounds, or the configured ceiling for one round. Four seconds remain in the
  28-second Lambda timeout for local sandbox, policy, and audit work.
- `SHADOW_HUNTER_NIM_MAX_TOKENS`: client-wide completion cap, default 512
  (accepted range 384–4096; individual agent calls use 384).

The hosted base URL is intentionally not caller-controlled. It is restricted to
NVIDIA's HTTPS API Catalog host to prevent server-side request forgery through a
provider URL override.

Both agents request compact structured answers with `enable_thinking=false`.
Red additionally sends a strict JSON schema whose scenario ID enum is built from
the supplied candidate catalogue. This prevents internal reasoning tokens from
consuming the limited completion budget and reduces free-form schema drift. The
deterministic Blue checks and the ToolGateway remain authoritative.

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

Verification performed locally on 20 November 2026:

- Focused command:
  `python -m pytest tests/test_nim.py tests/test_agents.py tests/test_gateway.py tests/test_agent_evaluation_store.py -q`
  — **37 passed**.
- Full command: `python -m pytest -q` — **112 passed, 2 failed**. The failures
  are outside the Red/Blue change: the AgentCore session-ID test expects an
  error-message phrase the current implementation does not emit, and the
  Lambda entrypoint test cannot import the optional `mangum` dependency,
  which is not installed in this local environment.
- `python -m compileall -q src/shadow_hunter tests` — passed.
- `git diff --check` — passed.
- A one-round Red/Blue-to-gateway adapter integration test passed in the
  focused suite using stubbed NIM clients.
- A three-round local synthetic contract run also used stubbed NIM responses:
  two attacks were denied, one legitimate own-order read was allowed, no
  refunds were executed, and all three expected decisions matched. Metrics:
  attack success 0/2, defensive effectiveness 2/2, false-denial rate 0/1,
  and policy decision accuracy 3/3. This proves the local harness path only;
  it is not evidence of hosted model quality or provider latency.

A live NVIDIA evaluation was not possible. Presence-only checks found no
NVIDIA API key/secret ARN, A2A signing-key configuration, or operator token
in the connected process environment, and no local API server was listening
on port 8000. No `.env` or credential file was opened, no secret values were
read or requested, and no NVIDIA request or AWS operation was made. The next
verification step remains a credentialed one-round hosted call followed by
the three-round hosted evaluation.


## Independent evidence verification and reproducible local harness (23 November 2026)

Every `RedBlueSimulation.run` now verifies a round **after** the actual
`ToolGateway` decision is written, before returning an observation or
counting it toward evaluation metrics. The verifier checks:

- exactly one persisted gateway `POLICY_DECISION` per correlated proposal;
- exactly two Red/Blue `A2A_MESSAGE_SENT` events and one authenticated
  `A2A_MESSAGE_RECEIVED`, with expected senders, recipients, message IDs and
  key references;
- the trusted principal, gateway tool name, decision, reason and policy
  provenance match the Red/Blue outcome;
- the independently recorded `A2A_EVALUATION` agrees with the actual gateway
  decision, scenario and round;
- no execution event for a refund appears within the test trace.

Missing, conflicting or duplicate evidence fails the run closed. Successfully
verified rounds produce an `A2A_EVIDENCE_VERIFIED` event and a SHA-256 digest
over a canonical **semantic** proof excluding UUIDs, timestamps, signatures,
tokens and other secrets. These checks establish **consistency of locally
recorded A2A and gateway evidence**, not external log immutability or hosted
model correctness.

The operator dashboard displays `Verified audit · <12 hex characters>` for
results that carry a valid 64-hex-character independently recorded digest.
Otherwise, it shows `Not independently verified`. Hosted-model evaluations
include the number of verified rounds, with details copied from the disposable
synthetic sandbox into the operator audit history.

### Run reproducible local security evaluation

```sh
python scripts/run_red_blue_synthetic.py --rounds 8 --output artifacts/red-blue-evaluation.json
python scripts/run_red_blue_synthetic.py --rounds 8 --output artifacts/red-blue-evaluation-repeat.json
cmp artifacts/red-blue-evaluation.json artifacts/red-blue-evaluation-repeat.json
```

This exercise uses real policy and signed A2A logic, isolated SQLite synthetic
orders, random ephemeral HMAC keys, and the deterministic strategy/defense
reasoners. It does **not** contact AWS, NVIDIA, Lyzr, BAND or any real customer
system. The report records the scenario catalogue digest, per-round semantic
audit digests, metrics, actual/expected decisions, and the no-refund-execution
invariant. It deliberately marks `hosted_model_used: false` and
`hosted_model_verified: false`.

GitHub Actions runs the 8-round synthetic evaluation twice, compares the JSON
files byte for byte, and uploads the redacted report as
`shadow-hunter-red-blue-evidence`. Browser tests independently check that
verification labels are rendered safely.

### Still outstanding

A credentialed NVIDIA Red/Blue inference evaluation with genuinely separate
hosted models remains a separate release gate. The local deterministic
evaluation is a **reproducible policy-safety regression**, not a substitute
for measured hosted agent quality. A separate immutable audit archive or
hardware-backed identity check is also needed before claiming external
independent security attestation.


### Explicit opt-in hosted-model smoke run

The new `scripts/run_red_blue_hosted.py` is an operator-run smoke harness for
**actual NVIDIA model calls**. It is not part of default CI because calls may
incur provider charges and need an NVIDIA key. The CLI fails closed unless
both `--allow-provider-calls` and a locally supplied `NVIDIA_API_KEY` are
present. No AWS credentials, production customer data or payment provider
are involved.

```sh
# Configure NVIDIA_API_KEY securely in the process environment first.
python scripts/run_red_blue_hosted.py --allow-provider-calls \
  --rounds 1 --output artifacts/red-blue-hosted.json
```

It calls the distinct configured Red and Blue NIM models (two hosted inference
requests per round, up to three rounds), validates their structured output,
runs the proposed synthetic action through the real deterministic policy
gateway, verifies signed A2A audit evidence independently, and writes
redacted policy decisions, model IDs, seeds, metrics and digest receipts.
No prompt, provider API key, token, A2A secret, real customer identifier
or raw provider response is stored.

**Provider call status:** Unit tests use a fake NIM client to verify the
contract without external requests. Those tests alone do **not** prove a
live NVIDIA connection, nor a hosted security-performance advantage.
A successful explicit hosted run and evaluation of its metrics is necessary
before claiming model-assisted Red/Blue validation.


### Manual GitHub-hosted NIM smoke

For laptop-independent verification, the repository includes
`.github/workflows/red-blue-hosted-smoke.yml`, a **manual-only** GitHub Actions
workflow. Set the repository Actions secret `NVIDIA_API_KEY` through GitHub
Settings (never paste it into a workflow input, commit, issue or chat).
Then go to Actions → **Hosted Red-Blue model smoke (manual only)** →
**Run workflow**. Explicitly confirm provider calls and select 1–3 rounds.

The job is skipped without confirmation, checks for a configured NVIDIA
secret before sending any request, uses only synthetic local orders, and
uploads a short-lived redacted report. It does not run on pushes or PRs.
Provider usage may incur charges. No manual hosted workflow has been invoked
as part of the normal development CI.


### Hosted staging benchmark acceptance gate

The separate authenticated staging benchmark,
`scripts/benchmark_hosted_red_blue.py`, must now confirm that the
`AGENT_EVALUATION_RUN` audit record reports the requested number of
independently verified rounds, that each `AGENT_EVALUATION_RESULT` matches
its API row, and that each row has a corresponding redacted
`A2A_EVIDENCE_VERIFIED` receipt copied as
`AGENT_EVALUATION_TRACE_EVENT`. Missing, forged, duplicated or mismatched
SHA-256 receipts fail the benchmark instead of counting as a model success.

Staging audit indexes may be eventually consistent, so the benchmark retries
a still-incomplete trace up to three bounded times. It does not accept any
partial result or relax verification when a retry expires. This is a
**local-to-staging gateway audit consistency gate**, not a claim of an
externally independent or immutable audit store.
