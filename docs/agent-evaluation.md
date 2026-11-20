# Red/Blue agent evaluation runtime

## Runtime boundary

The first autonomous Red/Blue runtime is deterministic and provider-independent.
It does not invoke a local Ollama model, a paid API, Amazon Bedrock, or any other
LLM. The strategy planner and defense reasoner are inspectable Python components.

The Red Agent chooses from a bounded strategy pool: cross-customer access,
operator-only tool invocation, prompt-injected over-refund, policy-argument
tampering, currency substitution, type confusion, high-value approval boundary,
and a legitimate control. It records observations and raises the priority of a
strategy family if a future round shows that a malicious proposal received ALLOW.

The Blue Agent classifies proposal signals and emits a heuristic risk score,
threat categories, indicators, and a recommended handling action. Its output
is explanatory. Blue does not grant permissions and cannot bypass the gateway:
every proposal still reaches the existing ToolGateway and PolicyEngine. The
operator-only refund execution operation is not part of the agent tool allowlist.

## A2A authentication configuration

The message envelope uses HMAC-SHA256 with separate keys for Red and Blue.
The receiver verifies key-to-agent assignment, sender and recipient, signature,
timestamp (90-second clock-skew window), and nonce. A successful nonce claim is
persisted in the configured SQLite or DynamoDB store so a message cannot be
replayed across workers or subsequent evaluation runs.

Set the server environment variable SHADOW_HUNTER_A2A_KEYS to a JSON object:

\`\`\`json
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
\`\`\`

Generate two independent values with a cryptographically secure random generator,
for example Python secrets.token_urlsafe(48). Do not reuse the customer/operator
bearer tokens, do not use the same secret for both agents, and do not commit the
values to source control. Configure them in the local process environment for
development and in a managed secret facility before any hosted deployment.
The key IDs shown above must map to exactly one key each for red-agent and
blue-agent. The API rejects missing or malformed configuration; it does not
silently fall back to unsigned messages.

HMAC authenticates messages among processes that share a secret, but it does not
encrypt the payload or provide forward secrecy. This milestone still uses an
in-process transport. Do not expose this protocol directly to an untrusted
network; a remote deployment requires TLS/mTLS or platform workload identity,
network authorization, rate limits, and independent transport review.

## Operator evaluation

After configuring both A2A keys and signing in to /operator with an operator
credential, use **Run 8-round evaluation**. The API accepts a bounded rounds
value from 1 through 20. Each run:

1. Creates a temporary SQLite database.
2. Seeds synthetic own-customer and foreign-customer orders.
3. Runs Red proposals through signed A2A envelopes to Blue.
4. Verifies Blue's signed response and records the gateway policy decision.
5. Deletes the temporary database and writes aggregate metrics, redacted case
   results, and allowlisted A2A/policy trace metadata into the primary audit store.
   The trace metadata omits message payloads, signatures, HMAC secrets, and tokens.

The main order/refund tables are not used for the evaluation workload. Persistent
A2A nonce records and redacted evaluation audit events are written to the primary
store. Refunds created by the high-value test remain in the temporary sandbox
and are never executed.

The authenticated operator API is:

- POST /v1/operator/agent-evaluations/run with an optional JSON body containing
  only rounds.
- GET /v1/operator/agent-evaluations/latest returns the latest aggregate and
  its per-case redacted results.

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

Attack success is a policy-boundary metric, not a claim that a financial side effect
occurred. Even an ALLOW refund request remains pending human approval; execution
still requires the separate, parameter-bound operator capability.

Blue's risk score is a deterministic heuristic signal. It is not a calibrated
probability, a universal prompt-injection detector, or an independent authorization
decision. Evaluation results are evidence for the tested synthetic scenarios only;
they must not be generalized to production attack coverage without broader tests.

## Verification and deployment status

The code and behavior-focused tests have been authored but not executed under the
current repository engineering-cycle instruction. No model runtime or AWS resource
was deployed by this feature.
