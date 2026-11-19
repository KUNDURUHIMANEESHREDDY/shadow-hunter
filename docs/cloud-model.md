# Cloud model configuration

## Current integration

The hourly engineering workflow runs on a GitHub-hosted Ubuntu runner and invokes the Codex CLI with an OpenAI API key. It does not use a local Windows runner and does not reuse a ChatGPT browser/session subscription.

Default model: `gpt-6.1-sol`. Override it with the repository Actions variable `SHADOW_HUNTER_MODEL`. The selected model is an OpenAI API model and API usage is billed separately from ChatGPT plan usage.

## Required GitHub configuration

Configure these in **Settings → Secrets and variables → Actions**:

| Name | Type | Value |
|---|---|---|
| `OPENAI_API_KEY` | Secret | OpenAI API project key with model inference access |
| `SHADOW_HUNTER_AUTOMATION_ENABLED` | Variable | `true` to enable scheduled/manual runs; keep `false` until ready |
| `SHADOW_HUNTER_MODEL` | Variable | Optional; defaults to `gpt-6.1-sol` |

Never commit the API key, put it in a repository variable, or paste it into chat. Rotate it immediately if it is exposed.

The workflow also uses the repository-provided `GITHUB_TOKEN` with `contents: write` to push verified cycle commits to `main`. Checkout disables persisted credentials; the wrapper removes GitHub credentials from the model process and only injects the token for the final Git push.

## Enable only when ready

1. Create an OpenAI API key in the OpenAI Platform and confirm the project has billing/usage access.
2. Add it as the `OPENAI_API_KEY` Actions secret.
3. Set `SHADOW_HUNTER_AUTOMATION_ENABLED` to `true`.
4. Optionally set `SHADOW_HUNTER_MODEL`; the default is `gpt-6.1-sol`.
5. Trigger **Actions → Shadow Hunter hourly engineering cycle → Run workflow** for a manual run.

A ChatGPT subscription does not automatically fund API requests. If the OpenAI API project has no billing/usage access, model execution will fail closed before starting a cycle.

## Runtime boundaries

- GitHub-hosted Ubuntu standard runners keep the workload off the user's laptop.
- Each cycle has a 30-minute timeout; the hourly schedule is not one continuous 24-hour process.
- The workflow remains gated by `SHADOW_HUNTER_AUTOMATION_ENABLED` and the 28 November 2026 UTC deadline.
- The agent is instructed to implement one bounded task. The wrapper retains its protected-path, secret-pattern, verification, and no-force-push gates.
- The agent must not create paid AWS resources, change secrets, or alter the workflow and its own execution controls.
- Public repository visibility does not make Actions secrets public, but all committed source and Git history are public. Never commit credentials or private data.

## Important limitation

This config uses an OpenAI API model through Codex CLI. It is not the same thing as remotely invoking the exact GPT-6 instance serving this ChatGPT conversation. ChatGPT session context, internal runtime, and subscription entitlements are not exposed as a reusable endpoint to GitHub Actions.
