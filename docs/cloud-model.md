# Model execution

Shadow Hunter no longer has an unattended cloud runner or a model API integration configured.

## Current operating model

- Code changes are authored by the assistant in an active ChatGPT conversation.
- Repository updates are made directly to `main` through the connected GitHub integration.
- This does not expose the current ChatGPT model session as a reusable API endpoint.
- No Codex CLI, self-hosted runner, GitHub Actions runner, or OpenAI API key is required for this interactive workflow.
- No tests, builds, lint, or verification commands are run under the current owner instruction.

## Automation limitation

ChatGPT task automations support daily, weekly, and monthly recurring schedules; hourly recurring schedules are not supported. A daily automation can start one assistant task, but cannot guarantee 30 minutes of coding every hour or 24 runs per day.

The exact GPT-6 model serving this conversation cannot be kept alive as a continuous background process. Any future external model runtime would be a separate integration and must not be described as this exact ChatGPT session.

## Security

Never commit API keys, access tokens, local authentication files, or customer data. If a future model provider is integrated, credentials must be stored in an appropriate secret manager and provider usage/billing must be explicitly approved.
