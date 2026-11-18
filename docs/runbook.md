# Operations runbook

## Kill switch

Set repository variable `SHADOW_HUNTER_AUTOMATION_ENABLED` to `false` to stop the agent cycle. Disable the scheduled workflow or cancel active runs for urgent containment. Do not rely on a model prompt as a kill switch.

## Before enabling unattended cycles

- Confirm private repository visibility and trusted write collaborators.
- Register a dedicated self-hosted runner with the `shadow-hunter` label.
- Verify the runner executes as a dedicated restricted Windows account, not an administrator.
- Verify runner access is limited to the project workspace and required toolchain.
- Confirm Codex CLI authentication persists in the runner identity.
- Set a model usage limit or provider-level spending limit.
- Set strict max runtime, model calls, tool calls, retries and per-day cycle count.
- Ensure the agent cannot read local secrets or edit runner configuration.
- Verify workflow only runs on schedule/workflow_dispatch and never on fork PRs.
- Run a manual non-mutating dry run before enabling writes and pushes.
- Confirm commits are pushed to main only after the automated verification gate.

## Incident response

1. Disable the automation variable and cancel any active run.
2. Revoke or rotate compromised credentials using the provider's official process.
3. Inspect the last cycle record, commit, workflow logs and changed files.
4. Determine whether the model, runner, tool, policy, or credential boundary failed.
5. Revert safely using a reviewed commit; do not force-push.
6. Add a regression test and re-run the adversarial case before re-enabling.

## Recovery

- Restore from the latest known-good Git commit and documented infrastructure state.
- Re-run data and audit integrity checks.
- Do not replay refund side effects without inspecting idempotency state.
