# Hourly engineering cycle

## Contract

- Cadence: hourly, at minute 7 (UTC).
- Maximum job duration: 30 minutes.
- Target: 24 runs/day for 10 days (up to 240 runs).
- Concurrency: one run at a time.
- Default state: DISABLED until the OpenAI API key, model access, billing controls, and branch protection are configured.
- Compute: GitHub-hosted Ubuntu runner; the user's PC is not required.
- Model: Codex CLI using the OpenAI API; default model is `gpt-6.1-sol`.
- Setup: see [cloud model configuration](cloud-model.md).
- Deadline guard: stop new cycles after 28 November 2026 UTC.
- No overlapping catch-up runs after a missed tick.

## Per-cycle sequence

1. Read README status, engineering log, Git status, recent commits, issues, and CI/test results.
2. Pick one highest-priority non-duplicate task.
3. State acceptance criteria before changing files.
4. Implement a narrow vertical slice.
5. Run the relevant test suite, security checks, and `git diff --check`.
6. Inspect the full diff and scan for secrets or out-of-scope changes.
7. If checks pass, update README and append a cycle record.
8. Commit/push to main only when the verification gate succeeds.
9. If blocked, write the exact blocker, evidence, and required human action; do not create a false success commit.

## Cycle record

Each record must include run ID, timestamp, task ID, files changed, tests executed and results, security checks, commit SHA, push status, outstanding blockers, and next task.

## Safety stops

Stop without committing if:
- Codex/model auth is missing or quota is exhausted.
- The cost/time budget is exceeded.
- Any secret or suspicious credential is detected.
- Main branch has unexpected concurrent changes or a non-fast-forward update.
- Tests fail or cannot be run when required by the task.
- A task requires AWS resource creation/paid services not authorized by the current budget.
- The agent attempts to alter its own workflow, policy, secrets, spending cap, or permissions.

## Reality of scheduling

GitHub scheduled workflows are not a real-time scheduler: runs may be delayed or dropped during high load. A 30-minute timeout limits a run but does not guarantee it will use exactly 30 minutes. The GitHub-hosted runner is independent of the user's PC. OpenAI API usage quotas/costs are separate from GitHub Actions compute. This hourly workflow is not a single continuous 24-hour process.
