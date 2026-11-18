---
name: shadow-hunter-cycle
description: Run one bounded Shadow Hunter engineering cycle: inspect repository state, select one priority, implement and verify a vertical slice, update evidence, and hand off blockers.
---

# Shadow Hunter engineering cycle

1. Read AGENTS.md, README.md, docs/engineering-cycle.md, docs/threat-model.md, and recent cycle records.
2. Inspect git status, latest commits, workflow/test status, issues and current implementation.
3. Select one high-priority, non-duplicate task with explicit acceptance criteria.
4. Delegate independent architecture, AWS, policy, security or evaluation work to the matching Codex subagent. Keep ownership boundaries clear.
5. Implement one vertical slice and add tests.
6. Run focused tests, full relevant suite, lint/type/build, secret scanning and diff checks.
7. Reject unverified claims, test weakening, secrets, unapproved spend and changes to workflow/runner/policy permissions.
8. Update README build status and append an evidence-backed cycle record.
9. Primary orchestrator commits and pushes to main only after verification. Subagents never commit or push.
10. Stop before the 30-minute limit. Record blockers rather than making unsupported changes.
