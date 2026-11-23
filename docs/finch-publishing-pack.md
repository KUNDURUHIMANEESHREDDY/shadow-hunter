# Finch submission readiness — Shadow Hunter audit-review skill

**Prepared, not published.** This is the human-readable listing copy and
security checklist for the versioned skill package in
`.agents/skills/shadow-hunter-audit-review/`.

## Listing draft

**Name:** Shadow Hunter — Auditable Agent Decision Review

**Summary:** Review sanitized AI-agent policy decisions and identify whether a
recorded action was allowed, denied, or escalated. Designed for incident review
and evidence summaries without granting any model the authority to execute
external tools.

**What's included:** SKILL.md, MIT LICENSE, trust-boundary instructions,
restricted output format, audit evidence review workflow.

**Permissions:** No network, shell, transaction, wallet, environment-secret
reads, external tool invocation, or customer data access required for the
skill itself.

**Limitations:** Not a policy engine, doesn't independently validate AWS
infrastructure, can't guarantee absence of model hallucination, and cannot
approve or perform refunds.

**Proof to collect before publication:**
- Compare tracked package contents with the reviewed Git commit.
- Scan the skill files with the checked-in skill-scanner.
- Run synthetic prompt-injection tests (untrusted text never becomes policy).
- Verify public listing accurately describes read-only capabilities.
- Use Finch's authorized account publishing interface. Do not disclose
  secret keys, tokens, or private customer data.
- Confirm the resulting listing and version from Finch itself before
  describing it as published.

No marketplace signing, billing, trading, or spending action is automated.
