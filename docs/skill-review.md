# Agent skill review — 18 November 2026

## Installed skill inventory

| Skill | Source revision | Scanner result | Handling |
|---|---|---:|---|
| agent-safety | ericrisco/rsc-harness v4.1.8 / resolved 28a51a91 | 0 findings | Committed with original MIT license |
| skill-scanner | getsentry/skills a582c51ee29d0f35e6ac321340796f77d43da733 | 36 pattern findings | Manually inspected; committed with Apache-2.0 license |
| testing | Mindrally/skills v1.0.0 / 7682ca77710e0971eab4e0ae5dddfa281aea0ba5 | 0 findings | Committed with Apache-2.0 license |
| llm-security | semgrep/skills 68177b8830f96cd9d10dacbb14dde2566360503d | 0 findings | Local only; excluded pending license review |

## Manual review notes

- `agent-safety`: instructions focus on least agency, deny-by-default tool access, external-content isolation, risk-based human approval, and runtime/cost caps. It has a threat-model reference and no bundled executable scripts.
- `testing`: a general testing guidance skill with no bundled scripts.
- `skill-scanner`: the 36 scanner matches are mostly expected self-matches. Its reference files intentionally document malicious prompt-injection, Base64, and dangerous-code examples; its own scanner patterns naturally match these examples. The bundled Python script was inspected across all 674 lines: it reads the target skill files, parses YAML/regex/URLs, and emits JSON; no network access or write/command execution behavior was found in the script.
- `llm-security`: the scanner reported no findings. It labels OWASP, MITRE and NIST URLs as outside its small trusted-domain allowlist; that is an allowlist limitation, not proof those domains are malicious. The Semgrep repository exposes a custom rules license rather than a conventional SPDX license, so this skill remains untracked pending legal review.

## Scanner limitations

A clean result does not prove a skill is safe. The scanner is pattern-based and can miss obfuscated or novel behavior. Findings require manual interpretation. Pin revisions and re-review changes before updating.
