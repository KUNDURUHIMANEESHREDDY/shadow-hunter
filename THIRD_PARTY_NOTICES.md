# Third-party notices

Shadow Hunter includes selected agent skills as development-time guidance. These are separate works with their own licenses; their licenses do not replace or alter the root project's MIT License.

## Committed development skills

### agent-safety

- Source: https://github.com/ericrisco/rsc-harness
- Skill: `agent-safety`
- Pinned source: tag `v4.1.8`, resolved commit `28a51a91` (skill metadata tree SHA: `f5f669aa71545ef88a3a4f72b6b4eaa83f268997`)
- License: MIT
- Original license: `.agents/skills/agent-safety/LICENSE`

### skill-scanner

- Source: https://github.com/getsentry/skills
- Skill: `skill-scanner`
- Pinned source commit: `a582c51ee29d0f35e6ac321340796f77d43da733`
- License: Apache License 2.0
- Original license: `.agents/skills/skill-scanner/LICENSE`

### testing

- Source: https://github.com/Mindrally/skills
- Skill: `testing`
- Pinned source tag: `v1.0.0`, resolved commit `7682ca77710e0971eab4e0ae5dddfa281aea0ba5`
- License: Apache License 2.0
- Original license: `.agents/skills/testing/LICENSE`

## Installed locally but not committed

### llm-security

- Source: https://github.com/semgrep/skills
- Skill: `llm-security`
- Resolved source commit: `68177b8830f96cd9d10dacbb14dde2566360503d`
- GitHub reports the repository license as `Other`; its root LICENSE file refers to the Semgrep Rules License v1.0.
- This skill is installed only in the local working copy and excluded from Git until the license scope and redistribution terms are reviewed. Do not copy it into the repository or release artifacts.

## Review policy

Third-party skills are untrusted supply-chain inputs. Review the source repository, immutable revision, full skill instructions, every bundled script, dependencies, hooks, URLs, and license before installation or update. Run the local static scanner, then manually inspect findings: documented attack examples can produce intentional false positives. Never automatically execute a skill's installation scripts or arbitrary bundled code.
