# Engineering cycle — local release-candidate documentation and security review

- Review date: 2026-11-20
- Repository baseline: main at 6b26b6aaea1308706abb1ba3eac375251bd45d25
- Scope: refresh architecture/deployment status, perform a read-only source-level security review, and prepare the deployment checklist for ap-southeast-2.
- Outcome: documentation updated; source-level review recorded; no production-code changes.
- AWS resources created or changed: **none**.
- Credentials or local authentication stores accessed: **none**.

## Work completed

- Updated docs/architecture.md with current route boundaries, baseline evidence status, the security-review reference, and known release blockers.
- Added docs/security-review-2026-11-21.md with seven prioritized findings, positive controls, evidence paths, remediations, and a verification matrix.
- Updated docs/production-deployment-readiness.md to reference the latest reviewed commit, record the selected Sydney Region, add Cognito identity-attribute controls, and make the source-review findings explicit deployment gates.
- Updated the README status table and added this cycle record.

## Security review summary

The highest-priority item is conditional but release-blocking: Cognito tenant/customer attributes are trusted by the pre-token trigger, while the repository does not control user-pool/app-client attribute write permissions. Medium findings cover order-existence disclosure, lack of a maker-checker invariant, unrecoverable one-time approval tokens after page refresh, and unbounded per-operator hosted-model usage. Low findings cover operator-console framing hardening and upstream AgentCore error reflection.

The review found meaningful existing controls in JWT verification, deterministic policy enforcement, tool allowlisting, transactional approval/refund handling, least-privilege resource scoping, synthetic Red/Blue evaluation, and audit archive separation. See the security report for exact evidence and qualification.

## Region decision

The owner-selected target remains ap-southeast-2 (Asia Pacific — Sydney). Current AWS AgentCore regional documentation lists Sydney support for the Harness, Gateway, Identity and Policy features relevant to this architecture. This does not prove account entitlement, quotas, model availability, token-exchange setup, pricing, or deployed configuration. No account or SSO profile was accessed.

## Verification and deployment record

- Repository source was inspected through the connected GitHub integration at the recorded baseline.
- Targeted credential-marker searches on the default branch did not surface a concrete credential value. No full-history or provider-side secret scan was performed.
- Tests, builds, linting, SAST/DAST, browser checks, SAM validation, cfn-lint, and packaging were **not run**.
- The repository's docs/engineering-cycle.md currently prohibits verification commands until the owner explicitly changes that rule. This cycle did not modify that policy.
- No AWS CLI, AWS APIs, AWS credentials, stacks, user pools, app clients, tables, buckets, queues, Lambda functions, APIs, or AgentCore resources were created, inspected, or modified.
- No live NVIDIA inference request was sent.

## Remaining gates

1. Obtain explicit owner approval to update the repository verification policy and run the agreed test/static/infrastructure checks.
2. Remediate or formally accept each finding with a documented compensating control and regression evidence.
3. Complete Cognito user-pool/app-client configuration with non-writable customer identity attributes, operator MFA, separate operator client/group, and V3_0 trigger association.
4. Run formal validation on all three SAM templates and build/package review.
5. Obtain explicit AWS account, Region, environment, and billable-resource approval before deployment.
6. Deploy in stages, then produce the synthetic cross-customer denial, correlated audit trace, S3 object, and independent read-only byte-verification evidence.

## Files updated

- README.md
- docs/architecture.md
- docs/production-deployment-readiness.md
- docs/security-review-2026-11-21.md (new)
- docs/cycles/2026-11-20-local-release-candidate-security-review.md (new)
