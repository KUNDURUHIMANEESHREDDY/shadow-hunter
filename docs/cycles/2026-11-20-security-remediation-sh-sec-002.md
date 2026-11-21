# Engineering cycle — SH-SEC-002 maker-checker separation

- Date: 2026-11-20
- Repository baseline: `main` at `dbb36bf210105a842e2b8796db4762d77659d809` (SH-SEC-001)
- Scope: enforce that the authenticated refund requester cannot approve their own refund in both persistence adapters; re-check the stored requester/approver pair before execution.
- Outcome: local implementation and regression tests pass; live DynamoDB staging verification remains pending.
- AWS resources created or changed: **none**.
- Credentials, local auth stores, or customer data accessed: **none**.

## Change contract

The approver identity is the authenticated operator subject supplied by the API, never a body field. It must differ from the `principal_id` stored when the refund request was created. The invariant must be enforced at the authoritative state transition in both SQLite and DynamoDB, logged as a denial, and revalidated before refund execution so legacy or altered records cannot bypass it. An independent operator must still be able to approve.

## Implementation

- SQLite `approve`: compares the approver subject with the stored requester inside the existing `BEGIN IMMEDIATE` transaction. Same-subject attempts append `APPROVAL_SELF_APPROVAL_BLOCKED` with DENY / `MAKER_CHECKER_VIOLATION`, commit the denial event, leave the approval pending, and return a controlled `StoreError`. The approval UPDATE also requires `principal_id <> approver_id`.
- DynamoDB `approve`: performs an early constant-time comparison and records a denial audit event. The approval `TransactWriteItems` update independently requires `principal_id <> :approver`, so a concurrent change between read and write cannot authorize self-approval. The failed-transaction path re-reads and records the specific denial if a concurrent change made the requester and approver equal.
- SQLite and DynamoDB refund execution: both validate that stored requester and approver are distinct before any new refund execution. Their final approval-consumption transitions also enforce the inequality, so pre-fix or altered self-approved records cannot authorize a new debit.
- Rejection remains available to an authenticated operator; it does not grant execution authority.
- Added tests for self-approval denial, pending-state preservation, denial audit evidence, independent-operator approval, DynamoDB's conditional update expression, and legacy self-approved SQLite execution denial.
- Updated the security review, architecture, threat model, production readiness, and README status.

## Regression evidence

The tests were added before the production fix and initially failed:
- SQLite accepted a same-subject approval instead of raising.
- DynamoDB accepted a same-subject approval instead of raising.
- The DynamoDB approval transaction did not contain a requester/approver inequality condition.

After the implementation:
- `python -m pytest tests/test_approvals.py tests/test_dynamodb_store.py tests/test_gateway.py -q`: **22 passed**.
- The legacy self-approved SQLite execution case was first run independently and failed before the execution guard; after the guard, it passed in the focused suite.
- The DynamoDB tests use a fake transaction client and inspect the conditional expression. They do not replace live DynamoDB validation.

## Broader verification

- `python -m pytest -q --ignore=tests/test_lambda_handler.py`: **163 passed**.
- `python -m compileall -q src tests`: passed.
- `python scripts/validate-repo.py`: passed (8 Codex TOML files, 0 workflow YAML files, 7 Copilot agent profiles, 4 required project files).
- `git diff --check`: passed.
- Ruff `--select F,I`: passed.
- Ruff `--select E,F,I --ignore E501`: passed.
- Full-file Ruff checks still report pre-existing diagnostics in these modules: import/type-style rules (UP035, UP037), mutable class attributes (RUF012), an existing broad exception handler (S110), an existing conditional-shape rule (SIM102), and existing E501 line-length violations. The new/changed lines that introduced E501 findings were wrapped; unrelated baseline lint cleanup was not included.

The excluded `tests/test_lambda_handler.py` test requires the optional `mangum` dependency, which is not installed in this local environment. No dependency was installed to change that environment.

## Security and release boundaries

- No AWS CLI/API calls, DynamoDB endpoint calls, Cognito inspection, staging checks, deployment, change sets, or billable resources were used.
- The SQLite behavior is exercised locally. DynamoDB is verified only through the contract test that inspects the transaction condition; deployed DynamoDB behavior remains unverified.
- Production deployment remains **NO-GO**. SH-SEC-007 (trusted Cognito tenant/customer attributes) remains a conditional High deployment blocker; live AWS identity and service verification are still required.

## Next one-at-a-time objective

Proceed to SH-SEC-007, the conditional High Cognito trusted-attribute deployment gate, before the remaining Medium/Low application findings. Keep AWS account access and resource creation outside scope unless separately approved.
