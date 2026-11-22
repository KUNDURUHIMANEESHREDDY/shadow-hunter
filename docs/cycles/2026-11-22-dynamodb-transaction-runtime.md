# Engineering cycle — DynamoDB transaction runtime integration

- Date: 2026-11-22
- Baseline: `main` at `6364bbf30f32cd1868414efe1fd934d7724db8dc`
- Scope: real Boto3 transaction client selection and offline DynamoDB data-plane lifecycle coverage
- AWS account, credentials, resources, network calls or deployments: **none**
- Owner-owned uncommitted files (API, gateway, agents, existing tests and docs): **preserved; not part of this change**

## Reproduced defect

The adapter used `table.meta.client` for `TransactWriteItems` while also
pre-serializing each transaction action with `boto3.dynamodb.types.TypeSerializer`.
That high-level DynamoDB resource client applies its own DynamoDB conversion,
double-encoding all Item/Key values into nested `M` maps. A representative
refund-request transaction failed with
`TransactionCanceledException` / cancellation reasons
`[TypeError, TypeError, TypeError]`.

## Change

- `DynamoDBStore` uses a dedicated low-level `boto3.client("dynamodb")`
  for transactions; the table resource continues to handle normal get/put/query calls.
- Explicitly supplied clients are still supported for contract tests and custom wiring.
- New `tests/test_dynamodb_integration.py` uses Moto's isolated, in-memory
  AWS-compatible DynamoDB implementation, including the real PK/SK/GSI1 schema.
- Integration assertions cover idempotent refund creation, conflict denial,
  maker-checker, approval, atomic order-balance change, token consumption,
  token rotation, idempotent execution replay, audit queries and counters,
  rejection, A2A nonce replay protection, and operator evaluation quotas.
- The reproducible dev dependency is `moto[dynamodb]>=5.2,<6`.
- Updated `infra/data/README.md` with commands and verification boundaries.

## Verification evidence

- Initial integration run before the fix: **5 failed**, caused by transaction
  double-encoding in the first database write.
- `python -m pytest -q --tb=short tests/test_dynamodb_integration.py`
  after the fix: **5 passed in 5.98s**.
- A full local suite run returned **184 passed, 2 failed**. One failure was
  missing local `mangum` (subsequently installed); the other was
  `tests/test_operator_settings_api.py::test_operator_can_recover_approved_token_after_browser_refresh`
  with `KeyError: 'approval'`. The API and related existing tests had
  pre-existing uncommitted edits and were intentionally not modified here.
- After installing the already-declared `mangum` development dependency, the
  repeated full suite returned **185 passed, 1 failed**. The sole remaining
  failure is the same operator recovery `KeyError: 'approval'` on the
  pre-existing, uncommitted API working tree; it is not presented as green.
- Focused Lambda handler and DynamoDB groups after installing `mangum`:
  **14 passed in 5.70s**.
- `python scripts/validate-repo.py`: passed.
- `git diff --check`: no output.
- `python -m compileall -q src/shadow_hunter tests/test_dynamodb_integration.py`:
  passed.

## Remaining release gates

This is **not** a live AWS verification. Provisioning and testing the real
Cognito identity contract, DynamoDB table/conditional transactions, stream to
S3 Object Lock export, API Gateway/Lambda integration, IAM, and alarms in
staging require separate explicit approval to use AWS resources. No claim of
production readiness or actual payment-provider refunds is made.
