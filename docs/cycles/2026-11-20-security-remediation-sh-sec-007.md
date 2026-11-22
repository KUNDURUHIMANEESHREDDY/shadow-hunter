# Engineering cycle — SH-SEC-007 Cognito trusted-identity boundary

- Date: 2026-11-20
- Repository baseline: `main` at `b8968a8befe6cd031852ab43944a38544c5d5dc0` (SH-SEC-002)
- Scope: verify the new-pool Cognito trust boundary in infrastructure-as-code and token-handler behavior; explicitly identify the existing-pool add-on's limits.
- Outcome: new-pool source mitigations and offline contract tests verified; the conditional High live-Cognito release gate remains OPEN.
- AWS resources created or changed: **none**.
- AWS account, credentials, User Pools, identities, customer data or live Cognito tokens accessed: **none**.

## Change contract

The token's tenant/customer claims are trusted authorization inputs. In the new-pool path, only a trusted administrator may set those attributes during user creation; human app clients must not be able to read or write them; the token trigger must be V3_0 and fail closed for customer/delegated identities without both attributes. Server-managed operator group membership remains separate. The existing-pool trigger add-on must not be represented as securing a pool whose schema, app-client permissions, identity-provider mappings and sign-up/profile flows have not been audited.

## Source and test changes

- Added `tests/test_cognito_identity_template.py`, which parses the actual CloudFormation templates and asserts:
  - the stack is production-only and the Cognito tier is an explicit ESSENTIALS/PLUS input;
  - user creation is administrator-only; MFA is mandatory; deletion protection and retain policies are enabled;
  - `tenant_id` and `customer_id` are immutable string attributes;
  - the pre-token trigger is V3_0 and the invocation permission is scoped to the User Pool ARN;
  - the customer/operator app clients explicitly allow writes to email only and read only email/email_verified; they do not have the trusted attributes or `aws.cognito.signin.user.admin` scope;
  - customer/operator clients are distinct; operator scopes are restricted; the operator group is provisioned without members; and the confidential M2M client uses the delegated token-exchange flow;
  - the existing-pool add-on does not create/configure a User Pool or app client.
- Added a pre-token regression that proves pre-existing `tenant_id` / `customer_id` claim overrides cannot replace values from Cognito's trusted user attributes.
- Added `PyYAML>=6.0` to the optional development dependencies for the template-contract test.
- Expanded `infra/cognito/README.md` to distinguish the new-pool and existing-pool paths and make the latter's required audit explicit.
- Updated the security review, deployment readiness, architecture and README status. The live High release gate remains open.

## Verification evidence

- `python -m pytest tests/test_cognito_identity_template.py tests/test_production_identity_contract.py tests/test_cognito_pretoken.py tests/test_auth.py -q`: **39 passed**.
- `python -m pytest -q --ignore=tests/test_lambda_handler.py`: **167 passed**. The Lambda-entrypoint test was excluded because the optional `mangum` package is not installed in this local environment.
- `python -m compileall -q src tests`: passed.
- Ruff `--select F,I` on the changed Cognito/auth modules and identity tests: passed after import sorting.
- `sam validate --template-file infra/cognito/identity-stack.yaml`: passed (basic SAM validation).
- `sam validate --lint --template-file infra/cognito/pre-token-generation.yaml`: passed.
- `sam build --template-file infra/cognito/identity-stack.yaml`: passed.
- `sam build --template-file infra/cognito/pre-token-generation.yaml`: passed.
- `sam validate --lint --template-file infra/cognito/identity-stack.yaml`: **failed with E3030** because the bundled lint schema did not include `ALLOW_TOKEN_EXCHANGE_DELEGATION` in `ExplicitAuthFlows`. Current AWS CloudFormation and Cognito API references list this value as supported. The standalone current `cfn-lint` executable was not available in this environment, so the schema mismatch could not be cross-checked locally.
- `python scripts/validate-repo.py` and `git diff --check`: passed.

The SAM lint failure is recorded rather than hidden. It is a bundled-schema false positive against the current AWS reference, but a current standalone cfn-lint run remains desirable.

## Security and release boundaries

- No AWS CLI/API calls, account lookup, credentials, Cognito deployment, User Pool inspection, real token issuance, staging attack, deployment/change set, or billable resource was used.
- Immutable custom attributes must be assigned during user creation; they cannot be corrected by a later update. The provisioning workflow must validate the tenant/customer mapping before creating the user.
- The new-pool template materially mitigates the source-level write-control gap. The existing-pool add-on only deploys the Lambda and its invoke permission; it does not make an existing pool safe.
- Before any customer-facing Cognito deployment, inspect the actual User Pool schema, every app client's `ReadAttributes` / `WriteAttributes`, all IdP attribute mappings, all self-service profile paths, operator group assignment/MFA, the V3_0 trigger association, and real customer/operator/OBO JWT claims. Attempt customer self-modification of both trusted attributes and prove it is rejected.
- Production remains **NO-GO** until this live evidence and the other security findings are closed or formally accepted with compensating controls.

## Next one-at-a-time objective

Proceed to SH-SEC-003 (secure recovery or rotation for the one-time approval capability lost after an operator page refresh). Keep the SH-SEC-007 High deployment gate visible; do not substitute offline tests for live Cognito verification.
