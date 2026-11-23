# AgentCore staging: verified gates and current blocker (23 November 2026)

## Current result

The existing data, identity and API CloudFormation stacks remain deployed in
`ap-southeast-2` per the November 22 staging report. This cycle adds
repeatable security verification, **not** a new AgentCore deployment.

The connected AWS CLI returned `Your session has expired. Please reauthenticate
using 'aws login'` on STS and AgentCore list operations. Consequently no
AgentCore managed Harness, Gateway, Policy Engine or OBO credential provider
was created, updated, or live-verified in this cycle. Do not mark the system
production-ready or authenticated E2E as complete.

## Security verification added

- `scripts/verify_agentcore_staging.py`: AWS **read-only** control-plane check.
  Requires explicit staging resource identifiers and validates:
  - Harness READY, expected Cognito JWT discovery URL/customer client, and
    actual governed-Gateway tool linkage
  - Gateway READY, CUSTOM_JWT inbound authorization, configured
    policy-engine ARN in **ENFORCE** mode
  - Policy Engine ACTIVE, target READY using HTTP OpenAPI, Identity OBO provider
    READY and OAuth **TOKEN_EXCHANGE**, exact resource audience and scope
  - It neither inspects client secrets nor requests user JWTs
- `scripts/smoke_agentcore_staging.py`: strict HTTPS allowlist pinned to
  Shadow Hunter's approved staging API Gateway hostname; redirects disabled;
  public health check and anonymous/invalid JWT rejection.
  Authenticated mode requires distinct short-lived **synthetic** customer,
  operator and delegated OBO JWTs, plus a synthetic order ID. A full pass also
  requires an explicit live Harness invocation with `--invoke-model`
  (potential AWS charges). The probe never prints tokens or response bodies.
- Focused tests use mocks and cannot prove live AWS identity propagation.

## Once the AWS session has been reauthenticated

1. Run `aws login` on the authorized development machine, then
   `aws sts get-caller-identity` and confirm the **staging** account before
   any deployment. Do not commit credentials or tokens.
2. Check AgentCore quotas, allowed model, policy-engine rules, configured
   AWS budget/alerts and any deployment costs. Deploy the Cognito OBO
   credential provider, governed Gateway + OpenAPI target, Cedar Policy
   Engine, and managed Harness using the existing approved staging design.
   No real user/customer data; no production updates.
3. Use the identifiers from the deployed resources to run:

```sh
python scripts/verify_agentcore_staging.py \
  --harness-id "STAGING_HARNESS_ID" \
  --gateway-id "STAGING_GATEWAY_ID" \
  --target-id "STAGING_TARGET_ID" \
  --policy-engine-id "STAGING_POLICY_ENGINE_ID" \
  --credential-provider-name "STAGING_PROVIDER_NAME" \
  --issuer "https://cognito-idp.ap-southeast-2.amazonaws.com/STAGING_POOL_ID" \
  --customer-client-id "STAGING_CUSTOMER_CLIENT_ID"
python scripts/smoke_agentcore_staging.py --boundary-only
```

4. Obtain short-lived JWTs from **real Cognito staging authentication**
   for three separate synthetic identities and expose them through temporary
   environment variables (never place their values in shell history or Git):

   - `SHADOW_HUNTER_E2E_CUSTOMER_JWT` — customer access token
   - `SHADOW_HUNTER_E2E_OBO_JWT` — genuine AgentCore Identity target-scoped
     token carrying the expected actor claim
   - `SHADOW_HUNTER_E2E_OPERATOR_JWT` — operator access token with group claim

   Run `python scripts/smoke_agentcore_staging.py --synthetic-order-id
   "STAGING_SYNTHETIC_ORDER_ID" --invoke-model`. This performs **read-only**
   tool checks and a model invocation; it does not request or execute refunds.

5. Independently verify the policy decision traces in CloudWatch, deny
   wrong audience/scope/actor and cross-customer access, and confirm the
   delegated token is truly issued by Cognito/Identity, not created by a mock.
   Verify the S3 audit archive and operator sign-in/MFA flow.
6. Update the application staging stack with the **verified** Harness ARN;
   repeat health and authenticated E2E tests. Production remains NO-GO until
   staging evidence and the security review are complete.

## Boundaries

Passing these scripts is necessary but not sufficient for production. The
read-only control-plane verifier checks configuration, not actual OBO token
issuance or policy decisions; the HTTP probe checks a small set of routes,
not comprehensive load, tenant isolation or penetration testing. No model
access or cloud deployment is asserted from an offline test.
