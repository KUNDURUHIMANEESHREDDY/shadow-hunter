# Gate 2 — Cognito OBO cross-tenant staging isolation

The new `scripts/verify_two_tenant_staging.py` is a read-only, pinned
staging verifier requiring actual distinct synthetic Cognito/AgentCore
Identity delegated tokens for tenant A and tenant B, their independently
owned synthetic order IDs, and a separate operator access token.

It performs six protected `get_order` tool calls and four restricted audit
lookups. The gate succeeds only if:

- Both tenants can read their own synthetic orders.
- Both cross-tenant reads are denied without a disclosed order.
- Foreign/missing resource responses are semantically indistinguishable.
- A matching policy decision exists for each allowed/denied trace.
- Public output never includes credentials, order details or model claims.

It does not mint or fake OAuth tokens, perform writes, request refunds,
or create/delete test identities.

```bash
# Configure all five inputs from real, short-lived staging identity flows:
# SHADOW_HUNTER_E2E_TENANT_A_OBO_JWT
# SHADOW_HUNTER_E2E_TENANT_B_OBO_JWT
# SHADOW_HUNTER_E2E_TENANT_A_ORDER_ID
# SHADOW_HUNTER_E2E_TENANT_B_ORDER_ID
# SHADOW_HUNTER_E2E_OPERATOR_JWT
python scripts/verify_two_tenant_staging.py --run-read-only
```

No production deployment can be marked fully authenticated until this and
the separate `scripts/smoke_cognito_identity.py --obo` token-exchange gate
pass with real short-lived JWTs in an approved staging environment.
Local fake-server tests prove only the verifier contract, not live isolation.
