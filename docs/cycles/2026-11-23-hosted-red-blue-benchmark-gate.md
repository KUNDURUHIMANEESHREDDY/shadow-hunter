# Gate 3 — Hosted Red/Blue benchmark evidence

The hosted evaluation endpoint runs NVIDIA NIM Red/Blue models against a
disposable synthetic SQLite store, with independent deterministic tool-policy
enforcement. Each run is limited by the existing operator cooldown and daily
quota and persists restricted synthetic audit events.

The new `scripts/benchmark_hosted_red_blue.py` requires explicit opt-in
to a single paid hosted evaluation and a short-lived genuine staging operator
JWT. It **does not run on CI or on a schedule**.

```bash
python scripts/benchmark_hosted_red_blue.py \\
  --invoke-hosted-model --acknowledge-charges --rounds 3 \\
  --report-file hosted-red-blue-report.json
```

The runner calls only the pinned staging operator evaluation endpoint;
fetches its correlated audit trace; checks the run metadata declares
`hosted_nvidia_nim`, verifies case counts and aggregate metrics; and
produces a sanitized JSON report with denominators, confusion matrix
(attack blocked/allowed vs legitimate blocked/allowed), model names,
and explicit evidence limitations. It never serializes JWTs, customer
records, prompts, model freeform text, or provider response bodies.

**Important comparison limitation:** cases are compared against their expected
policy outcomes *within the same hosted run*, not against a no-policy
environment or a randomized control system. Never claim causal improvement
over an unprotected agent from this report alone.

## Unverified external prerequisites

- Actual NVIDIA API credentials in the backend's Secrets Manager or
  protected environment, not in source control.
- Independently minted Cognito operator JWT with the appropriate group.
- Staging evaluation enabled only after cost bounds are reviewed.
- Host model access and successful token quota/API call.
- Genuine provider and archived audit evidence. The offline test fixtures
  are never to be presented as measured hosted results.

This script produces no valid report until the required live checks pass.
