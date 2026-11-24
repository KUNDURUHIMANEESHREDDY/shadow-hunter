# Step 3: bounded adaptive workflow recovery

The graph executor now uses completion-driven scheduling rather than fixed batches. It updates the residual dependency graph as verified prerequisites complete, keeps unrelated branches progressing during backoff, and propagates failed dependencies transitively. Attempt counts and revision snapshots are returned with each graph result.

Only explicitly classified temporary public GitHub metadata reads may be retried. One retry per node, maximum four per graph; each attempt retains the original resource and revalidates the approved capability. HTTP 502/503/504 without Retry-After and selected transport failures are retryable. Authorization, rate limits, malformed data, audit failures and unknown exceptions do not trigger recovery. No substitution or weakened dependency constraints.

Validation: 53 focused tests passed, including 17 recovery tests; 2 browser checks passed. Controlled transient fault injection followed by a real public GitHub metadata request succeeded, with two attempts for metadata and one each for the independent and dependent nodes. This is a controlled failure test, not evidence of a real GitHub outage.

Scope: synchronous graph execution only. Arbitrary model-generated replanning, substitute providers, persistent checkpoints and independent general result verification remain separate milestones.
