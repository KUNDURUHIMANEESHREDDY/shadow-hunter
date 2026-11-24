# Bounded recurring jobs and cross-domain workflows

Seven approved capabilities: order summary, refund eligibility, compound order review, model health, numeric summary, unit conversion, and public metadata for three explicitly allowed GitHub repositories. The metadata adapter uses a fixed HTTPS origin, no credentials, redirects or arbitrary URLs.

A recurring job has an explicit authenticated grant, interval of 60?86400 seconds, 2?20 executions, and at most seven days of planned recurrence. Successful runs atomically advance the due time; denial, failure, cancellation and expiry stop the sequence. No duplicate claims or silent replay. The workflow endpoint accepts at most eight explicitly specified nodes, validates every input and the dependency graph before any invocation, and executes up to two ready nodes at once. A failed or denied prerequisite blocks dependents.

The workspace supports recurrence and explicit graph entry. These are general orchestration primitives, not unrestricted model-generated execution.

Focused tests before the workflow builder UI: 16 passed. A real GitHub metadata request for python/cpython succeeded. A prior mixed unit/browser invocation failed due to the Playwright session event loop remaining active during synchronous MCP/Lambda unit tests; run non-browser and browser tests in separate pytest processes.
