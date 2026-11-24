# Local orchestration improvements

Base revision: 1471331. No changes to the tool permission boundary or production deployment.

- Two active planning sessions, two waiting admissions, eight concurrent workflow lifetimes.
- Authenticated streamed requests cancel their own asynchronous HTTP transport; shared Ollama process is not killed.
- Full graph validation before any tool call and reusable dependency ledger for independent nodes and joins.
- Existing read-only support tool scope, account isolation, audit correlation and deny-stop rules remain.

Verification: 79 focused tests passed and one opt-in test skipped. A live local Qwen request interrupted after 0.407 seconds total elapsed (signal after 0.3 seconds). Two concurrently submitted plans returned order_details and refund_eligibility in 6.156 seconds. These observations do not prove simultaneous model computation or compute termination on the server. The live experiment occurred before the final dependency-ledger integration, which was covered by the focused tests.

Remaining: persistent independent job scheduler, broader registered capabilities, verified backend inference termination, hardware parallelism measurement, updated browser E2E.
