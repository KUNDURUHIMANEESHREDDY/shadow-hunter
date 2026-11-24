# Durable independent local jobs

Builds on 2b2891d. SQLite stores owner, capability, order ID, state, lease, and trace metadata. The queue does not retain bearer credentials, free-form prompts or returned business data. A current authenticated customer must dispatch their own queued jobs. No unattended execution, external adapters, or new write permissions are enabled.

Registered capabilities: order summary, refund status and compound order/refund review. The existing gateway independently authorizes every read, and policy evidence is verified. Jobs may run concurrently in batches of up to four, with transactional claiming, per-account limits, a global running limit, and lease expiry that interrupts rather than replays. Cancelling queued work cannot cancel an active job; active streamed model tasks retain the existing cancellation route.

API: GET/POST /v1/agent/local-jobs, POST /v1/agent/local-jobs/run-next, POST /v1/agent/local-jobs/run-batch, POST /v1/agent/local-jobs/{job_id}/cancel. Local SQLite runtime only. Workspace controls are account-scoped and clear on disconnect.

Verification: six scheduler tests plus one new real Edge browser queue test passed. The preceding live local runtime suite and cancellation checkpoint returned ten passes. On the existing Ollama server two streamed generations were serial (A first token 0.047s, end 0.547s; B first token 0.610s, end 1.172s). Runner logs reported parallel=1. This is not hardware parallelism.
