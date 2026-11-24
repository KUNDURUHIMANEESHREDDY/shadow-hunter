# Durable independent local jobs

Builds on 2b2891d. SQLite stores owner, capability, order ID, state, lease, and trace metadata. The queue does not retain bearer credentials, free-form prompts or returned business data. A current authenticated customer must dispatch their own queued jobs. No unattended execution, external adapters, or new write permissions are enabled.

Registered capabilities: order summary, refund status and compound order/refund review. The existing gateway independently authorizes every read, and policy evidence is verified. Jobs may run concurrently in batches of up to four, with transactional claiming, per-account limits, a global running limit, and lease expiry that interrupts rather than replays. Cancelling queued work cannot cancel an active job; active streamed model tasks retain the existing cancellation route.

API: GET/POST /v1/agent/local-jobs, POST /v1/agent/local-jobs/run-next, POST /v1/agent/local-jobs/run-batch, POST /v1/agent/local-jobs/{job_id}/cancel. Local SQLite runtime only. Workspace controls are account-scoped and clear on disconnect.

Verification: six scheduler tests plus one new real Edge browser queue test passed. The preceding live local runtime suite and cancellation checkpoint returned ten passes. On the existing Ollama server two streamed generations were serial (A first token 0.047s, end 0.547s; B first token 0.610s, end 1.172s). Runner logs reported parallel=1. This is not hardware parallelism.

## Isolated GPU runner experiment

An additional loopback Ollama server was started with OLLAMA_NUM_PARALLEL=2 and OLLAMA_MAX_LOADED_MODELS=1. The existing server was left unchanged. Runner debug logs reported CUDA, two slots, 592.3 MiB VRAM, and an explicit cancellation record for task 0 after its first token and HTTP stream closure. Two subsequent generations overlapped: A 0.172 to 4.016 seconds; B 0.063 to 3.266 seconds (relative to common request start). Logs showed separate slots 0 and 1 processing different tasks. This establishes concurrent GPU-backed generation, not kernel-level simultaneity or a throughput improvement claim. The temporary server was shut down.

Application revision db28299: 474 non-browser tests passed, one opt-in skipped. The complete browser suite needs pytest-playwright as well as Playwright; run with --browser-channel msedge in the isolated environment.
