# Local automatic dispatch and utility registry

- Five capabilities: three governed support reads, fixed loopback model health, and bounded numeric summaries.
- One-shot scheduling: integer delay 0 through 3600 seconds; expires 300 seconds after due time. Manual dispatch cannot claim scheduled work early.
- Explicit authenticated scheduling, transactional claims, current local identity revalidation, fail-closed missing accounts, bounded concurrency, expiry and cancellation before execution.
- The application lifespan owns the polling worker. No bearer credentials, free-form prompts, or business results are retained in the queue. Bounded job inputs are stored; do not submit sensitive numbers. Automatic outcomes expose status and trace metadata, not retained results.
- Local SQLite and local token authentication only. Disable with SHADOW_HUNTER_AUTO_JOBS_ENABLED=false. No recurring or external side-effect jobs.
- Ollama was restarted on its existing loopback port only after active connections closed. The user-level OLLAMA_NUM_PARALLEL setting is 2, startup logs confirm 2, and all five models remained available.
- Previous revision b0c5948: 474 non-browser passes, one skip, and 21 browser/live passes. New focused scheduler and automatic utility browser checks: 11 passed.

Remaining: broader external adapters, persistent outputs with appropriate privacy controls, recurring scheduling and production authorization. No claim of arbitrary general-purpose execution.
