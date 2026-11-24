# Step 5: opt-in persistent workflow memory

Added an account-scoped SQLite memory store, sanitized server-generated outcome summaries, optional public metadata and model readiness findings, capability-based retrieval during preview, and authenticated view/delete/clear endpoints. Saving and retrieval require explicit opt-in. Records are historical context, not live evidence, and never enter the authorization boundary. Clear invalidates previously issued save epochs so running workflows cannot recreate cleared records. Retention: 30 days, 30 records per account, 3000 globally, with lazy expiry on memory access.

Validation: 64 focused tests passed, including persistence after reopening the database, account and tenant isolation, opt-in, expiry, capacity, redaction, clear-during-execution, and API integration. Two browser tests passed, including save, recall, delete and disconnect cleanup.

Scope: local workflow runs only. No raw prompts, order IDs, numerical inputs, private business results or credentials persisted by the memory feature. No vector database, automatic semantic inference from previous results, cross-device synchronization, background retention cleanup or physical secure erasure. Full regression, deployment and publication remain separate release steps.
