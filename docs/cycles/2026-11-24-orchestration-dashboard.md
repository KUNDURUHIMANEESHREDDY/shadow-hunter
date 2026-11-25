# Step 8: live orchestration dashboard

Added authenticated, graph-validated NDJSON streaming with ordered sequence numbers and monotonic elapsed timestamps. Bounded queue and shared workflow admission; disconnect signals the graph executor to stop dispatching new nodes while active reads finish. Worker retains admission until it exits. The stream reports validated graph topology (without resource inputs), execution, independent verification, recovery, terminal node states, residual revisions and final outcome. The existing synchronous API remains supported; optional memory uses the shared execution path.

Workspace adds a scrollable dependency diagram with live node states, verified-node progress, retry and elapsed counters, chronological timeline and stop control. Disconnect clears dashboard state and aborts active stream; stale account responses are ignored. No fabricated progress.

Validation: 112 focused regression tests passed; seven browser checks passed across two runs (including existing verification, memory and recovery checks, new successful/denied dashboard checks, checkpoint resume and preview). Actual loopback HTTP test held a synthetic adapter open and received running events before releasing it. Another closed the stream during the active node and confirmed its dependent did not execute. Controlled retry and verification failure tests confirm incomplete workflows cannot display all nodes verified. One existing pytest fixture deprecation warning per browser run.

Scope: active synchronous graph streams, not durable cross-session monitoring of every runtime or forceful adapter cancellation. Full repository regression, deployment and GitHub push remain separate release steps.
