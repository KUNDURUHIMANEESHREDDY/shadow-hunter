# Decision 0005 — in-process Red/Blue harness before remote A2A

- Date: 2026-11-20
- Status: Accepted

## Context

Shadow Hunter already has a deterministic policy engine, a narrow tool gateway,
human approval, and correlated audit events. The project needs a Red/Blue security
evaluation layer without weakening those enforcement boundaries or prematurely
introducing networked agent identities.

## Decision

Add a deterministic in-process message exchange first. The Red Agent emits a bounded
attack proposal; the Blue Agent validates the envelope and submits the requested action
to the existing ToolGateway. The gateway assigns the Blue Agent ID server-side. The
Blue Agent returns a redacted policy result to Red, and the simulator records both
messages and the outcome in the existing trace.

## Consequences

- The first slice can exercise real policy and gateway behavior without AWS resources
  or model-provider credentials.
- The fixed scenario factory makes attack cases reproducible and suitable for tests.
- The protocol envelope is not an authenticated network protocol. Remote communication,
  replay protection, service identity, and transport authorization remain future work.
- The Blue Agent is a deterministic gateway adapter, not yet an LLM-driven defender.
- The Red/Blue harness must not expose payment execution or return protected tool data.
