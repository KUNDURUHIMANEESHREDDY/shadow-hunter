# Submission architecture

```mermaid
flowchart TD
    U["User / synthetic request"] --> A["Authenticated API"]
    A --> O["Local agent planner"]
    O --> G["Deterministic tool gateway"]
    G --> P{"Policy decision"}
    P -->|ALLOW| T["Scoped business tools"]
    P -->|DENY| B["Blocked action"]
    P -->|ESCALATE| H["Independent human approval"]
    H --> T
    T --> L["Correlated audit evidence"]
    B --> L
    H --> L
    L --> V["Independent evidence verification"]
    R["Synthetic Red/Blue lab"] --> G
    V --> D["Operator dashboard"]
    L -. "Redacted decision; optional" .-> BAND["BAND adapter: not live verified"]
    BAND -. "Synthetic advisory only" .-> LY["Lyzr adapter: not live verified"]
    LY -. "Advisory, no authority" .-> D
```

Solid lines depict the local application architecture, including the separately bounded synthetic lab. Dotted lines denote optional sponsor paths with no live evidence at the tested baseline. The approval service and operator-only execution retain independent authorization checks. No real payment operation is performed in the demo.
