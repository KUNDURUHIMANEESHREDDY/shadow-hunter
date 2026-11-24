# Shadow Hunter

**Autonomous intelligence. Deterministic security.**

Shadow Hunter is a security and governance control plane for AI agents. It separates model reasoning from authorization, so an agent can interpret a request and propose a workflow without deciding its own permissions.

The first implemented workload is customer support and refund management. A local AI workspace, policy-controlled tools, human approval controls and traceable evidence demonstrate how useful agentic workflows can operate within defined boundaries.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](pyproject.toml)
[![Runtime](https://img.shields.io/badge/Local%20runtime-Ollama-black.svg)](src/shadow_hunter/local_runtime.py)

> **Development status:** Local prototype verified with synthetic records and real local model inference. Production release is not approved.

## Why Shadow Hunter?

AI agents can misunderstand instructions, propose invalid actions or encounter untrusted content. A model's confidence is not sufficient authorization. Shadow Hunter places deterministic policy enforcement outside the model, checks authenticated identities and resource ownership, and records evidence of each decision.

## Capabilities

| Component | Implemented capability |
| --- | --- |
| Policy engine | Deterministic ALLOW, DENY and ESCALATE decisions; default-deny authorization |
| Governed MCP tools | Order lookup, refund eligibility and controlled refund-request creation |
| Local AI workspace | Qwen 3.5 0.8B via Ollama; structured read-only plans, separate plan review and dependency checks |
| Execution verification | Correlated policy decisions, result validation and one bounded recovery attempt for inconsistent compound reads |
| Human approval | Expiring, parameter-bound, single-use approval capabilities; operator-only refund execution |
| Audit and history | Correlated decision records, trace queries and account-scoped local task history |
| Operator console | Policy evidence, approvals, operational settings and evaluation results |
| Runtime controls | Model readiness, two concurrent planner sessions, bounded workflow admission, cancellable inference HTTP requests and queue timeouts |

The local model workspace is restricted to order information and refund eligibility. Refund-request creation is available through the separate governed tool interface; actual refund execution is never exposed as a model tool. Demo refund execution updates an internal ledger, not a payment provider.

## Architecture

```mermaid
flowchart TD
    U["Authenticated customer"] --> W["Local support workspace"]
    W --> P["Qwen 3.5 0.8B via Ollama"]
    P --> R["Structured proposal and review"]
    R --> C["Server-owned workflow and runtime controls"]
    C --> G["Governed tool gateway"]
    M["Authenticated MCP tool client"] --> G
    G --> D{"Deterministic policy engine"}
    D -->|Allow| T["Authorized business tools"]
    D -->|Deny| B["Block request"]
    D -->|Escalate| A["Approval workflow"]
    O["Authenticated operator"] --> A
    A --> E["Re-authorized operator-only ledger execution"]
    T --> S[("Order and refund store")]
    E --> S
    D --> L[("Correlated audit evidence")]
    B --> L
    A --> L
    T --> L
    E --> L
    L --> V["Result verification and operator trace view"]
    V --> W
    V --> O
```

The model proposes; the server validates the plan and identity; the gateway authorizes each invocation. Human approval does not replace authorization, and results are checked against the associated policy evidence.

### Technology stack

| Layer | Technology |
| --- | --- |
| Application and policy | Python, FastAPI, Uvicorn |
| Local intelligence | Ollama, Qwen 3.5 0.8B |
| Tool protocol | Model Context Protocol (MCP) |
| Frontend | Browser-based HTML, CSS and JavaScript |
| Local persistence | SQLite |
| Optional cloud adapters | DynamoDB, Cognito, Amazon Bedrock AgentCore, Cedar policy templates |
| Verification | Pytest, Playwright, deterministic synthetic evaluation |

## Run locally

Use Python 3.11+, Git and an installed Ollama runtime. The following Windows PowerShell example is for a fresh **localhost-only synthetic demo**, not a production deployment.

```powershell
git clone https://github.com/KUNDURUHIMANEESHREDDY/shadow-hunter.git
cd shadow-hunter
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[server,dev]"
```

Start Ollama locally if it is not already running. Install the required model with:

```powershell
ollama pull qwen3.5:0.8b
```

In a fresh PowerShell session, from the repository root, configure isolated local identities and a new demo database:

```powershell
$customer = [guid]::NewGuid().ToString("N")
$operator = [guid]::NewGuid().ToString("N")
$customers = @{}
$customers[$customer] = @{
    subject_id = "demo-subject"
    tenant_id = "demo-tenant"
    customer_id = "demo-customer"
}
$operators = @{}
$operators[$operator] = @{ subject_id = "demo-operator" }

$env:SHADOW_HUNTER_CUSTOMER_TOKENS = $customers | ConvertTo-Json -Compress
$env:SHADOW_HUNTER_OPERATOR_TOKENS = $operators | ConvertTo-Json -Compress
$env:SHADOW_HUNTER_AUTH_MODE = "local"
$env:SHADOW_HUNTER_STORE_BACKEND = "sqlite"
$env:SHADOW_HUNTER_DB_PATH = "demo-$([guid]::NewGuid().ToString('N')).sqlite3"
$env:SHADOW_HUNTER_LOCAL_READONLY_ENABLED = "true"
$env:SHADOW_HUNTER_DEMO_MODE = "true"
$env:SHADOW_HUNTER_EVAL_ENABLED = "false"

Write-Host "Local customer token: $customer"
Write-Host "Local operator token: $operator"
.\.venv\Scripts\shadow-hunter-api.exe
```

Keep the tokens private. In a fresh, non-cloud-configured development environment, the app listens on `127.0.0.1:8000` by default. Never expose the local demo server to the public Internet.

Open [the operator console](http://127.0.0.1:8000/operator), authenticate with the generated operator token and seed the synthetic order using the demo seed control or the authenticated `POST /v1/operator/demo/seed` endpoint. Then open [the local workspace](http://127.0.0.1:8000/local-workspace), authenticate with the generated customer token, check model readiness, enter order ID `order-demo-001` and try:

> Show my order details and check refund eligibility.

The workspace displays the verified result, live activity and task history. Cancellation closes the active streamed-task inference HTTP request and stops at subsequent execution checkpoints. Ollama's internal compute interruption has not been independently verified.

### Local interfaces

| Interface | Path |
| --- | --- |
| Local AI support workspace | `/local-workspace` |
| Operator console | `/operator` |
| Customer interface (managed-runtime integration) | `/customer` |
| Health | `/health` |
| API documentation | `/docs` |
| MCP server | `/mcp/` |

## Verification and evidence

Recorded development results from **24 November 2026**:

| Verification | Recorded result | Tested revision |
| --- | --- | --- |
| Full non-browser regression | 457 passed, 1 opt-in test skipped | [6a97a08](https://github.com/KUNDURUHIMANEESHREDDY/shadow-hunter/commit/6a97a085d5ed8dc2b1a3a930759ea30ef8830d3d) |
| Latest queue-cancellation patch | 91 targeted passed, 1 opt-in test skipped | [30337b9](https://github.com/KUNDURUHIMANEESHREDDY/shadow-hunter/commit/30337b9f079ae6ba2f83bf8b866480d0bfd05d8b) |
| Live local HTTP, streaming and browser E2E | 9 passed | [457d5a2](https://github.com/KUNDURUHIMANEESHREDDY/shadow-hunter/commit/457d5a21f9bb178d7ca7dc6ee13b69a86b700399) |
| Live cancellation checkpoint and expanded browser controls | 2 passed | [33b5be6](https://github.com/KUNDURUHIMANEESHREDDY/shadow-hunter/commit/33b5be6e412ed2febc3c2b930081ac21e786ff60) |
| Language workflow benchmark | 12/12 acceptable outcomes; 11/12 exact intent | 457d5a2 |
| Support intent-boundary benchmark | 12/12 expected outcomes | 457d5a2 |
| Local synthetic defensive evaluation | 8/8 expected outcomes, no executed refunds | [Submission evidence](docs/hackathon/README.md) |

These results apply to the stated revisions and bounded test corpora. They do not establish universal security, unrestricted task understanding, production readiness or successful hosted sponsor integration.

Run the non-browser suite in the isolated development environment:

```powershell
.\.venv\Scripts\python.exe -m pytest -q --ignore=tests/e2e
```

For opt-in live model and browser testing, start Ollama, ensure the required model is installed, install Playwright and have Microsoft Edge available:

```powershell
.\.venv\Scripts\python.exe -m pip install playwright
$env:RUN_LOCAL_QWEN_E2E = "1"
.\.venv\Scripts\python.exe -m pytest -q tests/e2e/test_local_runtime_live.py
.\.venv\Scripts\python.exe -m pytest -q tests/test_local_runtime.py::test_live_model_cancellation_checkpoint
Remove-Item Env:RUN_LOCAL_QWEN_E2E
```

## Optional integrations

The local prototype does not require cloud inference or sponsor accounts.

| Integration | Role | Verification status |
| --- | --- | --- |
| BAND | Redacted policy-decision publication | Live collaboration not verified |
| Lyzr | Advisory inference | Live collaboration not verified |
| NVIDIA NIM | Optional hosted evaluation | Current hosted benchmark not verified |
| AWS AgentCore and Cognito | Optional managed deployment and identity | Managed execution and live delegated two-tenant release gates remain open |

See [sponsor integrations](docs/sponsor-integrations.md), [keyless authentication](docs/keyless-auth.md) and the [hackathon submission kit](docs/hackathon/README.md). External integrations do not expand the model's execution authority.

## Scope and roadmap

The prototype currently supports one bounded customer-support workload. The local planner admits two concurrent planning sessions and two waiting requests, with a five-second queue wait and a 45-second planning budget. Eight workflow lifetimes may be admitted at once. The dependency ledger validates the entire allowlisted graph and exposes ready nodes; the support workload retains serial dependent reads and gateway verification. Streamed inference cancellation closes its HTTP request without terminating the shared Ollama process. Two concurrent live requests returned correct plans in 6.156 seconds; this does not prove parallel compute inside Ollama. A dedicated persistent scheduler and broader approved capability adapters are still pending.

Further work includes broader approved support coverage, a durable scheduler, verified Ollama compute cancellation and parallelism, repeatable live-model reliability measurements, latest-patch full regression and browser testing, and independent production verification. No production-ready deployment or verified public demo is claimed.

## Repository guide

| Path | Purpose |
| --- | --- |
| [src/shadow_hunter/](src/shadow_hunter/) | Application, policy, gateway, local runtime and persistence |
| [tests/](tests/) | Regression and end-to-end verification |
| [docs/](docs/) | Architecture, security decisions and operational documentation |
| [infra/](infra/) | Optional cloud infrastructure and deployment configuration |
| [scripts/](scripts/) | Local verification and demonstration utilities |

For detailed historical milestones and release gates, see the [previous README snapshot](https://github.com/KUNDURUHIMANEESHREDDY/shadow-hunter/blob/1969e7ed5e26493ae9aead45ec11dcda5983ffb9/README.md) and [architecture documentation](docs/architecture.md).

## License

Released under the [MIT License](LICENSE). See [third-party notices](THIRD_PARTY_NOTICES.md) for applicable attribution.
