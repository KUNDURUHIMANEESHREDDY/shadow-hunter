# Devpost submission draft

## Project name
Shadow Hunter

## Tagline
Autonomous intelligence. Deterministic security.

## Inspiration
Autonomous agents increasingly interact with business tools. A language model can suggest an action, but its output should never be the authority that decides whether sensitive data or operations are accessible.

## What it does
Shadow Hunter is a governance and security control plane for autonomous AI agents. It evaluates proposed tool calls against deterministic policies and produces ALLOW, DENY or ESCALATE decisions. Its initial workload is synthetic customer support and refunds. Sensitive requests require independent human approval, and policy decisions are recorded in correlated audit evidence.

## How we built it
Python, FastAPI, SQLite, optional DynamoDB, an authenticated tool gateway, an operator console, signed in-process agent messages, and a local Qwen planning integration. The Red/Blue evaluation laboratory uses controlled synthetic scenarios and verifies persisted policy evidence. BAND and Lyzr adapters, a Finch-ready audit skill, and an AdaL storyboard are prepared; live sponsor connectivity and publication are not yet verified.

## Accomplishments
At baseline 89d1b61 the local deterministic evaluation passed all eight expected outcomes: seven unsafe synthetic actions were blocked and one legitimate control was allowed. No refunds were executed. Thirty-six focused API and sponsor-boundary tests passed. These are bounded synthetic results, not claims of universal protection or live hosted-model performance.

## Challenges and next steps
Verify a real authorized sponsor collaboration, expand independent live-model evaluation, polish the demo and complete staging release gates. Production deployment is not claimed.

## Links
Repository: https://github.com/KUNDURUHIMANEESHREDDY/shadow-hunter
License: MIT
Demo video and team details: to be supplied after confirmation.
