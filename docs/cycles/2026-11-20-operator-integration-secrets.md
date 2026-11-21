# Engineering cycle - operator integration secrets and Cognito login

- Date: 2026-11-20
- Scope: add authenticated in-app management for NVIDIA NIM and Red/Blue A2A credentials, plus Cognito PKCE operator sign-in.
- Status: implementation added; focused Python tests pass; AWS/SAM deployment and live Cognito/NIM integration remain unverified.

## Observable behavior

- The operator console has a Settings → Integrations & Secrets panel.
- An authenticated operator can save an NVIDIA API key to the fixed configured Secrets Manager ARN and trigger a bounded hosted NIM connection probe.
- An authenticated operator can rotate Red and Blue HMAC credentials. The backend generates independent random keys and writes them to the fixed A2A Secrets Manager ARN. The browser and API response receive key IDs only.
- The API reports only boolean secret configuration state.
- Production operator login/logout uses Cognito authorization-code flow with PKCE (S256). The access token stays in page memory; OAuth state and verifier are transient session-storage values. Local development retains the opaque bearer-token input.
- SAM creates retained per-environment Secrets Manager resources when external ARNs are not supplied. Lambda permissions are limited to GetSecretValue and PutSecretValue on the two selected secret ARNs.

## Security boundaries

- The browser cannot submit a Secrets Manager ARN or choose an arbitrary secret target.
- NVIDIA and HMAC secret values are never returned, logged, audited, or stored in browser storage.
- The operator API checks operator identity before reading status, saving credentials, testing NIM, or rotating keys.
- A configured Secrets Manager ARN takes precedence over direct local environment values, ensuring console changes are used on the next NIM/A2A initialization.
- A2A rotation replaces both keys; it is an operator action with an explicit browser confirmation.
- The public operator config route returns only the auth mode, Cognito hosted UI origin, and public app-client ID.
- No AWS resource was created, no secret was modified, and no deployment was performed during this cycle.

## Verification

Focused command:

`python -m pytest tests/test_settings.py tests/test_operator_settings_api.py tests/test_nim.py tests/test_agents.py -q`

Final focused result: **41 passed in 6.17s**.

The API tests use a local FastAPI test client, a disposable SQLite store, a fake operator authenticator, and a fake Secrets Manager adapter. They verify authorization, no secret echo, audit redaction, key separation, malformed key rejection, and managed-secret precedence. They do not prove IAM or AWS service behavior.

The first test collection attempt exposed an existing local MCP SDK mismatch: `mcp.server.MCPServer` is unavailable in the installed package. The API route tests isolate the MCP runtime with a test-only adapter; the product dependency mismatch remains outside this feature.

## Deployment requirements not yet verified

- Run SAM validation/build against `infra/app/template.yaml`.
- Provision or confirm Cognito Hosted UI domain, operator public app client, authorization-code grant, PKCE, `openid` scope, callback URL, and operator group claim.
- Deploy the SAM stack and verify the Lambda role can read/write only the two selected secret ARNs.
- Save an actual NVIDIA API key through the UI and run the connection probe.
- Generate Red/Blue keys through the UI, then run one hosted synthetic evaluation.
- Test Cognito login and token expiry against a deployed Cognito user pool.

The operator console and backend are not production-deployed. The feature is implemented locally but AWS permissions, hosted UI configuration, provider credentials, and live inference are unverified.

Additional final verification after the status and audit failure-path refinements:

- `python -m compileall -q src/shadow_hunter tests`: passed.
- Extracted operator inline JavaScript and ran `node --check`: passed.
- Parsed `infra/app/template.yaml` with PyYAML and checked the two secret resources exist: passed. This is a YAML parse, not SAM/CloudFormation schema validation.
- `git diff --check`: passed.
- Full suite, `python -m pytest -q`: **139 passed, 1 failed**. The only failure is the pre-existing local environment limitation `ModuleNotFoundError: No module named 'mangum'` in `tests/test_lambda_handler.py`. The dependency is declared in the project's AWS extra but is not installed in this Python environment.
- SAM CLI and cfn-lint are not installed, so formal template validation/build was not run.
