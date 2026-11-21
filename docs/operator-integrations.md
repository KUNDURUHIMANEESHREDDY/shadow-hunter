# Operator integrations and secret management

The operator console exposes **Settings → Integrations & Secrets** for two backend-managed credentials:

- NVIDIA NIM API key: operator supplies the key once; the API writes it to the configured NVIDIA Secrets Manager secret.
- Red/Blue A2A signing keys: the backend generates independent 48-byte-plus random HMAC secrets, assigns separate key IDs to `red-agent` and `blue-agent`, and writes the map to the configured A2A Secrets Manager secret.

The browser never receives stored provider/HMAC values. The NIM form clears after save. The rotation endpoint returns key IDs only. Both mutations require operator authentication and append an audit event containing the integration name and operation, never the secret value.

## AWS deployment

When `NvidiaApiKeySecretArn` or `A2AKeysSecretArn` is empty, `infra/app/template.yaml` creates a dedicated Secrets Manager secret for that integration. Both resources use `DeletionPolicy: Retain`. If an external secret ARN is supplied, the application uses that exact ARN instead.

The Lambda role receives only `secretsmanager:GetSecretValue` and `secretsmanager:PutSecretValue` on the selected NVIDIA and A2A secret ARNs. It does not receive `CreateSecret`, `DeleteSecret`, `ListSecrets`, or broad Secrets Manager access. Do not point both settings at the same secret.

The operator must have the configured secret targets and Cognito operator identity provisioned by the deployment. The console's status endpoint reports only boolean configuration state.

## Local development

For the settings UI to save secrets locally, configure:

- `SHADOW_HUNTER_NIM_API_KEY_SECRET_ARN`
- `SHADOW_HUNTER_A2A_KEYS_SECRET_ARN`
- `AWS_REGION` (or `AWS_DEFAULT_REGION`)
- AWS credentials for the local process with GetSecretValue and PutSecretValue on those two exact secret ARNs.

The local operator console continues to accept `SHADOW_HUNTER_OPERATOR_TOKENS` through its password field. Local direct `NVIDIA_API_KEY` and `SHADOW_HUNTER_A2A_KEYS` remain supported when no Secrets Manager ARN is configured. If an ARN is configured, that managed secret takes precedence so updates made in the UI take effect on the next test/evaluation.

## Cognito operator login

Production login uses OAuth 2.0 authorization code flow with PKCE (S256). Configure:

- `SHADOW_HUNTER_AUTH_MODE=cognito`
- `SHADOW_HUNTER_COGNITO_OPERATOR_CLIENT_ID`
- `SHADOW_HUNTER_COGNITO_HOSTED_UI_DOMAIN` as an HTTPS origin, without a path/query/fragment.

The SAM template exposes `CognitoHostedUiDomain` and passes it to the API. Configure the Cognito operator app client as a **public client with no client secret**, authorization-code grant enabled, and `openid` scope enabled. Add the deployed console URL as both an allowed callback URL and an allowed sign-out URL. For the default API Gateway stage, the callback is:

`https://{api-id}.execute-api.{region}.amazonaws.com/prod/operator`

The app stores the short-lived OAuth state and PKCE verifier in session storage for the redirect transaction. The Cognito access token is held only in page memory; it is not written to local/session storage. The API independently validates the token and requires membership in `SHADOW_HUNTER_COGNITO_OPERATOR_GROUP`. The API Gateway operator route also uses its Cognito JWT authorizer.

The public `GET /operator/config` route returns only the auth mode, Cognito hosted UI origin, and public operator app-client ID. It does not return integration secrets or AWS secret ARNs.

## Operator workflow

1. Deploy the SAM stack with the existing Cognito and DynamoDB parameters, plus `CognitoHostedUiDomain`.
2. Open `/operator` and sign in through Cognito (production) or enter a local operator bearer token (development).
3. Open **Settings → Integrations & Secrets**.
4. Paste and save the NVIDIA API key. Use **Test connection** to make a bounded hosted NIM request.
5. Use **Generate / rotate signing keys** to create separate Red and Blue HMAC keys.
6. Confirm both statuses show configured, then run the synthetic Red/Blue evaluation.

Rotating A2A keys replaces both current keys. Existing messages signed with the previous keys will no longer validate. This application currently uses the keys for its in-process Red/Blue evaluation harness; do not treat this as authorization for exposing remote agent traffic. Remote A2A still needs a separate authenticated transport and network security design.

## Operational boundaries

- Saving or rotating secrets changes the active credentials immediately for subsequent requests. It does not deploy infrastructure.
- The NIM connection test makes a real, small hosted inference request and may incur provider usage.
- The Red/Blue evaluation remains bounded to three rounds and synthetic SQLite data.
- The console does not create arbitrary Secrets Manager resources or accept caller-supplied secret ARNs.
- If a secret write succeeds but the subsequent audit write fails, verify integration status before retrying; the Secrets Manager mutation and application audit store cannot participate in one atomic transaction.
