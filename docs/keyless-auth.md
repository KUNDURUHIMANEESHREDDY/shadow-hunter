# Shadow Hunter — browser authentication without developer access keys

The keyless workflow has two separate trust boundaries:

1. **AWS developer login:** Native AWS CLI v2 browser sign-in generates temporary
   AWS credentials for the signed-in developer. It does not ask for IAM user access
   keys and does not put passwords or OAuth tokens in the application repository.
2. **Customer/operator application sign-in:** Amazon Cognito authorization-code
   + PKCE obtains scoped user JWTs. Public browser app clients have **no client
   secret**. The Shadow Hunter API independently validates signatures, identity,
   token use, expiry, scopes and trusted tenant/customer claims.

Cloud Lambda and AgentCore workers use attached IAM execution roles for AWS
service calls. A confidential machine-to-machine OAuth client still has a
server-side credential managed by AWS (such as Secrets Manager). User browser
login does **not** eliminate that machine credential or make it safe to expose.

## Connect AWS using a browser

Requirements: AWS CLI v2.32.0+, your authorized AWS account, and a browser.
On the authorized computer, from the repository root:

    python scripts/connect_aws.py --profile shadow-hunter-staging
    python scripts/connect_aws.py --profile shadow-hunter-staging --check --verify-staging

The first invocation runs native **aws login** with no static access-key
configuration; AWS opens its own sign-in page. The second command checks STS
and the existing Cognito staging pool and client configuration **read only**.
To guard against the wrong account, add:

    --expected-account YOUR_12_DIGIT_ACCOUNT_ID

The CLI prints a masked account suffix and generic failure reasons. It never
prints any AWS access key, secret, JWT, MFA seed, or OAuth code. The local
runner filters environment access keys before launching AWS CLI so stale
environment keys cannot silently override the browser-authenticated profile.

You may also use **aws logout --profile shadow-hunter-staging** to end a
developer session. This has no effect on customer Cognito sessions.

## Customer sign-in

Visit **/customer** on the deployed Shadow Hunter HTTPS API domain.
The customer page fetches **/customer/config** and shows **Sign in with Cognito**
when the backend is set to Cognito mode. It creates a random state and PKCE
verifier, redirects to the configured Cognito hosted-login domain, and checks
the state before exchanging its authorization code over HTTPS. The backend
**/v1/customer/session** endpoint validates the new access token before the
chat is made available.

The page requests:

    openid email shadow-hunter/customer shadow-hunter-api/refunds

The custom scopes are needed for the Cognito customer identity contract and
future on-behalf-of (OBO) delegated-tool exchange. An SRP-only access token
without the appropriate OAuth scopes does **not** prove delegated OBO works.

Access tokens exist only in JavaScript memory (not localStorage, cookies or
sessionStorage). The short-lived PKCE challenge is in sessionStorage during the
redirect and is then cleared. Refreshing the customer page signs the user out
of that tab; sign-out also uses Cognito's logout endpoint. Chat requests send
only the Bearer access token and user prompt, not an AWS access key or client
secret. If the managed Harness is unavailable, the UI does not claim success.

## Staging callback configuration is still required

The existing Sydney staging Customer app client currently lists:

    Callback: https://localhost/shadow-hunter-customer
    Logout:   https://localhost/

These URLs **do not match** the newly implemented /customer page.
A real deployed login needs the exact customer page HTTPS URL, for example:

    https://YOUR_AUTHORIZED_API_HOST/prod/customer

The **callback and logout URLs must match the OAuth app-client settings
exactly** (scheme, host, port and path). Update the reviewed staging identity
CloudFormation parameters (CustomerCallbackUrl and CustomerLogoutUrl), then
validate the app client before enabling login. Do not use a wildcard or unowned
domain. No stack update, new paid resource or customer account is made by this
implementation.

The existing operator UI already supports **/operator** and its Cognito
authorization-code + PKCE flow. Its client, group and operator scope remain
separate; the customer token cannot access operator routes. Existing agent
and API access checks remain enforced on the server.

## Test and release evidence

    python -m pytest -q tests/test_keyless_auth.py
    python -m pytest -q tests/e2e/test_customer_keyless_login.py --browser chromium
    python -m pytest -q
    python scripts/validate-repo.py

Browser E2E uses intercepted fake Cognito endpoints and a loopback FastAPI
server with synthetic customer tokens. It checks PKCE S256 challenge matching,
redirect state, backend token verification, and role separation. It **does not**
authenticate a real Cognito user or verify live two-tenant OBO exchange.

The AWS read-only staging check passed with an existing authorized AWS
session, without generating or logging IAM access keys. Real customer PKCE
sign-in, OBO delegation, two-tenant staging isolation, and managed AgentCore
execution remain separate **NO-GO production release gates** until tested.
