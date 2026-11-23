"""Non-destructive HTTP checks for Shadow Hunter's real AWS staging API.

No test tokens are fetched or printed. For full authenticated verification,
provide short-lived *synthetic* staging JWTs through environment variables.
The probe refuses non-staging hosts and follows no redirects.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from urllib import error, request
from urllib.parse import urlsplit

STAGING_BASE = "https://eh90jsiseg.execute-api.ap-southeast-2.amazonaws.com/prod"
_STAGING_HOST = "eh90jsiseg.execute-api.ap-southeast-2.amazonaws.com"


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes = b""


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_base_url(base_url: str) -> str:
    parsed = urlsplit(base_url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != _STAGING_HOST
        or parsed.port not in (None, 443)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path.rstrip("/") != "/prod"
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Only the approved Shadow Hunter AWS staging URL is permitted")
    return base_url.rstrip("/")


def send(base_url: str, method: str, path: str, *,
         token: str | None = None, payload: dict | None = None) -> Response:
    base_url = validate_base_url(base_url)
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("Invalid probe path")
    headers = {"Accept": "application/json"}
    body = None
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token is not None:
        if not token or any(char.isspace() for char in token):
            raise ValueError("Invalid access token")
        headers["Authorization"] = "Bearer " + token
    req = request.Request(base_url + path, data=body, headers=headers, method=method)
    opener = request.build_opener(_NoRedirect())
    try:
        with opener.open(req, timeout=12) as res:
            return Response(res.status, res.read(65536))
    except error.HTTPError as exc:
        # Never output a provider response body: it may contain tenant data.
        return Response(exc.code)


def run_checks(base_url: str, tokens: dict[str, str], *,
               synthetic_order_id: str | None = None,
               invoke_model: bool = False,
               boundary_only: bool = False,
               sender=send) -> tuple[bool, list[str]]:
    """Return (passed, concise results); missing full-test tokens fail closed."""
    validate_base_url(base_url)
    results = []
    all_ok = True

    def check(label: str, method: str, path: str, expected: int,
              *, token: str | None = None, payload: dict | None = None) -> Response:
        nonlocal all_ok
        response = sender(base_url, method, path, token=token, payload=payload)
        success = response.status == expected
        all_ok = all_ok and success
        results.append(f"{'PASS' if success else 'FAIL'} {label}: HTTP {response.status} (expected {expected})")
        return response

    health = check("public health", "GET", "/health", 200)
    check("public operator config", "GET", "/operator/config", 200)
    check("reject anonymous chat", "POST", "/v1/agent/chat", 401,
          payload={"prompt": "hello"})
    check("reject anonymous tool", "POST", "/v1/agent/tools/get_order", 401,
          payload={"arguments": {"order_id": "synthetic"}})
    check("reject anonymous operator", "GET", "/v1/operator/overview", 401)
    # Gateway must reject *invalid* Bearer tokens even when a route has a JWT authorizer.
    check("reject invalid delegated token", "POST",
          "/v1/agent/tools/get_order", 401, token="invalid.invalid.invalid",
          payload={"arguments": {"order_id": "synthetic"}})

    if boundary_only:
        results.append("BOUNDARY ONLY: authenticated E2E was not exercised")
        return all_ok, results

    missing = [key for key in ("customer", "operator", "obo") if not tokens.get(key)]
    if missing or not synthetic_order_id:
        results.append("INCOMPLETE: short-lived synthetic customer, operator, and OBO JWTs plus a synthetic order ID are required")
        return False, results

    try:
        body = json.loads(health.body)
        if body.get("agentcore_configured") is not True or body.get("demo_mode") is True:
            results.append("FAIL AgentCore Harness not ready in staging (or demo mode enabled)")
            all_ok = False
    except (ValueError, AttributeError, TypeError):
        results.append("FAIL health payload is not valid JSON")
        all_ok = False

    check("authenticated operator", "GET", "/v1/operator/overview", 200,
          token=tokens["operator"])
    check("authenticated delegated read-only tool", "POST",
          "/v1/agent/tools/get_order", 200, token=tokens["obo"],
          payload={"arguments": {"order_id": synthetic_order_id}})
    check("reject original customer token at tool boundary", "POST",
          "/v1/agent/tools/get_order", 401, token=tokens["customer"],
          payload={"arguments": {"order_id": synthetic_order_id}})
    if invoke_model:
        check("authenticated Harness chat", "POST", "/v1/agent/chat", 200,
              token=tokens["customer"],
              payload={"prompt": "Describe your capabilities without calling tools or requesting a refund."})
    else:
        results.append("NOT RUN: Harness inference requires --invoke-model (potential AWS charges)")
        all_ok = False  # Full E2E is incomplete without the actual managed Harness.
    return all_ok, results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=STAGING_BASE)
    parser.add_argument("--boundary-only", action="store_true",
                        help="Check only public and unauthenticated denial paths")
    parser.add_argument("--invoke-model", action="store_true",
                        help="Exercise live authenticated Harness inference (may incur AWS charges)")
    parser.add_argument("--synthetic-order-id",
                        help="ID of a synthetic staging order, never a real customer's order")
    args = parser.parse_args(argv)
    if args.boundary_only and args.invoke_model:
        parser.error("--boundary-only and --invoke-model are mutually exclusive")
    tokens = {
        "customer": os.environ.get("SHADOW_HUNTER_E2E_CUSTOMER_JWT", ""),
        "obo": os.environ.get("SHADOW_HUNTER_E2E_OBO_JWT", ""),
        "operator": os.environ.get("SHADOW_HUNTER_E2E_OPERATOR_JWT", ""),
    }
    try:
        passed, results = run_checks(
            args.base_url, tokens, synthetic_order_id=args.synthetic_order_id,
            invoke_model=args.invoke_model, boundary_only=args.boundary_only,
        )
    except (ValueError, error.URLError, TimeoutError) as exc:
        print("FAIL staging probe could not complete:", type(exc).__name__, file=sys.stderr)
        return 2
    for result in results:
        print(result)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
