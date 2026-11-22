from __future__ import annotations


def test_lambda_entrypoint_exposes_handler():
    # Importing the module requires the AWS deployment extra (Mangum).
    from shadow_hunter.lambda_handler import handler

    assert callable(handler)


def _http_api_event(raw_path: str) -> dict:
    return {
        "version": "2.0",
        "routeKey": "GET /health",
        "rawPath": raw_path,
        "rawQueryString": "",
        "headers": {"host": "example.com", "x-forwarded-proto": "https"},
        "requestContext": {
            "accountId": "synthetic",
            "apiId": "synthetic",
            "domainName": "example.com",
            "http": {
                "method": "GET",
                "path": raw_path,
                "protocol": "HTTP/1.1",
                "sourceIp": "127.0.0.1",
                "userAgent": "pytest",
            },
            "requestId": "synthetic",
            "routeKey": "GET /health",
            "stage": "prod",
            "timeEpoch": 123,
        },
        "isBase64Encoded": False,
    }


def test_lambda_http_api_named_stage_prefix_reaches_fastapi_health(monkeypatch):
    import json
    import sys
    from types import ModuleType

    from fastapi import FastAPI
    import shadow_hunter.lambda_handler as lambda_handler

    # Test stage-path handling independently of the optional MCP runtime.
    app = FastAPI()

    @app.get("/health")
    def health():
        return {"status": "ok"}

    stub = ModuleType("shadow_hunter.api")
    stub.app = app
    monkeypatch.setitem(sys.modules, "shadow_hunter.api", stub)
    monkeypatch.setenv("SHADOW_HUNTER_API_BASE_PATH", "/prod")
    monkeypatch.setattr(lambda_handler, "_asgi_handler", None)

    staged = lambda_handler.handler(_http_api_event("/prod/health"), None)
    assert staged["statusCode"] == 200
    assert json.loads(staged["body"])["status"] == "ok"

    # The same warm handler must still accept an already-unprefixed path.
    unprefixed = lambda_handler.handler(_http_api_event("/health"), None)
    assert unprefixed["statusCode"] == 200
