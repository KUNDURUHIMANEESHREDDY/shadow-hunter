"""AWS Lambda entrypoint for the Shadow Hunter FastAPI application."""
from __future__ import annotations

from typing import Any

from mangum import Mangum

_asgi_handler: Any | None = None


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Initialize FastAPI/Mangum on first invocation and reuse warm handler."""
    global _asgi_handler
    if _asgi_handler is None:
        from .api import app

        _asgi_handler = Mangum(app, lifespan="off")
    return _asgi_handler(event, context)
