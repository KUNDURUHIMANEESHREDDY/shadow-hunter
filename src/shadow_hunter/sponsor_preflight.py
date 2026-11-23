"""Read-only sponsor configuration and Band identity preflight.

No credentials or room identifiers are printed, and Lyzr inference is not
called by this tool. Use --band-auth only with the test account owner's consent.
"""
from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request

from shadow_hunter.sponsors import _NoRedirect, sponsor_status


def check_band_auth() -> str:
    key = os.environ.get("SHADOW_HUNTER_BAND_API_KEY", "")
    if not key:
        return "not_configured"
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(
        "https://app.band.ai/api/v1/agent/me",
        headers={"x-api-key": key, "Accept": "application/json"},
        method="GET",
    )
    try:
        with opener.open(req, timeout=5) as response:
            # Identity presence only, not response body or identifiers.
            return "authenticated" if response.status == 200 else "unverified"
    except urllib.error.HTTPError as exc:
        return "unauthorized" if exc.code in (401, 403) else "unverified"
    except (urllib.error.URLError, TimeoutError, OSError):
        return "unreachable"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Redacted sponsor configuration preflight")
    parser.add_argument("--band-auth", action="store_true", help="Opt-in read-only request to BAND /agent/me")
    args = parser.parse_args(argv)
    status = sponsor_status()
    data = {
        "lyzr": {
            "configured": status["lyzr"]["configured"],
            "live_authenticated": "not_checked",
        },
        "band": {
            "configured": status["band"]["configured"],
            "outbound_ready": status["band"]["publication_ready"],
            "live_authenticated": check_band_auth() if args.band_auth else "not_checked",
        },
        "finch": {"skill_package": "prepared", "marketplace_published": "unverified"},
        "adal": {"demo_brief": "prepared", "external_video_export": "unverified"},
    }
    print(json.dumps(data, indent=2))
    return 0 if all([status["lyzr"]["configured"], status["band"]["configured"]]) else 2


if __name__ == "__main__":
    raise SystemExit(main())
