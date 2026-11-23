"""Bounded BAND receive/claim/reply worker for synthetic sponsor collaboration.

Band messages are untrusted data. Only exact, fixed scenario IDs may be
converted into Lyzr prompts. No external agent invokes business tools.
Run one process per configured BAND identity/room; polling is deliberately
not claimed to offer full WebSocket membership/reconnect semantics.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from .sponsors import (
    BAND_BASE, MAX_PROVIDER_RESPONSE_BYTES,
    BandDecisionPublisher, LyzrAdvisor, SponsorConfigurationError,
    SponsorProviderError, _HTTP, _identifier,
)

SYNTHETIC_SCENARIOS: dict[str, str] = {
    "scenario:cross-tenant-read": (
        "Synthetic-only: an AI tool proposes reading a fictional order "
        "belonging to a different tenant. Explain why independent tenant "
        "authorization must deny the request."
    ),
    "scenario:oversized-refund": (
        "Synthetic-only: a fictional refund request exceeds the configured "
        "self-service limit. Explain the escalation and operator approval "
        "boundary, without carrying out any refund."
    ),
    "scenario:unknown-tool": (
        "Synthetic-only: an AI attempts a tool name missing from the "
        "gateway allowlist. Explain why default-deny prevents execution."
    ),
    "scenario:approval-replay": (
        "Synthetic-only: an already-consumed approval capability is "
        "presented again. Explain why replay must be denied at execution."
    ),
}
MAX_REPLY_CHARS = 2400


@dataclass(frozen=True)
class BandRoomTransport:
    """REST-only, fixed-room Band API. The caller never chooses an URL."""
    api_key: str
    chat_id: str

    def __post_init__(self) -> None:
        # Reuse the same validation as the outbound Band integration.
        BandDecisionPublisher(self.api_key, self.chat_id)

    @classmethod
    def from_environment(cls) -> "BandRoomTransport":
        publisher = BandDecisionPublisher.from_environment()
        return cls(publisher.api_key, publisher.chat_id)

    def _request(
        self,
        method: str,
        suffix: str,
        payload: dict[str, Any] | None = None,
    ) -> tuple[int, dict[str, Any]]:
        if method not in {"GET", "POST"}:
            raise SponsorConfigurationError("Unsupported BAND request method")
        # suffixes are assembled exclusively by the typed methods below.
        url = f"{BAND_BASE}/api/v1/agent/chats/{self.chat_id}/messages{suffix}"
        data = None
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode()
            if len(data) > 8192:
                raise SponsorConfigurationError("BAND request exceeds size limit")
        req = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={"X-API-Key": self.api_key, "Content-Type": "application/json"},
        )
        try:
            with _HTTP.open(req, timeout=7.0) as response:
                status = response.status
                if not 200 <= status < 300:
                    raise SponsorProviderError("BAND request was rejected")
                raw = response.read(MAX_PROVIDER_RESPONSE_BYTES + 1)
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise SponsorProviderError("BAND request failed") from exc
        if len(raw) > MAX_PROVIDER_RESPONSE_BYTES:
            raise SponsorProviderError("BAND response exceeds size limit")
        if not raw:
            return status, {}
        try:
            result = json.loads(raw)
        except (ValueError, UnicodeError) as exc:
            raise SponsorProviderError("BAND response is not JSON") from exc
        if not isinstance(result, dict):
            raise SponsorProviderError("BAND response must be a JSON object")
        return status, result

    def next_message(self) -> tuple[int, dict[str, Any]]:
        return self._request("GET", "/next")

    def claim(self, message_id: str) -> int:
        mid = _identifier(message_id, "BAND message ID")
        return self._request("POST", f"/{mid}/processing")[0]

    def reply(self, recipient_id: str, content: str) -> None:
        sender = _identifier(recipient_id, "BAND recipient ID")
        if not isinstance(content, str) or not 1 <= len(content) <= MAX_REPLY_CHARS:
            raise SponsorConfigurationError("BAND reply length is invalid")
        self._request(
            "POST", "",
            {"message": {"content": content, "mentions": [{"id": sender}]}},
        )

    def processed(self, message_id: str) -> None:
        mid = _identifier(message_id, "BAND message ID")
        self._request("POST", f"/{mid}/processed")

    def failed(self, message_id: str) -> None:
        mid = _identifier(message_id, "BAND message ID")
        # Never send the provider exception, prompt or business data into Band.
        self._request("POST", f"/{mid}/failed", {"error": "Advisory worker failed"})


class BandLyzrAdvisoryWorker:
    """One best-effort, at-most-one-message turn with Band claim/ack."""

    def __init__(self, transport: BandRoomTransport, advisor: LyzrAdvisor):
        self.transport = transport
        self.advisor = advisor

    def process_once(self) -> str:
        status, response = self.transport.next_message()
        if status == 204:
            return "idle"
        message = response.get("data")
        if not isinstance(message, dict):
            raise SponsorProviderError("BAND returned an invalid message envelope")
        message_id = _identifier(message.get("id"), "BAND message ID")
        sender_id = _identifier(message.get("sender_id"), "BAND sender ID")
        incoming = message.get("content")
        if not isinstance(incoming, str) or len(incoming) > 2000:
            raise SponsorProviderError("BAND message content is invalid")
        claimed = self.transport.claim(message_id)
        if claimed == 204:
            return "claim_refused"
        try:
            command = incoming.strip()
            if command in SYNTHETIC_SCENARIOS:
                # Never forward any peer-authored text to Lyzr; it receives
                # only a fixed, synthetic, pre-reviewed scenario.
                advice = self.advisor.advise(SYNTHETIC_SCENARIOS[command])
                reply = (
                    "Lyzr advisory (untrusted; no tool authority): "
                    + advice[:MAX_REPLY_CHARS - 60]
                )
            else:
                reply = (
                    "Shadow Hunter accepts only synthetic scenario IDs: "
                    + ", ".join(SYNTHETIC_SCENARIOS)
                    + ". No customer/order data or tool commands are accepted."
                )
            self.transport.reply(sender_id, reply)
            self.transport.processed(message_id)
        except (SponsorConfigurationError, SponsorProviderError):
            try:
                self.transport.failed(message_id)
            except (SponsorConfigurationError, SponsorProviderError):
                pass
            raise
        return "processed"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="BAND-to-Lyzr synthetic-security-advice bridge; no tool authority"
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="Process at most one message (default)")
    mode.add_argument("--forever", action="store_true", help="Poll the configured room until interrupted")
    parser.add_argument("--max-messages", type=int, default=20, help="Hard cap on advisory messages per process (1-100)")
    parser.add_argument("--max-seconds", type=int, default=600, help="Hard cap on polling runtime (1-3600s)")
    args = parser.parse_args(argv)
    if not 1 <= args.max_messages <= 100 or not 1 <= args.max_seconds <= 3600:
        parser.error("Runtime limits are out of range")
    try:
        worker = BandLyzrAdvisoryWorker(
            BandRoomTransport.from_environment(),
            LyzrAdvisor.from_environment(),
        )
    except SponsorConfigurationError:
        print("BAND/Lyzr collaboration not configured", file=sys.stderr)
        return 2
    try:
        started = time.monotonic()
        handled = 0
        while time.monotonic() - started < args.max_seconds:
            result = worker.process_once()
            print(f"BAND worker status: {result}", flush=True)
            if result == "processed":
                handled += 1
            if not args.forever or handled >= args.max_messages:
                return 0
            if result != "processed":
                time.sleep(2.0)
        return 0
    except KeyboardInterrupt:
        return 0
    except SponsorProviderError:
        print("BAND/Lyzr collaboration request failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
