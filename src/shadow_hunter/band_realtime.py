"""BAND Phoenix WebSocket wake-ups with bounded REST catch-up.

The WebSocket is a notification channel only. REST performs all claims,
acknowledgements, and replies using the fixed-room BandLyzrAdvisoryWorker.
The peer never chooses a tool, endpoint, model instruction, or output format.
"""
from __future__ import annotations

import json
import os
import random
import sys
import time
from dataclasses import dataclass
from typing import Callable, Any
from urllib.parse import urlencode

from .band_worker import BandLyzrAdvisoryWorker, BandRoomTransport
from .sponsors import LyzrAdvisor, SponsorConfigurationError, SponsorProviderError, _identifier

WS_ORIGIN = "wss://app.band.ai/api/v1/socket/websocket"
MAX_FRAME = 65536
MAX_RETRIES = 5
HEARTBEAT_SECONDS = 25
REST_BACKLOG_LIMIT = 10


class BandRealtimeError(RuntimeError):
    """WebSocket initialization, connection, or protocol failure."""


def parse_frame(raw: str | bytes) -> tuple[str | None, str | None, str, str, dict]:
    if not isinstance(raw, (str, bytes)) or len(raw) > MAX_FRAME:
        raise BandRealtimeError("Oversized or missing Band frame")
    try:
        frame = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise BandRealtimeError("Invalid Band frame JSON") from exc
    if (
        not isinstance(frame, list)
        or len(frame) != 5
        or any(item is not None and not isinstance(item, str) for item in frame[:2])
        or not isinstance(frame[2], str)
        or not isinstance(frame[3], str)
        or not isinstance(frame[4], dict)
    ):
        raise BandRealtimeError("Invalid Phoenix message envelope")
    return frame[0], frame[1], frame[2], frame[3], frame[4]


@dataclass
class BandRealtimeListener:
    """Single-room listener with hard runtime/message/reconnect budgets."""

    worker: BandLyzrAdvisoryWorker
    agent_id: str
    api_key: str
    room_id: str
    max_seconds: int = 600
    max_messages: int = 20
    max_reconnects: int = MAX_RETRIES
    connect: Callable[..., Any] | None = None
    clock: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep

    def __post_init__(self) -> None:
        _identifier(self.agent_id, "BAND agent ID")
        _identifier(self.room_id, "BAND room ID")
        if not isinstance(self.api_key, str) or len(self.api_key) < 8:
            raise SponsorConfigurationError("BAND API key is missing")
        if not (1 <= self.max_seconds <= 3600 and 1 <= self.max_messages <= 100):
            raise SponsorConfigurationError("Listener runtime limits are out of range")
        if not 0 <= self.max_reconnects <= 10:
            raise SponsorConfigurationError("Listener retry limit is out of range")

    @classmethod
    def from_environment(cls, **kwargs) -> "BandRealtimeListener":
        transport = BandRoomTransport.from_environment()
        advisor = LyzrAdvisor.from_environment()
        return cls(
            worker=BandLyzrAdvisoryWorker(transport, advisor),
            agent_id=os.environ.get("SHADOW_HUNTER_BAND_AGENT_ID", ""),
            api_key=transport.api_key,
            room_id=transport.chat_id,
            **kwargs,
        )

    def _connector(self):
        if self.connect is not None:
            return self.connect
        try:
            from websockets.sync.client import connect
        except ImportError as exc:
            raise SponsorConfigurationError(
                "Install websockets>=14,<17 to use BAND real-time mode"
            ) from exc
        return connect

    def _drain(self, remaining: int) -> int:
        completed = 0
        # Drain the bounded REST backlog on every new connection/wakeup.
        for _ in range(min(remaining, REST_BACKLOG_LIMIT)):
            result = self.worker.process_once()
            if result != "processed":
                break
            completed += 1
        return completed

    def run(self) -> dict[str, int | str]:
        connect = self._connector()
        start = self.clock()
        processed = 0
        reconnects = 0
        topic = f"chat_room:{self.room_id}"
        uri = WS_ORIGIN + "?" + urlencode({"vsn": "2.0.0", "agent_id": self.agent_id})
        while self.clock() - start < self.max_seconds and processed < self.max_messages:
            try:
                with connect(
                    uri,
                    additional_headers={"x-api-key": self.api_key},
                    open_timeout=7,
                    close_timeout=3,
                    max_size=MAX_FRAME,
                    ping_interval=20,
                ) as ws:
                    # REST catch-up handles missed events while offline.
                    processed += self._drain(self.max_messages - processed)
                    if processed >= self.max_messages:
                        break
                    ref = 1
                    join_ref = str(ref)
                    ws.send(json.dumps([join_ref, join_ref, topic, "phx_join", {}]))
                    joined = False
                    last_heartbeat = self.clock()
                    while (
                        self.clock() - start < self.max_seconds
                        and processed < self.max_messages
                    ):
                        # Regular Phoenix heartbeat (not merely WebSocket ping).
                        if self.clock() - last_heartbeat >= HEARTBEAT_SECONDS:
                            ref += 1
                            ws.send(json.dumps([None, str(ref), "phoenix", "heartbeat", {}]))
                            last_heartbeat = self.clock()
                        try:
                            raw = ws.recv(timeout=2)
                        except TimeoutError:
                            continue
                        _join, message_ref, message_topic, event, payload = parse_frame(raw)
                        if event == "phx_reply" and message_ref == join_ref and message_topic == topic:
                            if payload.get("status") != "ok":
                                raise BandRealtimeError("BAND refused room subscription")
                            joined = True
                        elif event == "message_created" and message_topic == topic and joined:
                            processed += self._drain(self.max_messages - processed)
                        elif event in {"phx_error", "phx_close"} and message_topic == topic:
                            raise BandRealtimeError("BAND room channel closed")
                    if self.clock() - start >= self.max_seconds:
                        break
            except (OSError, EOFError, TimeoutError, BandRealtimeError) as exc:
                if reconnects >= self.max_reconnects:
                    raise BandRealtimeError("BAND reconnection budget exhausted") from exc
                reconnects += 1
                # Bounded exponential backoff with jitter; never sleep beyond deadline.
                delay = min(2 ** (reconnects - 1), 16) + random.uniform(0, 0.25)
                remaining = self.max_seconds - (self.clock() - start)
                if remaining <= 0:
                    break
                self.sleep(min(delay, remaining))
                continue
        return {"status": "stopped", "processed": processed, "reconnects": reconnects}


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="BAND realtime room notifications for synthetic Lyzr advice")
    parser.add_argument("--max-seconds", type=int, default=600)
    parser.add_argument("--max-messages", type=int, default=20)
    parser.add_argument("--max-reconnects", type=int, default=5)
    args = parser.parse_args(argv)
    try:
        result = BandRealtimeListener.from_environment(
            max_seconds=args.max_seconds,
            max_messages=args.max_messages,
            max_reconnects=args.max_reconnects,
        ).run()
        print(json.dumps(result))
        return 0
    except (SponsorConfigurationError, SponsorProviderError, BandRealtimeError):
        print("BAND realtime listener not configured or connection failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
