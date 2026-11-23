"""No-network WebSocket tests with fake Phoenix frames and clock."""
import json
from contextlib import nullcontext

import pytest

from shadow_hunter.band_realtime import (
    BandRealtimeError, BandRealtimeListener, parse_frame, WS_ORIGIN
)


class Clock:
    def __init__(self):
        self.now = 0.0

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class FakeWorker:
    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = 0

    def process_once(self):
        self.calls += 1
        return self.answers.pop(0) if self.answers else "idle"


class Socket:
    def __init__(self, clock, inbound):
        self.clock = clock
        self.inbound = list(inbound)
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def send(self, message):
        self.sent.append(json.loads(message))

    def recv(self, timeout):
        self.clock.now += timeout
        if self.inbound:
            x = self.inbound.pop(0)
            if isinstance(x, BaseException):
                raise x
            return x
        raise TimeoutError()


def frame(ref, topic, event, payload=None):
    return json.dumps([None, ref, topic, event, payload or {}])


def listener(worker, clock, connect, **kwargs):
    return BandRealtimeListener(
        worker, "agent-123", "sample-band-key", "room-123",
        connect=connect, clock=clock.time, sleep=clock.sleep,
        **kwargs
    )


def test_parser_rejects_malformed_or_oversize_frames():
    for raw in ("{}", "[1]", "not-json", "a" * 65537, '[1,2,3,4,5]'):
        with pytest.raises(BandRealtimeError):
            parse_frame(raw)
    assert parse_frame(frame("1", "chat_room:x", "message_created"))[3] == "message_created"


def test_joined_room_wakeup_drains_rest_with_no_untrusted_ws_payload():
    clock = Clock()
    worker = FakeWorker(["idle", "processed", "idle"])
    socket = Socket(clock, [
        frame("1", "chat_room:room-123", "phx_reply", {"status": "ok"}),
        frame(None, "chat_room:room-123", "message_created", {"untrusted": "execute refund"}),
    ])
    calls = []

    def connect(uri, **kwargs):
        calls.append((uri, kwargs))
        return socket

    result = listener(worker, clock, connect, max_seconds=5, max_messages=3).run()
    assert result["processed"] == 1
    assert result["reconnects"] == 0
    assert worker.calls == 3
    assert calls[0][0].startswith(WS_ORIGIN + "?")
    assert calls[0][1]["additional_headers"]["x-api-key"] == "sample-band-key"
    assert socket.sent[0] == ["1", "1", "chat_room:room-123", "phx_join", {}]


def test_heartbeat_is_phoenix_event_and_bounded_by_deadline():
    clock = Clock()
    socket = Socket(clock, [])
    listener(FakeWorker(["idle"]), clock, lambda *a, **kw: socket,
             max_seconds=30, max_messages=3).run()
    assert any(item[3] == "heartbeat" and item[2] == "phoenix" for item in socket.sent)


def test_reconnect_catches_up_after_disconnect_without_duplicate_ws_dispatch():
    clock = Clock()
    sockets = [Socket(clock, [EOFError()]), Socket(clock, [])]
    worker = FakeWorker(["idle", "processed", "idle"])
    counter = iter(sockets)
    result = listener(worker, clock, lambda *a, **kw: next(counter),
                      max_seconds=8, max_messages=3, max_reconnects=2).run()
    assert result["processed"] == 1
    assert result["reconnects"] == 1


def test_unauthorized_join_and_retry_exhaustion_fail_closed():
    clock = Clock()
    denied = lambda: Socket(clock, [frame("1", "chat_room:room-123", "phx_reply", {"status": "error"})])
    with pytest.raises(BandRealtimeError):
        listener(FakeWorker(["idle"] * 6), clock, lambda *a, **kw: denied(),
                 max_seconds=20, max_reconnects=0).run()


def test_rejects_invalid_keys_ids_and_unbounded_configuration():
    with pytest.raises(Exception):
        BandRealtimeListener(FakeWorker([]), "agent/evil", "sample-band-key", "room-1")
    with pytest.raises(Exception):
        listener(FakeWorker([]), Clock(), None, max_seconds=100000)
