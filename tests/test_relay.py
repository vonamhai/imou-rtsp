from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

from app.imou.p2p import ImouP2PError
from app.relay import P2PFront


class FakeRelay:
    def __init__(self, upstream_port: int, fail: Exception | None = None) -> None:
        self.upstream_port = upstream_port
        self.fail = fail
        self.local_port: int | None = None
        self.ready = False
        self.closed = False

    async def async_start(self) -> None:
        await asyncio.sleep(0.05)
        if self.fail is not None:
            raise self.fail
        self.local_port = self.upstream_port
        self.ready = True

    async def async_close(self) -> None:
        self.closed = True
        self.ready = False


async def _echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(4096):
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()


async def _wait_for(predicate: Any, timeout: float = 5.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not predicate():
        if loop.time() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(0.02)


async def test_front_tunnels_buffers_and_closes_when_idle() -> None:
    echo = await asyncio.start_server(_echo, "127.0.0.1", 0)
    echo_port = int(echo.sockets[0].getsockname()[1])
    relays: list[FakeRelay] = []

    def factory(config: Any) -> FakeRelay:
        relay = FakeRelay(echo_port)
        relays.append(relay)
        return relay

    front = P2PFront(SimpleNamespace(serial="ABC"), idle_timeout=0.3, factory=factory)
    port = await front.open()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        request = b"OPTIONS rtsp://127.0.0.1/cam RTSP/1.0\r\nCSeq: 1\r\n\r\n"
        writer.write(request)
        await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(len(request)), 5) == request
        assert front.status == "ready"

        reader2, writer2 = await asyncio.open_connection("127.0.0.1", port)
        writer2.write(b"ping")
        await writer2.drain()
        assert await asyncio.wait_for(reader2.readexactly(4), 5) == b"ping"
        assert len(relays) == 1

        writer.close()
        writer2.close()
        await _wait_for(lambda: front.clients == 0)
        await _wait_for(lambda: relays[0].closed)
        assert front.status == "idle"
    finally:
        await front.close()
        echo.close()


async def test_front_reports_failures_and_backs_off() -> None:
    relays: list[FakeRelay] = []

    def factory(config: Any) -> FakeRelay:
        relay = FakeRelay(0, fail=ImouP2PError("device_offline"))
        relays.append(relay)
        return relay

    front = P2PFront(SimpleNamespace(serial="ABC"), idle_timeout=1, factory=factory)
    port = await front.open()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"OPTIONS")
        await writer.drain()
        assert await asyncio.wait_for(reader.read(), 5) == b""
        writer.close()
        assert front.status == "error:device_offline"
        assert len(relays) == 1 and relays[0].closed

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        assert await asyncio.wait_for(reader.read(), 5) == b""
        writer.close()
        assert len(relays) == 1
    finally:
        await front.close()


async def test_config_change_restarts_relay() -> None:
    echo = await asyncio.start_server(_echo, "127.0.0.1", 0)
    echo_port = int(echo.sockets[0].getsockname()[1])
    relays: list[FakeRelay] = []

    def factory(config: Any) -> FakeRelay:
        relay = FakeRelay(echo_port)
        relays.append(relay)
        return relay

    front = P2PFront(SimpleNamespace(serial="ABC", pw="1"), idle_timeout=30, factory=factory)
    port = await front.open()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"a")
        await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(1), 5) == b"a"
        writer.close()
        await _wait_for(lambda: front.clients == 0)

        front.update_config(SimpleNamespace(serial="ABC", pw="2"))
        await _wait_for(lambda: relays[0].closed)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"b")
        await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(1), 5) == b"b"
        writer.close()
        assert len(relays) == 2
    finally:
        await front.close()
        echo.close()
