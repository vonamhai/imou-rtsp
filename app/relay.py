"""Stable loopback RTSP ports backed by lazily started Imou P2P relays.

MediaMTX needs a fixed source URL, but an ``ImouP2PRelay`` listens on a new
ephemeral port every time it starts. A ``P2PFront`` owns one stable port per
device, starts the relay when MediaMTX connects and stops it after the last
client has been gone for ``idle_timeout`` seconds.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import replace
from typing import Any

from .imou.models import ImouDevice
from .imou.p2p import ImouP2PDeviceConfig, ImouP2PError, ImouP2PRelay, p2p_config_from_device

_LOGGER = logging.getLogger(__name__)
_MAX_PENDING = 1 << 20
_CHUNK = 65536
_RETRY_DELAYS = (5, 10, 20, 40, 60)

RelayFactory = Callable[[ImouP2PDeviceConfig], Any]


def front_config(device: ImouDevice, username: str = "", password: str = "") -> ImouP2PDeviceConfig:
    """Return the device P2P config; a password typed in the UI wins.

    The P2P handshake is signed with the camera's local login (``admin`` +
    Safety Code). The cloud's ``p2pToken``/``accountNew`` are frequently
    encrypted with a key the bridge does not have, so they only serve as a
    fallback when the user has not entered the Safety Code.
    """
    config = p2p_config_from_device(device)
    if not password:
        return config
    return replace(
        config,
        p2p_username=username or "admin",
        p2p_password=password,
    )


def _consume_result(task: asyncio.Task[Any]) -> None:
    if not task.cancelled():
        task.exception()


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    while data := await reader.read(_CHUNK):
        writer.write(data)
        await writer.drain()


async def _close_writer(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        async with asyncio.timeout(3):
            await writer.wait_closed()
    except (TimeoutError, OSError):
        writer.transport.abort()


class P2PFront:
    """One fixed 127.0.0.1 port that tunnels to a camera through P2P."""

    def __init__(
        self,
        config: ImouP2PDeviceConfig,
        *,
        idle_timeout: float,
        start_timeout: float = 35.0,
        factory: RelayFactory = ImouP2PRelay,
    ) -> None:
        self.config = config
        self.idle_timeout = idle_timeout
        self.start_timeout = start_timeout
        self.port: int | None = None
        self.clients = 0
        self.last_error = ""
        self._factory = factory
        self._relay: Any = None
        self._stale = False
        self._server: asyncio.AbstractServer | None = None
        self._start_task: asyncio.Task[Any] | None = None
        self._idle_task: asyncio.Task[None] | None = None
        self._client_tasks: set[asyncio.Task[Any]] = set()
        self._failures = 0
        self._retry_at = 0.0
        self._closed = False

    @property
    def status(self) -> str:
        if self._relay is not None and getattr(self._relay, "ready", False) and not self._stale:
            return "ready"
        if self._start_task is not None and not self._start_task.done():
            return "connecting"
        if self.last_error:
            return f"error:{self.last_error}"
        return "idle"

    async def open(self) -> int:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = int(self._server.sockets[0].getsockname()[1])
        return self.port

    def update_config(self, config: ImouP2PDeviceConfig) -> None:
        if config == self.config:
            return
        self.config = config
        self._stale = True
        self._failures = 0
        self._retry_at = 0.0
        if self.clients == 0:
            self._schedule_idle(0)

    async def close(self) -> None:
        self._closed = True
        if self._server is not None:
            self._server.close()
        for task in (self._idle_task, self._start_task, *self._client_tasks):
            if task is not None and not task.done():
                task.cancel()
        tasks = [task for task in (self._start_task, *self._client_tasks) if task is not None]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await self._close_relay()
        if self._server is not None:
            with suppress(Exception):
                await asyncio.wait_for(self._server.wait_closed(), 5)

    async def _close_relay(self) -> None:
        relay = self._relay
        self._relay = None
        if relay is None:
            return
        try:
            await asyncio.wait_for(relay.async_close(), 15)
        except (ImouP2PError, TimeoutError, OSError) as err:
            _LOGGER.debug("P2P relay close for %s: %s", self.config.serial, err)
        except Exception:  # noqa: BLE001 - never let cleanup crash the bridge
            _LOGGER.exception("Unexpected error while closing a P2P relay")

    def _schedule_idle(self, delay: float) -> None:
        if self._idle_task is not None and not self._idle_task.done():
            self._idle_task.cancel()
        self._idle_task = asyncio.create_task(self._idle_close(delay))

    async def _idle_close(self, delay: float) -> None:
        await asyncio.sleep(delay)
        start = self._start_task
        if start is not None and not start.done():
            with suppress(Exception):
                await asyncio.shield(start)
        if self.clients == 0 and self._relay is not None:
            _LOGGER.info("Closing idle P2P relay for %s", self.config.serial)
            await self._close_relay()

    async def _ensure_relay(self) -> Any:
        relay = self._relay
        if relay is not None and relay.ready and not self._stale:
            return relay
        if self._start_task is None or self._start_task.done():
            remaining = self._retry_at - time.monotonic()
            if remaining > 0:
                raise ImouP2PError(self.last_error or "retry_wait")
            self._start_task = asyncio.create_task(self._start_relay())
            self._start_task.add_done_callback(_consume_result)
        return await asyncio.shield(self._start_task)

    async def _start_relay(self) -> Any:
        await self._close_relay()
        self._stale = False
        _LOGGER.info("Starting P2P relay for %s", self.config.serial)
        relay: Any = None
        try:
            relay = self._factory(self.config)
            self._relay = relay
            await asyncio.wait_for(relay.async_start(), self.start_timeout)
        except Exception as err:  # noqa: BLE001 - every failure becomes a retry stage
            if isinstance(err, ImouP2PError):
                stage = err.stage
            elif isinstance(err, TimeoutError):
                stage = "timeout"
            elif isinstance(err, OSError):
                stage = "network"
            else:
                _LOGGER.exception("Unexpected P2P relay failure")
                stage = "internal"
            self.last_error = stage
            delay = _RETRY_DELAYS[min(self._failures, len(_RETRY_DELAYS) - 1)]
            self._failures += 1
            self._retry_at = time.monotonic() + delay
            _LOGGER.warning(
                "P2P relay for %s failed (%s); next attempt allowed in %ss",
                self.config.serial,
                stage,
                delay,
            )
            if relay is not None and self._relay is relay:
                await self._close_relay()
            raise ImouP2PError(stage) from err
        self.last_error = ""
        self._failures = 0
        self._retry_at = 0.0
        _LOGGER.info("P2P relay for %s is ready", self.config.serial)
        return relay

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._client_tasks.add(task)
        self.clients += 1
        if self._idle_task is not None and not self._idle_task.done():
            self._idle_task.cancel()
        upstream: asyncio.StreamWriter | None = None
        try:
            if self._closed:
                return
            pending = bytearray()
            ensure = asyncio.ensure_future(self._ensure_relay())
            read_task = asyncio.ensure_future(reader.read(_CHUNK))
            try:
                while not ensure.done():
                    await asyncio.wait({ensure, read_task}, return_when=asyncio.FIRST_COMPLETED)
                    if read_task.done():
                        data = read_task.result()
                        if not data:
                            return
                        pending.extend(data)
                        if len(pending) > _MAX_PENDING:
                            return
                        read_task = asyncio.ensure_future(reader.read(_CHUNK))
                if read_task.done():
                    data = read_task.result()
                    if not data:
                        return
                    pending.extend(data)
            finally:
                if not read_task.done():
                    read_task.cancel()
                    with suppress(asyncio.CancelledError):
                        await read_task
                if not ensure.done():
                    ensure.cancel()
                    with suppress(asyncio.CancelledError, ImouP2PError):
                        await ensure
            try:
                relay = ensure.result()
            except ImouP2PError:
                return
            port = relay.local_port
            if port is None:
                return
            up_reader, upstream = await asyncio.open_connection("127.0.0.1", port)
            if pending:
                upstream.write(bytes(pending))
                await upstream.drain()
            pipes = {
                asyncio.ensure_future(_pipe(reader, upstream)),
                asyncio.ensure_future(_pipe(up_reader, writer)),
            }
            try:
                await asyncio.wait(pipes, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for pipe in pipes:
                    pipe.cancel()
                await asyncio.gather(*pipes, return_exceptions=True)
        except (OSError, asyncio.IncompleteReadError) as err:
            _LOGGER.debug("P2P client for %s ended: %s", self.config.serial, err)
        finally:
            if upstream is not None:
                await _close_writer(upstream)
            await _close_writer(writer)
            self.clients -= 1
            if task is not None:
                self._client_tasks.discard(task)
            if self.clients == 0 and not self._closed:
                self._schedule_idle(self.idle_timeout)


class P2PManager:
    """Own one ``P2PFront`` per device that is published in P2P mode."""

    def __init__(self, idle_timeout: float, factory: RelayFactory = ImouP2PRelay) -> None:
        self.idle_timeout = idle_timeout
        self._factory = factory
        self._fronts: dict[str, P2PFront] = {}

    async def ensure_front(
        self, device: ImouDevice, username: str = "", password: str = ""
    ) -> P2PFront:
        key = device.device_id.casefold()
        config = front_config(device, username, password)
        front = self._fronts.get(key)
        if front is None:
            front = P2PFront(config, idle_timeout=self.idle_timeout, factory=self._factory)
            await front.open()
            self._fronts[key] = front
        else:
            front.update_config(config)
        return front

    def get(self, device_id: str) -> P2PFront | None:
        return self._fronts.get(device_id.casefold())

    async def prune(self, keep: set[str]) -> None:
        wanted = {item.casefold() for item in keep}
        for key in [key for key in self._fronts if key not in wanted]:
            front = self._fronts.pop(key)
            await front.close()

    async def close(self) -> None:
        fronts = list(self._fronts.values())
        self._fronts.clear()
        await asyncio.gather(*(front.close() for front in fronts), return_exceptions=True)
