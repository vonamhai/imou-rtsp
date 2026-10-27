"""Wire settings, storage, MediaMTX, the Imou cloud and the stream manager."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from contextlib import suppress
from typing import Any

import aiohttp

from .cloud import CloudManager, split_key
from .discovery import DiscoveredDevice, discover
from .imou.api import ImouApiClient
from .mediamtx import MediaMTX
from .relay import P2PManager
from .settings import Settings
from .store import Store
from .streams import StreamManager
from .util import LogBuffer

_LOGGER = logging.getLogger(__name__)
_FIRST_SCAN_DELAY = 2.0


class Bridge:
    """Everything the web UI needs, started and stopped together."""

    def __init__(
        self,
        settings: Settings,
        logs: LogBuffer | None = None,
        *,
        client_factory: Callable[..., ImouApiClient] = ImouApiClient,
    ) -> None:
        self.settings = settings
        self.logs = logs or LogBuffer()
        self.store = Store(settings.data_dir)
        self.mediamtx = MediaMTX(settings)
        self.p2p = P2PManager(settings.p2p_idle_timeout)
        self.session: aiohttp.ClientSession | None = None
        self.cloud: CloudManager | None = None
        self.streams: StreamManager | None = None
        self.discovered: dict[str, DiscoveredDevice] = {}
        self.discovery_running = False
        self.discovery_last: float | None = None
        self.discovery_error = ""
        self._client_factory = client_factory
        self._discovery_lock = asyncio.Lock()
        self._tasks: list[asyncio.Task[Any]] = []

    async def start(self) -> None:
        self.store.load()
        self.session = aiohttp.ClientSession(trust_env=True)
        self.cloud = CloudManager(
            self.settings,
            self.store,
            self.session,
            on_change=self._on_cloud_change,
            client_factory=self._client_factory,
        )
        self.streams = StreamManager(
            self.settings, self.store, self.cloud, self.mediamtx, self.p2p
        )
        added = self.cloud.sync_cameras()
        if added:
            _LOGGER.info("Created %s camera config(s) from the cached device list", added)
        await self.mediamtx.start()
        self.cloud.start()
        self.streams.start()
        self._tasks.append(asyncio.create_task(self._discovery_loop(), name="lan discovery"))
        _LOGGER.info(
            "Imou RTSP bridge started: web :%s, rtsp :%s",
            self.settings.web_port,
            self.settings.rtsp_port,
        )

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        if self.cloud is not None:
            await self.cloud.stop()
        if self.streams is not None:
            with suppress(Exception):
                await self.streams.stop()
        await self.mediamtx.stop()
        if self.session is not None:
            await self.session.close()

    def _on_cloud_change(self) -> None:
        if self.streams is not None:
            self.streams.mark_dirty()

    # ----------------------------------------------------------- discovery

    async def _discovery_loop(self) -> None:
        if self.settings.lan_scan_interval <= 0:
            return
        await asyncio.sleep(_FIRST_SCAN_DELAY)
        while True:
            try:
                await self.scan_lan()
            except Exception:  # noqa: BLE001 - discovery is best effort
                _LOGGER.exception("LAN discovery failed")
            await asyncio.sleep(self.settings.lan_scan_interval)

    async def scan_lan(self) -> int:
        """Find cameras on the LAN and refresh hosts of auto-host cameras."""
        if self._discovery_lock.locked():
            async with self._discovery_lock:
                return len(self.discovered)
        async with self._discovery_lock:
            self.discovery_running = True
            try:
                found = await discover()
                self.discovery_error = ""
            except OSError as err:
                found = {}
                self.discovery_error = f"Không quét được mạng LAN: {err}"
                _LOGGER.warning("LAN discovery failed: %s", err)
            finally:
                self.discovery_running = False
                self.discovery_last = time.time()
            self.discovered.update(found)
            if found:
                _LOGGER.info("LAN discovery found %s Dahua/Imou device(s)", len(found))
            self.apply_discovery()
            return len(found)

    def apply_discovery(self) -> bool:
        changed = False
        for key, config in self.store.cameras.items():
            if not config.auto_host:
                continue
            device_id, _ = split_key(key)
            hit = self.discovered.get(device_id.casefold())
            if hit is not None and config.host != hit.ip:
                _LOGGER.info("Camera %s is at %s", device_id, hit.ip)
                config.host = hit.ip
                changed = True
        if changed:
            self.store.save()
            if self.streams is not None:
                self.streams.mark_dirty()
        return changed

    def discovered_ip(self, device_id: str) -> str:
        hit = self.discovered.get(device_id.casefold())
        return hit.ip if hit is not None else ""
