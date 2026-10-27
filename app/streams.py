"""Turn camera configs into MediaMTX paths and report their live state."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from .cameras import CameraConfig
from .cloud import CloudManager, CloudStream, SourceError
from .cloud_front import CloudFrontManager
from .imou.models import ImouDevice
from .imou.p2p import _device_ip_candidates, plain_credential, rtsp_channel_number
from .mediamtx import MediaMTX, MediaMTXError, describe_tracks
from .relay import P2PManager
from .rtsp_probe import probe
from .settings import Settings
from .store import Store
from .util import redact_query, redact_url

_LOGGER = logging.getLogger(__name__)
_RECONCILE_INTERVAL = 60.0
_DEBOUNCE = 0.3
_RUNTIME_MAX_AGE = 3.0
_START_TIMEOUT = "10s"
_P2P_START_TIMEOUT = "45s"
_CLOUD_START_TIMEOUT = "45s"
_CLOSE_AFTER = "10s"
_CLOUD_RELAY = "relay"


def dahua_rtsp_url(
    host: str, port: int, username: str, password: str, channel: int, subtype: int
) -> str:
    """Build the standard Dahua/Imou RTSP URL."""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    userinfo = ""
    if username:
        userinfo = quote(username, safe="")
        if password:
            userinfo += ":" + quote(password, safe="")
        userinfo += "@"
    return (
        f"rtsp://{userinfo}{host}:{port}/cam/realmonitor"
        f"?channel={max(1, channel)}&subtype={max(0, subtype)}"
    )


def camera_credentials(device: ImouDevice | None, config: CameraConfig) -> tuple[str, str]:
    raw = device.raw if device is not None else {}
    username = config.username or plain_credential(raw.get("deviceUsername")) or "admin"
    password = config.password or plain_credential(raw.get("devicePassword"))
    return username, password


def cloud_lan_ip(device: ImouDevice | None) -> str:
    """Return a private IPv4 address reported by the cloud, if any."""
    if device is None:
        return ""
    for candidate in _device_ip_candidates(device):
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if address.version == 4 and address.is_private and not address.is_loopback:
            return str(address)
    return ""


def public_url(host: str, port: int, path: str) -> str:
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"rtsp://{host}:{port}/{path}"


@dataclass(slots=True)
class StreamEntry:
    key: str
    kind: str
    path: str
    mode: str
    conf: dict[str, Any] | None = None
    error: str = ""
    source: str = ""
    on_demand: bool = True


class StreamManager:
    """Reconcile MediaMTX paths with the stored camera configs."""

    def __init__(
        self,
        settings: Settings,
        store: Store,
        cloud: CloudManager,
        mediamtx: MediaMTX,
        p2p: P2PManager,
        cloud_fronts: CloudFrontManager | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.cloud = cloud
        self.mediamtx = mediamtx
        self.p2p = p2p
        self.cloud_fronts = cloud_fronts or CloudFrontManager()
        self.entries: dict[tuple[str, str], StreamEntry] = {}
        self.last_error = ""
        self._applied: dict[str, dict[str, Any]] = {}
        self._applied_generation = -1
        self._cloud_urls: dict[str, tuple[str, float]] = {}
        self._cloud_kinds: dict[str, str] = {}
        self._cloud_keep: set[str] = set()
        self._p2p_keep: set[str] = set()
        self._runtime: dict[str, dict[str, Any]] = {}
        self._static: dict[str, dict[str, Any]] = {}
        self._runtime_at = 0.0
        self._runtime_lock = asyncio.Lock()
        self._lock = asyncio.Lock()
        self._dirty = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    # ----------------------------------------------------------- lifecycle

    def start(self) -> None:
        self.mediamtx.on_ready.append(self.mark_dirty)
        self._dirty.set()
        self._task = asyncio.create_task(self._loop(), name="stream reconcile")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        await self.p2p.close()
        await self.cloud_fronts.close()

    def mark_dirty(self) -> None:
        self._dirty.set()

    async def _loop(self) -> None:
        while True:
            try:
                await asyncio.wait_for(self._dirty.wait(), _RECONCILE_INTERVAL)
            except TimeoutError:
                pass
            await asyncio.sleep(_DEBOUNCE)
            self._dirty.clear()
            try:
                await self.reconcile()
            except Exception:  # noqa: BLE001 - keep reconciling
                _LOGGER.exception("Stream reconcile failed")

    # ------------------------------------------------------------ sources

    def _base_conf(self, config: CameraConfig) -> dict[str, Any]:
        return {
            "sourceOnDemand": config.on_demand,
            "sourceOnDemandStartTimeout": _START_TIMEOUT,
            "sourceOnDemandCloseAfter": _CLOSE_AFTER,
        }

    async def _source(
        self, key: str, config: CameraConfig, kind: str, path: str
    ) -> tuple[dict[str, Any], str]:
        base = self._base_conf(config)
        if config.mode == "custom":
            url = config.custom_url
            conf = {"source": url, **base}
            if url.lower().startswith(("rtsp://", "rtsps://")):
                conf["rtspTransport"] = config.rtsp_transport
            return conf, redact_query(url)

        device, channel = self.cloud.find(key)
        if config.channel:
            channel_number = config.channel
        elif device is not None and channel is not None:
            channel_number = rtsp_channel_number(device, channel)
        else:
            channel_number = 1
        subtype = 1 if kind == "sub" else 0

        if config.mode == "lan":
            host = config.host or (cloud_lan_ip(device) if config.auto_host else "")
            if not host:
                raise SourceError(
                    "Chưa biết IP của camera trong mạng LAN. Bấm “Quét LAN” hoặc nhập IP."
                )
            username, password = camera_credentials(device, config)
            if not password:
                raise SourceError(
                    "Chưa có mật khẩu camera (Safety Code in trên tem dán ở camera)."
                )
            url = dahua_rtsp_url(host, config.port, username, password, channel_number, subtype)
            return {**base, "source": url, "rtspTransport": config.rtsp_transport}, redact_url(url)

        if config.mode == "p2p":
            if device is None:
                raise SourceError("Chế độ P2P cần thông tin thiết bị từ Imou cloud (hãy đăng nhập).")
            username, password = camera_credentials(device, config)
            if not password:
                raise SourceError("Chế độ P2P vẫn cần mật khẩu camera (Safety Code).")
            # Only a Safety Code typed in the UI replaces the cloud's P2P login.
            front = await self.p2p.ensure_front(device, config.username, config.password)
            self._p2p_keep.add(device.device_id)
            if front.port is None:
                raise SourceError("Không mở được cổng P2P nội bộ.")
            url = dahua_rtsp_url("127.0.0.1", front.port, username, password, channel_number, subtype)
            conf = {
                **base,
                "source": url,
                "sourceOnDemandStartTimeout": _P2P_START_TIMEOUT,
                "rtspTransport": "tcp",
            }
            return conf, f"P2P → {device.device_id} kênh {channel_number}"

        if config.mode == "cloud":
            if device is None or channel is None:
                raise SourceError("Chế độ cloud cần thông tin kênh từ Imou cloud (hãy đăng nhập).")
            sub = kind == "sub"
            if self._cloud_kinds.get(path) != _CLOUD_RELAY:
                url = await self._cloud_url(path, device, channel, sub)
                if not url.lower().startswith(("rtsp://", "rtsps://")):
                    return {**base, "source": url}, redact_query(url)
                # Imou RTSP relay links are single-use, so MediaMTX reads a
                # local front that fetches a new link for every connection.
                self._cloud_kinds[path] = _CLOUD_RELAY
                self._cloud_urls.pop(path, None)
            front = await self.cloud_fronts.ensure(path, self._cloud_fetcher(key, sub, path))
            self._cloud_keep.add(path)
            conf = {
                **base,
                "source": front.local_url,
                "sourceOnDemandStartTimeout": _CLOUD_START_TIMEOUT,
                "rtspTransport": "tcp",
            }
            return conf, "Cloud Imou (RTSP qua máy chủ trung chuyển, link mới mỗi lần kết nối)"

        raise SourceError("Chế độ nguồn không hợp lệ.")

    def _cloud_fetcher(
        self, key: str, sub: bool, path: str
    ) -> Callable[[], Awaitable[CloudStream]]:
        async def fetch() -> CloudStream:
            device, channel = self.cloud.find(key)
            if device is None or channel is None:
                raise SourceError("Không còn thông tin kênh từ Imou cloud (hãy đăng nhập lại).")
            stream = await self.cloud.live_stream(device, channel, sub=sub, fresh=True)
            if not stream.is_rtsp:
                self._cloud_kinds.pop(path, None)
                self.mark_dirty()
                raise SourceError("Imou đã đổi loại link xem trực tiếp; đang cấu hình lại.")
            return stream

        return fetch

    async def _cloud_url(self, path: str, device: ImouDevice, channel: Any, sub: bool) -> str:
        cached = self._cloud_urls.get(path)
        now = time.monotonic()
        if cached is not None:
            url, fetched = cached
            age = now - fetched
            runtime = self._runtime.get(path) or {}
            ready = bool(runtime.get("ready") or runtime.get("available"))
            failed = (self._static.get(path) or {}).get("state") == "error"
            if ready or (age < self.settings.cloud_url_ttl and not (failed and age > 30)):
                return url
        stream = await self.cloud.live_stream(device, channel, sub=sub)
        url = stream.url
        self._cloud_urls[path] = (url, now)
        _LOGGER.info("Fetched a cloud live URL for %s (%s)", path, stream.key or "url")
        return url

    async def _build_entries(self) -> dict[tuple[str, str], StreamEntry]:
        entries: dict[tuple[str, str], StreamEntry] = {}
        owners: dict[str, tuple[str, str]] = {}
        self._p2p_keep = set()
        self._cloud_keep = set()
        for key, config in sorted(self.store.cameras.items()):
            for kind, path in config.stream_paths():
                entry = StreamEntry(key, kind, path, config.mode, on_demand=config.on_demand)
                entries[(key, kind)] = entry
                if path in owners:
                    entry.error = "Tên đường dẫn bị trùng với camera khác."
                    continue
                owners[path] = (key, kind)
                try:
                    entry.conf, entry.source = await self._source(key, config, kind, path)
                except SourceError as err:
                    entry.error = err.message
        published = {entry.path for entry in entries.values() if entry.mode == "cloud"}
        for path in list(self._cloud_urls):
            if path not in published:
                self._cloud_urls.pop(path, None)
        for path in list(self._cloud_kinds):
            if path not in published:
                self._cloud_kinds.pop(path, None)
        return entries

    # ---------------------------------------------------------- reconcile

    async def reconcile(self) -> None:
        async with self._lock:
            entries = await self._build_entries()
            self.entries = entries
            try:
                if self.mediamtx.available:
                    await self._apply(entries)
            finally:
                await self.p2p.prune(self._p2p_keep)
                await self.cloud_fronts.prune(self._cloud_keep)

    async def _apply(self, entries: dict[tuple[str, str], StreamEntry]) -> None:
        if self.mediamtx.generation != self._applied_generation:
            self._applied = {}
            self._applied_generation = self.mediamtx.generation
        try:
            current = await self.mediamtx.list_path_configs()
        except MediaMTXError as err:
            self.last_error = str(err)
            _LOGGER.warning("Could not list MediaMTX paths: %s", err)
            return
        wanted = {entry.path: entry for entry in entries.values() if entry.conf is not None}
        for path, entry in wanted.items():
            assert entry.conf is not None
            if path in current and self._applied.get(path) == entry.conf:
                continue
            try:
                if path in current:
                    await self.mediamtx.replace_path(path, entry.conf)
                else:
                    await self.mediamtx.add_path(path, entry.conf)
            except MediaMTXError as err:
                entry.error = f"MediaMTX từ chối cấu hình: {redact_url(str(err))}"
                self._applied.pop(path, None)
                _LOGGER.warning("MediaMTX rejected path %s: %s", path, redact_url(str(err)))
                continue
            self._applied[path] = entry.conf
            _LOGGER.info("Published rtsp path /%s (%s)", path, entry.mode)
        for path in current:
            if path in self._applied and path in wanted:
                continue
            try:
                await self.mediamtx.delete_path(path)
            except MediaMTXError as err:
                _LOGGER.warning("Could not remove MediaMTX path %s: %s", path, err)
                continue
            self._applied.pop(path, None)
            _LOGGER.info("Removed rtsp path /%s", path)
        self.last_error = ""
        self._runtime_at = 0.0

    # ------------------------------------------------------------- status

    def _front_error(self, entry: StreamEntry) -> str:
        if entry.mode != "cloud":
            return ""
        front = self.cloud_fronts.get(entry.path)
        return front.last_error if front is not None else ""

    async def refresh_runtime(self, max_age: float = _RUNTIME_MAX_AGE) -> None:
        if not self.mediamtx.available:
            self._runtime = {}
            self._static = {}
            return
        if time.monotonic() - self._runtime_at < max_age:
            return
        async with self._runtime_lock:
            if time.monotonic() - self._runtime_at < max_age:
                return
            try:
                runtime = await self.mediamtx.list_paths()
            except MediaMTXError as err:
                _LOGGER.debug("Could not read MediaMTX path state: %s", err)
                return
            static: dict[str, dict[str, Any]] = {}
            published = {entry.path for entry in self.entries.values() if entry.conf is not None}
            for path, info in runtime.items():
                if path not in published or info.get("ready") or info.get("available"):
                    continue
                try:
                    source = await self.mediamtx.static_source(path)
                except MediaMTXError:
                    continue
                if source is not None:
                    static[path] = source
            self._runtime = runtime
            self._static = static
            self._runtime_at = time.monotonic()

    def stream_status(self, key: str, kind: str) -> dict[str, Any]:
        entry = self.entries.get((key, kind))
        result: dict[str, Any] = {
            "state": "pending",
            "detail": "Đang cấu hình…",
            "readers": 0,
            "source": "",
        }
        if entry is None:
            return result
        result["source"] = entry.source
        if entry.error:
            result.update(state="error", detail=entry.error)
            return result
        if not self.mediamtx.available:
            result.update(state="offline", detail="MediaMTX chưa chạy.")
            return result
        runtime = self._runtime.get(entry.path)
        if runtime is None:
            return result
        readers = runtime.get("readers") or []
        result["readers"] = len(readers) if isinstance(readers, list) else 0
        if runtime.get("ready") or runtime.get("available"):
            result.update(state="live", detail=describe_tracks(runtime) or "Đang phát")
            return result
        source = self._static.get(entry.path) or {}
        state = source.get("state")
        last_error = self._front_error(entry) or redact_url(str(source.get("lastError") or ""))
        if state == "error" or (state != "running" and last_error and not entry.on_demand):
            result.update(state="error", detail=last_error or "Nguồn camera báo lỗi.")
        elif state == "running":
            result.update(state="connecting", detail="Đang kết nối camera…")
        elif entry.on_demand:
            detail = "Sẵn sàng – camera chỉ được kết nối khi có người xem."
            if last_error:
                detail += f" Lần trước lỗi: {last_error}"
            result.update(state="standby", detail=detail)
        else:
            result.update(state="connecting", detail="Đang chờ camera…")
        return result

    # --------------------------------------------------------------- test

    async def test(self, key: str) -> list[dict[str, Any]]:
        """Pull every stream of one camera through MediaMTX once."""
        await self.reconcile()
        results: list[dict[str, Any]] = []
        username, password = self.mediamtx.internal_rtsp_credentials()
        for (entry_key, kind), entry in sorted(self.entries.items()):
            if entry_key != key:
                continue
            item: dict[str, Any] = {"kind": kind, "path": entry.path, "ok": False, "codecs": []}
            if entry.error or entry.conf is None:
                item["error"] = entry.error or "Chưa cấu hình được nguồn."
                results.append(item)
                continue
            if not self.mediamtx.available:
                item["error"] = "MediaMTX chưa chạy."
                results.append(item)
                continue
            timeout = {"p2p": 55.0, "cloud": 50.0}.get(entry.mode, 20.0)
            outcome = await probe(
                "127.0.0.1",
                self.settings.rtsp_port,
                entry.path,
                username=username,
                password=password,
                timeout=timeout,
            )
            item["ok"] = outcome.ok
            item["codecs"] = outcome.codecs
            if not outcome.ok:
                detail = outcome.error
                try:
                    source = await self.mediamtx.static_source(entry.path)
                except MediaMTXError:
                    source = None
                if front_error := self._front_error(entry):
                    detail = f"{detail} Chi tiết: {front_error}"
                elif source and source.get("lastError"):
                    detail = f"{detail} Chi tiết: {redact_url(str(source['lastError']))}"
                item["error"] = detail
            results.append(item)
        self._runtime_at = 0.0
        return results
