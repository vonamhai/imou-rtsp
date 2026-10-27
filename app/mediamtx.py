"""MediaMTX config rendering, process supervision and HTTP API access."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import secrets
from collections.abc import Awaitable, Callable, Mapping
from contextlib import suppress
from pathlib import Path
from typing import Any
from urllib.parse import quote

import aiohttp

from .settings import Settings
from .store import atomic_write

_LOGGER = logging.getLogger(__name__)
_MTX_LOGGER = logging.getLogger("mediamtx")
_BACKOFF = (1, 2, 5, 10, 30, 60)
_READY_TIMEOUT = 20.0
_STOP_TIMEOUT = 5.0
_LINE_PREFIX_RE = re.compile(r"^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} ")
_LEVELS = {
    "DEB": logging.DEBUG,
    "INF": logging.INFO,
    "WAR": logging.WARNING,
    "ERR": logging.ERROR,
}
_DURATION_RE = re.compile(r"(\d+(?:\.\d+)?)(h|ms|us|µs|ns|m|s)")
_DURATION_UNITS = {
    "h": 3600.0,
    "m": 60.0,
    "s": 1.0,
    "ms": 0.001,
    "us": 0.000001,
    "µs": 0.000001,
    "ns": 0.000000001,
}
LOOPBACK_IPS = ["127.0.0.1/32", "::1/128"]
# Seconds MediaMTX waits for a source's answer. Imou's cloud relay holds the
# first request for about 20 s while it wakes a sleeping (4G) camera.
READ_TIMEOUT = 30


class MediaMTXError(Exception):
    """The MediaMTX API rejected a request or is unavailable."""


def basic_auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
    return f"Basic {token}"


def go_duration_seconds(value: Any) -> float | None:
    """Parse durations such as ``10s`` or ``1m0s`` (Go ``time.Duration``)."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text in {"0", ""}:
        return 0.0
    position = 0
    total = 0.0
    for match in _DURATION_RE.finditer(text):
        if match.start() != position:
            return None
        total += float(match.group(1)) * _DURATION_UNITS[match.group(2)]
        position = match.end()
    if position != len(text):
        return None
    return total


def _values_equal(wanted: Any, current: Any) -> bool:
    if isinstance(wanted, str) and re.fullmatch(r"\d+(?:\.\d+)?(?:h|m|s|ms)", wanted):
        return go_duration_seconds(wanted) == go_duration_seconds(current)
    return wanted == current


def path_conf_matches(wanted: Mapping[str, Any], current: Mapping[str, Any]) -> bool:
    """Return whether every wanted field already has the wanted value."""
    return all(_values_equal(value, current.get(key)) for key, value in wanted.items())


def render_config(settings: Settings, internal_user: str, internal_pass: str) -> dict[str, Any]:
    """Return the MediaMTX global configuration (paths are managed via API)."""
    users: list[dict[str, Any]] = [
        {
            "user": internal_user,
            "pass": internal_pass,
            "ips": LOOPBACK_IPS,
            "permissions": [{"action": "api"}, {"action": "read"}],
        }
    ]
    if settings.rtsp_username:
        users.append(
            {
                "user": settings.rtsp_username,
                "pass": settings.rtsp_password,
                "ips": [],
                "permissions": [{"action": "read"}],
            }
        )
    else:
        users.append({"user": "any", "pass": "", "ips": [], "permissions": [{"action": "read"}]})
    return {
        "logLevel": settings.mediamtx_log_level,
        "logDestinations": ["stdout"],
        "readTimeout": f"{READ_TIMEOUT}s",
        "writeTimeout": "10s",
        "writeQueueSize": 512,
        "authMethod": "internal",
        "authInternalUsers": users,
        "api": True,
        "apiAddress": f"127.0.0.1:{settings.mediamtx_api_port}",
        "metrics": False,
        "pprof": False,
        "playback": False,
        "rtsp": True,
        "rtspTransports": list(settings.rtsp_transports),
        "rtspEncryption": "no",
        "rtspAddress": f":{settings.rtsp_port}",
        "rtpAddress": f":{settings.rtp_port}",
        "rtcpAddress": f":{settings.rtcp_port}",
        "rtspAuthMethods": ["basic"],
        "rtmp": False,
        "hls": settings.enable_hls,
        "hlsAddress": f":{settings.hls_port}",
        "webrtc": settings.enable_webrtc,
        "webrtcAddress": f":{settings.webrtc_port}",
        "webrtcLocalUDPAddress": f":{settings.webrtc_udp_port}",
        "srt": False,
        "moq": False,
        "paths": {},
    }


class MediaMTX:
    """Run MediaMTX as a child process and talk to its local API."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.config_path = settings.data_dir / "mediamtx.yml"
        self.internal_user = "bridge" + secrets.token_hex(4)
        self.internal_pass = secrets.token_urlsafe(24)
        self.state = "stopped"
        self.message = ""
        self.generation = 0
        self.ready = asyncio.Event()
        self.on_ready: list[Callable[[], Awaitable[None] | None]] = []
        self._process: asyncio.subprocess.Process | None = None
        self._task: asyncio.Task[None] | None = None
        self._session: aiohttp.ClientSession | None = None
        self._stopping = False
        self._base = f"http://127.0.0.1:{settings.mediamtx_api_port}"

    @property
    def available(self) -> bool:
        return self.state == "running" and self.ready.is_set()

    def internal_rtsp_credentials(self) -> tuple[str, str]:
        return self.internal_user, self.internal_pass

    async def start(self) -> None:
        self._session = aiohttp.ClientSession(
            headers={"Authorization": basic_auth_header(self.internal_user, self.internal_pass)},
            timeout=aiohttp.ClientTimeout(total=10),
            trust_env=False,
        )
        self._task = asyncio.create_task(self._supervise(), name="mediamtx supervisor")

    async def stop(self) -> None:
        self._stopping = True
        await self._terminate()
        if self._task is not None:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task
        await self._terminate()
        if self._session is not None:
            await self._session.close()
        self.state = "stopped"

    def _write_config(self) -> None:
        config = render_config(self.settings, self.internal_user, self.internal_pass)
        atomic_write(self.config_path, json.dumps(config, indent=2))

    async def _supervise(self) -> None:
        failures = 0
        while not self._stopping:
            binary = self.settings.mediamtx_bin
            if not Path(binary).is_file():
                self.state = "missing"
                self.message = f"Không tìm thấy MediaMTX tại {binary}"
                _LOGGER.error("%s", self.message)
                return
            try:
                self._write_config()
            except OSError as err:
                self.state = "crashed"
                self.message = f"Không ghi được cấu hình MediaMTX: {err}"
                _LOGGER.error("%s", self.message)
                await asyncio.sleep(30)
                continue
            self.state = "starting"
            self.message = ""
            started = asyncio.get_running_loop().time()
            try:
                self._process = await asyncio.create_subprocess_exec(
                    binary,
                    str(self.config_path),
                    cwd=str(self.settings.data_dir),
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
            except OSError as err:
                self.state = "crashed"
                self.message = f"Không chạy được MediaMTX: {err}"
                _LOGGER.error("%s", self.message)
            else:
                pump = asyncio.create_task(self._pump_output(self._process))
                try:
                    if await self._wait_api_ready(self._process):
                        self.generation += 1
                        self.state = "running"
                        self.ready.set()
                        _LOGGER.info("MediaMTX is ready (generation %s)", self.generation)
                        await self._fire_ready()
                    code = await self._process.wait()
                finally:
                    self.ready.clear()
                    with suppress(asyncio.CancelledError, Exception):
                        await asyncio.wait_for(pump, 2)
                if self._stopping:
                    return
                self.state = "crashed"
                self.message = f"MediaMTX đã dừng (mã {code}); xem nhật ký."
                _LOGGER.warning("MediaMTX exited with code %s", code)
            if asyncio.get_running_loop().time() - started > 120:
                failures = 0
            delay = _BACKOFF[min(failures, len(_BACKOFF) - 1)]
            failures += 1
            await asyncio.sleep(delay)

    async def _fire_ready(self) -> None:
        for callback in list(self.on_ready):
            try:
                result = callback()
                if asyncio.iscoroutine(result):
                    await result
            except Exception:  # noqa: BLE001 - keep the supervisor alive
                _LOGGER.exception("MediaMTX ready callback failed")

    async def _wait_api_ready(self, process: asyncio.subprocess.Process) -> bool:
        deadline = asyncio.get_running_loop().time() + _READY_TIMEOUT
        while asyncio.get_running_loop().time() < deadline:
            if process.returncode is not None:
                return False
            try:
                await self._request("GET", "/v3/config/global/get", timeout=2)
                return True
            except MediaMTXError:
                await asyncio.sleep(0.25)
        _LOGGER.warning("MediaMTX API did not become ready in time")
        return process.returncode is None

    async def _pump_output(self, process: asyncio.subprocess.Process) -> None:
        stream = process.stdout
        if stream is None:
            return
        while True:
            try:
                line = await stream.readline()
            except (ValueError, OSError):
                continue
            if not line:
                return
            text = _LINE_PREFIX_RE.sub("", line.decode("utf-8", "replace").rstrip())
            if not text:
                continue
            level = _LEVELS.get(text[:3], logging.INFO)
            if text[:3] in _LEVELS:
                text = text[4:]
            _MTX_LOGGER.log(level, "%s", text)

    async def _terminate(self) -> None:
        process = self._process
        if process is None or process.returncode is not None:
            return
        with suppress(ProcessLookupError):
            process.terminate()
        try:
            await asyncio.wait_for(process.wait(), _STOP_TIMEOUT)
        except TimeoutError:
            with suppress(ProcessLookupError):
                process.kill()
            with suppress(TimeoutError):
                await asyncio.wait_for(process.wait(), _STOP_TIMEOUT)

    async def _request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
        *,
        timeout: float = 10,
        allow_404: bool = False,
    ) -> Any:
        session = self._session
        if session is None or session.closed:
            raise MediaMTXError("MediaMTX API session is closed")
        try:
            async with session.request(
                method,
                self._base + path,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as response:
                body = await response.read()
                if response.status == 404 and allow_404:
                    return None
                data: Any = None
                if body:
                    with suppress(ValueError):
                        data = json.loads(body)
                if response.status >= 400:
                    message = data.get("error") if isinstance(data, Mapping) else None
                    raise MediaMTXError(message or f"HTTP {response.status}")
                return data
        except (aiohttp.ClientError, TimeoutError, OSError) as err:
            raise MediaMTXError(f"MediaMTX API unavailable: {err}") from err

    @staticmethod
    def _quote(name: str) -> str:
        return quote(name, safe="")

    async def _list_all(self, path: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        page = 0
        while True:
            data = await self._request("GET", f"{path}?itemsPerPage=500&page={page}")
            if not isinstance(data, Mapping):
                return items
            items.extend(item for item in data.get("items") or [] if isinstance(item, dict))
            page_count = data.get("pageCount")
            page += 1
            if not isinstance(page_count, int) or page >= page_count:
                return items

    async def list_path_configs(self) -> dict[str, dict[str, Any]]:
        items = await self._list_all("/v3/config/paths/list")
        return {str(item.get("name")): item for item in items if item.get("name")}

    async def list_paths(self) -> dict[str, dict[str, Any]]:
        items = await self._list_all("/v3/paths/list")
        return {str(item.get("name")): item for item in items if item.get("name")}

    async def add_path(self, name: str, conf: Mapping[str, Any]) -> None:
        await self._request("POST", f"/v3/config/paths/add/{self._quote(name)}", conf)

    async def replace_path(self, name: str, conf: Mapping[str, Any]) -> None:
        await self._request("POST", f"/v3/config/paths/replace/{self._quote(name)}", conf)

    async def delete_path(self, name: str) -> None:
        await self._request(
            "DELETE", f"/v3/config/paths/delete/{self._quote(name)}", allow_404=True
        )

    async def static_source(self, name: str) -> dict[str, Any] | None:
        data = await self._request(
            "GET", f"/v3/paths/static-sources/get/{self._quote(name)}", allow_404=True
        )
        return data if isinstance(data, dict) else None


def describe_tracks(path_info: Mapping[str, Any] | None) -> str:
    """Summarise the codecs of a MediaMTX path, e.g. ``H265 2560x1440, AAC``."""
    if not path_info:
        return ""
    parts: list[str] = []
    for track in path_info.get("tracks2") or []:
        if not isinstance(track, Mapping):
            continue
        codec = str(track.get("codec") or "?")
        props = track.get("codecProps")
        if isinstance(props, Mapping) and props.get("width") and props.get("height"):
            codec = f"{codec} {props['width']}x{props['height']}"
        parts.append(codec)
    if not parts:
        parts = [str(item) for item in path_info.get("tracks") or [] if item]
    return ", ".join(parts)


def default_data_dir_ok(path: Path) -> bool:
    """Return whether DATA_DIR is writable (used for a clear startup error)."""
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True
    except OSError:
        return False
