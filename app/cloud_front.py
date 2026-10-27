"""Stable loopback RTSP ports in front of Imou's cloud relay.

Imou's cloud ("transfer") RTSP URLs are signed, expire after a few minutes and
serve exactly one RTSP session; the ``tlsResource`` ones also require TLS even
though they say ``rtsp://``. MediaMTX needs one fixed source URL, so every
published cloud path gets a ``CloudFront`` on 127.0.0.1. Each time MediaMTX
connects, the front asks Imou for a new URL, opens TLS (or plain TCP) to the
relay and rewrites the loopback request URIs to that URL. Responses and
interleaved RTP/RTCP frames pass through untouched.

Waking a sleeping (4G) camera makes the relay hold the first request for about
20 s and then answer 500 and hang up, while the camera keeps waking up. The
front therefore replays that first request on a fresh link before answering
MediaMTX, so a cold start looks like one slow success instead of an error.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import time
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .cloud import CloudStream, SourceError
from .mediamtx import READ_TIMEOUT
from .relay import _close_writer, _pipe

_LOGGER = logging.getLogger(__name__)
_CHUNK = 65536
_MAX_HEAD = 64 * 1024
_MAX_BODY = 1 << 20
_FETCH_TIMEOUT = 30.0
_CONNECT_TIMEOUT = 15.0
_RETRY_DELAYS = (0, 5, 10, 20, 30)
_CLIENT_TIMEOUT = 10.0
# MediaMTX drops a request after READ_TIMEOUT; answer the first one before that.
_ANSWER_DEADLINE = READ_TIMEOUT - 3.0
_MAX_ATTEMPTS = 3
_MIN_ATTEMPT_WINDOW = 3.0
_QUICK_FAILURE = 2.0
_RETRY_PAUSE = 1.0
_ASLEEP_HINT = "camera có thể đang ngủ, mất mạng hoặc sóng 4G yếu"

Fetcher = Callable[[], Awaitable[CloudStream]]


def relay_tls_context() -> ssl.SSLContext:
    """TLS settings for Imou relays.

    Relays are addressed by bare IP and present an expired ``*.lechange.com``
    certificate, so it cannot be verified; TLS still keeps the video off the
    wire in clear text.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def rewrite_uri(uri: str, local: str, remote: str) -> str:
    """Map ``local`` (and ``local/<control>``) to the signed cloud URL."""
    if uri in (local, f"{local}/"):
        return remote
    if uri.startswith(f"{local}/"):
        return remote.rstrip("/") + uri[len(local) :]
    return uri


def rewrite_request_head(head: bytes, local: str, remote: str) -> bytes:
    """Rewrite the request line of one RTSP request header block."""
    end = head.find(b"\r\n")
    if end < 0:
        return head
    line = head[:end].decode("latin-1")
    method, _, rest = line.partition(" ")
    uri, _, version = rest.rpartition(" ")
    if not method or not uri or not version.startswith("RTSP/"):
        return head
    new_uri = rewrite_uri(uri, local, remote)
    if new_uri == uri:
        return head
    return f"{method} {new_uri} {version}".encode("latin-1") + head[end:]


def _header(head: bytes, name: bytes) -> bytes | None:
    for line in head.split(b"\r\n")[1:]:
        key, sep, value = line.partition(b":")
        if sep and key.strip().lower() == name:
            return value.strip()
    return None


def _content_length(head: bytes) -> int:
    try:
        return max(0, int(_header(head, b"content-length") or 0))
    except ValueError:
        return 0


def _status(head: bytes) -> int:
    """Status code of an RTSP response header block, 0 if it is not one."""
    version, _, rest = head.partition(b" ")
    code = rest[:3]
    if not version.startswith(b"RTSP/") or not code.isdigit():
        return 0
    return int(code)


def _unavailable(request: bytes) -> bytes:
    cseq = (_header(request, b"cseq") or b"0").decode("latin-1")
    return (
        f"RTSP/1.0 503 Service Unavailable\r\nCSeq: {cseq}\r\nContent-Length: 0\r\n\r\n"
    ).encode("latin-1")


async def read_message(reader: asyncio.StreamReader) -> tuple[bytes, bytes]:
    """Read one RTSP request or response: header block plus Content-Length body."""
    head = await reader.readuntil(b"\r\n\r\n")
    length = _content_length(head)
    if length > _MAX_BODY:
        raise ValueError("RTSP body too large")
    body = await reader.readexactly(length) if length else b""
    return head, body


async def forward_requests(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    local: str,
    remote: str,
) -> None:
    """Copy client -> relay, rewriting request URIs and keeping ``$`` frames intact."""
    buffer = bytearray()
    while data := await reader.read(_CHUNK):
        buffer += data
        out = bytearray()
        while buffer:
            if buffer[0] == 0x24:  # "$": interleaved RTP/RTCP frame
                if len(buffer) < 4:
                    break
                size = 4 + int.from_bytes(buffer[2:4], "big")
                if len(buffer) < size:
                    break
                out += buffer[:size]
                del buffer[:size]
                continue
            end = buffer.find(b"\r\n\r\n")
            if end < 0:
                if len(buffer) > _MAX_HEAD:
                    raise ValueError("RTSP request header too large")
                break
            head_end = end + 4
            head = bytes(buffer[:head_end])
            length = _content_length(head)
            if length > _MAX_BODY:
                raise ValueError("RTSP request body too large")
            if len(buffer) < head_end + length:
                break
            out += rewrite_request_head(head, local, remote)
            out += buffer[head_end : head_end + length]
            del buffer[: head_end + length]
        if out:
            writer.write(bytes(out))
            await writer.drain()


@dataclass
class _Relay:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    stream: CloudStream
    secure: bool


class CloudFront:
    """One fixed 127.0.0.1 port; every client gets a fresh Imou relay session."""

    def __init__(
        self,
        path: str,
        fetch: Fetcher,
        *,
        tls_context: ssl.SSLContext | None = None,
    ) -> None:
        self.path = path
        self.fetch = fetch
        self.port: int | None = None
        self.clients = 0
        self.sessions = 0
        self.last_error = ""
        self._tls = tls_context or relay_tls_context()
        self._server: asyncio.AbstractServer | None = None
        self._client_tasks: set[asyncio.Task[Any]] = set()
        self._failures = 0
        self._retry_at = 0.0
        self._closed = False

    @property
    def local_url(self) -> str:
        return f"rtsp://127.0.0.1:{self.port}/{self.path}"

    async def open(self) -> int:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = int(self._server.sockets[0].getsockname()[1])
        return self.port

    async def close(self) -> None:
        self._closed = True
        if self._server is not None:
            self._server.close()
        tasks = [task for task in self._client_tasks if not task.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if self._server is not None:
            with suppress(Exception):
                await asyncio.wait_for(self._server.wait_closed(), 5)

    def _failed(self, message: str) -> None:
        self.last_error = message
        delay = _RETRY_DELAYS[min(self._failures, len(_RETRY_DELAYS) - 1)]
        self._failures += 1
        self._retry_at = time.monotonic() + delay
        _LOGGER.warning("Cloud relay for /%s failed: %s", self.path, message)

    async def _connect(
        self,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, CloudStream, bool]:
        stream = await asyncio.wait_for(self.fetch(), _FETCH_TIMEOUT)
        if not stream.is_rtsp:
            raise SourceError("Link cloud không phải RTSP.")
        parts = urlsplit(stream.url)
        scheme = parts.scheme.lower()
        secure = stream.tls or scheme == "rtsps"
        host = parts.hostname
        if not host:
            raise SourceError("Link cloud không hợp lệ.")
        port = parts.port or (322 if scheme == "rtsps" else 554)
        if secure:
            connect = asyncio.open_connection(
                host, port, ssl=self._tls, ssl_handshake_timeout=_CONNECT_TIMEOUT
            )
        else:
            connect = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(connect, _CONNECT_TIMEOUT)
        return reader, writer, stream, secure

    async def _attempt(
        self, head: bytes, body: bytes, deadline: float
    ) -> tuple[int, bytes, _Relay | None]:
        """Send the client's first request over a fresh relay link.

        Returns the relay's status (0 = no answer) and answer; the link stays
        open only when the answer is a success.
        """
        reader, writer, stream, secure = await asyncio.wait_for(
            self._connect(), max(0.5, deadline - time.monotonic())
        )
        keep = False
        try:
            writer.write(rewrite_request_head(head, self.local_url, stream.url) + body)
            await writer.drain()
            answer_head, answer_body = await asyncio.wait_for(
                read_message(reader), max(0.5, deadline - time.monotonic())
            )
            status = _status(answer_head)
            keep = 0 < status < 400
            relay = _Relay(reader, writer, stream, secure) if keep else None
            return status, answer_head + answer_body, relay
        except (OSError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError):
            return 0, b"", None
        finally:
            if not keep:
                await _close_writer(writer)

    async def _open_session(self, head: bytes, body: bytes) -> tuple[_Relay | None, bytes]:
        """Return a relay link that accepted the first request, and the answer for the client."""
        started = time.monotonic()
        deadline = started + _ANSWER_DEADLINE
        status, answer = 0, b""
        for attempt in range(1, _MAX_ATTEMPTS + 1):
            begun = time.monotonic()
            try:
                status, answer, relay = await self._attempt(head, body, deadline)
            except SourceError as err:
                self._failed(err.message)
                return None, _unavailable(head)
            except (OSError, TimeoutError) as err:
                self._failed(f"Không kết nối được máy chủ cloud của Imou ({type(err).__name__}).")
                return None, _unavailable(head)
            except Exception:  # noqa: BLE001 - one bad session must not kill the front
                _LOGGER.exception("Unexpected cloud relay failure for /%s", self.path)
                self._failed("Lỗi nội bộ khi mở luồng cloud.")
                return None, _unavailable(head)
            now = time.monotonic()
            if relay is not None:
                self._failures = 0
                self._retry_at = 0.0
                self.last_error = ""
                self.sessions += 1
                _LOGGER.info(
                    "Cloud relay for /%s connected (%s, %s, answered after %.1fs, attempt %d)",
                    self.path,
                    relay.stream.key or "url",
                    "TLS" if relay.secure else "TCP",
                    now - started,
                    attempt,
                )
                return relay, answer
            if attempt == _MAX_ATTEMPTS or deadline - now < _MIN_ATTEMPT_WINDOW:
                break
            _LOGGER.info(
                "Cloud relay for /%s %s after %.1fs (camera waking up?); retrying with a new link",
                self.path,
                f"answered {status}" if status else "did not answer",
                now - begun,
            )
            if now - begun < _QUICK_FAILURE:
                await asyncio.sleep(_RETRY_PAUSE)
        if status:
            self._failed(
                f"Máy chủ cloud của Imou trả lỗi RTSP {status}, chưa lấy được hình "
                f"({_ASLEEP_HINT})."
            )
            return None, answer
        self._failed(f"Máy chủ cloud của Imou không trả lời ({_ASLEEP_HINT}).")
        return None, _unavailable(head)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._client_tasks.add(task)
        self.clients += 1
        upstream: asyncio.StreamWriter | None = None
        try:
            if self._closed or time.monotonic() < self._retry_at:
                return
            head, body = await asyncio.wait_for(read_message(reader), _CLIENT_TIMEOUT)
            relay, answer = await self._open_session(head, body)
            if relay is not None:
                upstream = relay.writer
            writer.write(answer)
            await writer.drain()
            if relay is None:
                return
            pipes = {
                asyncio.ensure_future(
                    forward_requests(reader, relay.writer, self.local_url, relay.stream.url)
                ),
                asyncio.ensure_future(_pipe(relay.reader, writer)),
            }
            try:
                await asyncio.wait(pipes, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for pipe in pipes:
                    pipe.cancel()
                await asyncio.gather(*pipes, return_exceptions=True)
        except (OSError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError) as err:
            _LOGGER.debug("Cloud relay client for /%s ended: %s", self.path, err)
        finally:
            if upstream is not None:
                await _close_writer(upstream)
            await _close_writer(writer)
            self.clients -= 1
            if task is not None:
                self._client_tasks.discard(task)


class CloudFrontManager:
    """Own one ``CloudFront`` per MediaMTX path served from the Imou cloud."""

    def __init__(self, tls_context: ssl.SSLContext | None = None) -> None:
        self._tls = tls_context
        self._fronts: dict[str, CloudFront] = {}

    async def ensure(self, path: str, fetch: Fetcher) -> CloudFront:
        front = self._fronts.get(path)
        if front is None:
            front = CloudFront(path, fetch, tls_context=self._tls)
            await front.open()
            self._fronts[path] = front
        else:
            front.fetch = fetch
        return front

    def get(self, path: str) -> CloudFront | None:
        return self._fronts.get(path)

    async def prune(self, keep: set[str]) -> None:
        for path in [path for path in self._fronts if path not in keep]:
            front = self._fronts.pop(path)
            await front.close()

    async def close(self) -> None:
        fronts = list(self._fronts.values())
        self._fronts.clear()
        await asyncio.gather(*(front.close() for front in fronts), return_exceptions=True)
