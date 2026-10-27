"""Minimal RTSP client used to check published MediaMTX paths."""

from __future__ import annotations

import asyncio
import base64
import re
from contextlib import suppress
from dataclasses import dataclass, field

_STATIC_PAYLOADS = {0: "PCMU", 8: "PCMA", 14: "MPA", 26: "JPEG", 32: "MPV"}
_MAX_BODY = 1_000_000
_INTERLEAVED = re.compile(r"interleaved=(\d+)")
_CONTENT_LENGTH = re.compile(rb"(?im)^content-length:[ \t]*(\d+)")
MEDIA_TIMEOUT = 15.0


@dataclass(slots=True)
class ProbeResult:
    ok: bool
    status: int | None = None
    codecs: list[str] = field(default_factory=list)
    error: str = ""


def parse_sdp_codecs(sdp: str) -> list[str]:
    """Return ``["video H264", "audio MPEG4-GENERIC"]`` from an SDP body."""
    codecs: list[str] = []
    media = ""
    payloads: list[str] = []
    mapped: dict[str, str] = {}

    def flush() -> None:
        if not media:
            return
        names = [mapped.get(pt) or _STATIC_PAYLOADS.get(int(pt), "") for pt in payloads if pt.isdigit()]
        names = [name for name in names if name]
        codecs.append(f"{media} {names[0] if names else '?'}")

    for raw_line in sdp.splitlines():
        line = raw_line.strip()
        if line.startswith("m="):
            flush()
            parts = line[2:].split()
            media = parts[0] if parts else "?"
            payloads = parts[3:] if len(parts) > 3 else []
            mapped = {}
        elif line.startswith("a=rtpmap:") and media:
            payload, _, rest = line[9:].partition(" ")
            mapped[payload.strip()] = rest.split("/", 1)[0].strip().upper()
    flush()
    return codecs


def first_track(sdp: str) -> tuple[str, str] | None:
    """Return ``(media, control)`` of the first video track, else of the first track."""
    tracks: list[tuple[str, str]] = []
    for raw_line in sdp.splitlines():
        line = raw_line.strip()
        if line.startswith("m="):
            parts = line[2:].split()
            tracks.append((parts[0] if parts else "?", ""))
        elif line.startswith("a=control:") and tracks:
            tracks[-1] = (tracks[-1][0], line[10:].strip())
    return next((track for track in tracks if track[0] == "video"), tracks[0] if tracks else None)


def track_url(base: str, control: str) -> str:
    """Resolve an SDP ``a=control`` value against the DESCRIBE Content-Base."""
    if control.lower().startswith(("rtsp://", "rtsps://")):
        return control
    if not control or control == "*":
        return base
    return (base if base.endswith("/") else base + "/") + control


async def _read_response(reader: asyncio.StreamReader) -> tuple[int, dict[str, str], bytes]:
    head = await reader.readuntil(b"\r\n\r\n")
    lines = head.decode("utf-8", "replace").split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("RTSP/") or not parts[1].isdigit():
        raise ValueError("invalid RTSP response")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        if separator:
            headers[name.strip().lower()] = value.strip()
    length_text = headers.get("content-length", "0") or "0"
    length = int(length_text) if length_text.isdigit() else 0
    if length > _MAX_BODY:
        raise ValueError("RTSP body too large")
    body = await reader.readexactly(length) if length else b""
    return int(parts[1]), headers, body


async def _request(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    method: str,
    url: str,
    cseq: int,
    extra: str,
) -> tuple[int, dict[str, str], bytes]:
    writer.write(
        f"{method} {url} RTSP/1.0\r\nCSeq: {cseq}\r\n{extra}"
        "User-Agent: imou-rtsp-bridge\r\n\r\n".encode()
    )
    await writer.drain()
    return await _read_response(reader)


async def _first_packet(reader: asyncio.StreamReader, channel: int) -> None:
    """Skip RTCP frames and RTSP messages until RTP arrives on ``channel``."""
    while True:
        first = await reader.readexactly(1)
        if first == b"$":
            header = await reader.readexactly(3)
            await reader.readexactly(int.from_bytes(header[1:3], "big"))
            if header[0] == channel:
                return
            continue
        head = first + await reader.readuntil(b"\r\n\r\n")
        match = _CONTENT_LENGTH.search(head)
        length = int(match[1]) if match else 0
        if length > _MAX_BODY:
            raise ValueError("RTSP body too large")
        if length:
            await reader.readexactly(length)


async def _play(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    base: str,
    track: tuple[str, str] | None,
    auth: str,
    media_timeout: float,
) -> str:
    """SETUP + PLAY one track and wait for its first RTP packet; return an error or ""."""
    if track is None:
        return "Luồng không có kênh hình hay tiếng nào."
    media, control = track
    try:
        async with asyncio.timeout(media_timeout):
            status, headers, _ = await _request(
                reader,
                writer,
                "SETUP",
                track_url(base, control),
                3,
                "Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n" + auth,
            )
            if status == 461:
                return ""  # RTSP_TRANSPORTS without tcp: DESCRIBE is all we can check
            if status != 200:
                return f"RTSP SETUP trả về {status}"
            session = headers.get("session", "").split(";", 1)[0].strip()
            interleaved = _INTERLEAVED.search(headers.get("transport", ""))
            status, _, _ = await _request(
                reader,
                writer,
                "PLAY",
                base,
                4,
                f"Session: {session}\r\nRange: npt=0.000-\r\n" + auth,
            )
            if status != 200:
                return f"RTSP PLAY trả về {status}"
            await _first_packet(reader, int(interleaved[1]) if interleaved else 0)
    except TimeoutError:
        what = "hình" if media == "video" else "dữ liệu"
        return (
            f"Camera đã nhận kết nối nhưng không gửi {what} trong {media_timeout:g} giây; "
            "đường truyền của camera có thể không đủ cho luồng này."
        )
    except (OSError, ValueError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        return "Luồng bị ngắt trước khi nhận được hình."
    return ""


async def probe(
    host: str,
    port: int,
    path: str,
    *,
    username: str = "",
    password: str = "",
    timeout: float = 20.0,
    media_timeout: float = MEDIA_TIMEOUT,
) -> ProbeResult:
    """Watch a MediaMTX path like a player and report its codecs.

    A source can finish the RTSP handshake and still send nothing (the H.265
    main stream of a 4G camera on a weak uplink, for one), so after DESCRIBE
    the first video track is played until its first RTP packet arrives.
    ``timeout`` bounds the wait for the source to start, ``media_timeout``
    the wait for its first packet.
    """
    url = f"rtsp://{host}:{port}/{path}"
    auth = ""
    if username:
        token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        auth = f"Authorization: Basic {token}\r\n"
    writer: asyncio.StreamWriter | None = None
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(host, port, limit=_MAX_BODY)
            status, _, _ = await _request(reader, writer, "OPTIONS", url, 1, auth)
            if status != 200:
                return ProbeResult(False, status, error=f"RTSP OPTIONS trả về {status}")
            status, headers, body = await _request(
                reader, writer, "DESCRIBE", url, 2, "Accept: application/sdp\r\n" + auth
            )
        if status != 200:
            return _describe_failed(status)
        sdp = body.decode("utf-8", "replace")
        base = headers.get("content-base") or headers.get("content-location") or url
        error = await _play(reader, writer, base, first_track(sdp), auth, media_timeout)
        return ProbeResult(not error, status, parse_sdp_codecs(sdp), error)
    except TimeoutError:
        return ProbeResult(False, error="Hết thời gian chờ camera trả luồng.")
    except ConnectionRefusedError:
        return ProbeResult(False, error="MediaMTX chưa sẵn sàng (không kết nối được cổng RTSP).")
    except (OSError, ValueError, asyncio.IncompleteReadError, asyncio.LimitOverrunError) as err:
        return ProbeResult(False, error=f"Lỗi kết nối RTSP: {err}")
    finally:
        if writer is not None:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()


def _describe_failed(status: int) -> ProbeResult:
    if status == 404:
        return ProbeResult(False, status, error="Chưa lấy được luồng từ camera.")
    if status == 401:
        return ProbeResult(False, status, error="MediaMTX từ chối xác thực nội bộ.")
    return ProbeResult(False, status, error=f"RTSP DESCRIBE trả về {status}")
