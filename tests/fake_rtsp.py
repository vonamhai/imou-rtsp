"""A tiny RTSP "camera" (Digest auth, TCP interleaved) used by the tests."""

from __future__ import annotations

import asyncio
import re
from contextlib import suppress
from hashlib import md5

REALM = "Login to FAKECAM"
NONCE = "0123456789abcdef"
SDP = (
    "v=0\r\n"
    "o=- 0 0 IN IP4 127.0.0.1\r\n"
    "s=Fake camera\r\n"
    "c=IN IP4 0.0.0.0\r\n"
    "t=0 0\r\n"
    "m=video 0 RTP/AVP 96\r\n"
    "a=rtpmap:96 H264/90000\r\n"
    "a=fmtp:96 packetization-mode=1\r\n"
    "a=control:trackID=0\r\n"
)


def _md5(text: str) -> str:
    return md5(text.encode()).hexdigest()


def rtp_packet(sequence: int, payload_type: int = 96) -> bytes:
    """An interleaved RTP packet on channel 0 carrying one dummy H264 IDR slice."""
    packet = (
        bytes([0x80, 0x80 | payload_type])
        + (sequence & 0xFFFF).to_bytes(2, "big")
        + (sequence * 4500 & 0xFFFFFFFF).to_bytes(4, "big")
        + b"\x12\x34\x56\x78"
        + b"\x65\x88\x84\x00\x21"
    )
    return b"$\x00" + len(packet).to_bytes(2, "big") + packet


async def stream_rtp(writer: asyncio.StreamWriter, interval: float = 0.05) -> None:
    """Send video until the connection closes, like a camera after PLAY."""
    sequence = 0
    while not writer.is_closing():
        if writer.transport.get_write_buffer_size() < 65536:
            writer.write(rtp_packet(sequence))
            sequence += 1
        await asyncio.sleep(interval)


class FakeCamera:
    """Answers OPTIONS/DESCRIBE/SETUP/PLAY like a Dahua camera."""

    def __init__(
        self, username: str = "admin", password: str = "secret", *, stream: bool = True
    ) -> None:
        self.username = username
        self.password = password
        self.stream = stream
        self.requests: list[tuple[str, str, dict[str, str]]] = []
        self.authorized: list[str] = []
        self.port = 0
        self._server: asyncio.AbstractServer | None = None
        self._writers: set[asyncio.StreamWriter] = set()

    async def start(self) -> int:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = int(self._server.sockets[0].getsockname()[1])
        return self.port

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
        for writer in list(self._writers):
            writer.close()
        if self._server is not None:
            with suppress(Exception):
                await asyncio.wait_for(self._server.wait_closed(), 5)

    def _digest_ok(self, method: str, header: str) -> bool:
        if not header.lower().startswith("digest "):
            return False
        params = dict(re.findall(r'(\w+)="?([^",]*)"?', header[7:]))
        if params.get("username") != self.username or params.get("nonce") != NONCE:
            return False
        ha1 = _md5(f"{self.username}:{REALM}:{self.password}")
        ha2 = _md5(f"{method}:{params.get('uri', '')}")
        return params.get("response") == _md5(f"{ha1}:{NONCE}:{ha2}")

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._writers.add(writer)
        streaming: asyncio.Task[None] | None = None
        try:
            while True:
                first = await reader.readexactly(1)
                if first == b"$":  # RTCP receiver reports from MediaMTX
                    header = await reader.readexactly(3)
                    await reader.readexactly(int.from_bytes(header[1:3], "big"))
                    continue
                head = first + await reader.readuntil(b"\r\n\r\n")
                lines = head.decode("utf-8", "replace").split("\r\n")
                method, url, _ = lines[0].split(" ", 2)
                headers: dict[str, str] = {}
                for line in lines[1:]:
                    name, sep, value = line.partition(":")
                    if sep:
                        headers[name.strip().lower()] = value.strip()
                length = int(headers.get("content-length", "0") or 0)
                if length:
                    await reader.readexactly(length)
                self.requests.append((method, url, headers))
                cseq = headers.get("cseq", "0")
                extra = ""
                body = ""
                status = "200 OK"
                if method == "OPTIONS":
                    extra = "Public: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN, GET_PARAMETER\r\n"
                elif method == "DESCRIBE":
                    if self._digest_ok(method, headers.get("authorization", "")):
                        self.authorized.append(url)
                        base = url if url.endswith("/") else url + "/"
                        extra = f"Content-Base: {base}\r\nContent-Type: application/sdp\r\n"
                        body = SDP
                    else:
                        status = "401 Unauthorized"
                        extra = f'WWW-Authenticate: Digest realm="{REALM}", nonce="{NONCE}"\r\n'
                elif method == "SETUP":
                    transport = headers.get("transport", "")
                    if "TCP" not in transport.upper():
                        status = "461 Unsupported Transport"
                    else:
                        extra = (
                            "Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n"
                            "Session: 12345678;timeout=60\r\n"
                        )
                elif method in ("PLAY", "GET_PARAMETER"):
                    extra = "Session: 12345678\r\n"
                elif method == "TEARDOWN":
                    writer.write(f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n\r\n".encode())
                    await writer.drain()
                    return
                else:
                    status = "405 Method Not Allowed"
                payload = body.encode()
                writer.write(
                    (
                        f"RTSP/1.0 {status}\r\nCSeq: {cseq}\r\n{extra}"
                        f"Content-Length: {len(payload)}\r\n\r\n"
                    ).encode()
                    + payload
                )
                await writer.drain()
                if method == "PLAY" and streaming is None and self.stream:
                    streaming = asyncio.create_task(stream_rtp(writer))
        except (asyncio.IncompleteReadError, ConnectionError, ValueError):
            pass
        finally:
            if streaming is not None:
                streaming.cancel()
            self._writers.discard(writer)
            writer.close()
