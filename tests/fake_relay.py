"""A fake Imou cloud relay: signed single-use URLs, absolute Content-Base, TLS."""

from __future__ import annotations

import asyncio
import datetime
import ssl
from contextlib import suppress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fake_rtsp import stream_rtp

RELAY_SDP = (
    "v=0\r\n"
    "o=- 0 0 IN IP4 127.0.0.1\r\n"
    "s=MTS\r\n"
    "t=0 0\r\n"
    "a=control:*\r\n"
    "m=video 0 RTP/AVP 96\r\n"
    "a=rtpmap:96 H264/90000\r\n"
    "a=fmtp:96 packetization-mode=1\r\n"
    "a=control:trackID=0\r\n"
)


def expired_server_context(tmp_path: Path) -> ssl.SSLContext:
    """Server TLS context with an expired self-signed ``*.lechange.com`` cert."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "*.lechange.com")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=60))
        .not_valid_after(now - datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "relay.crt"
    key_path = tmp_path / "relay.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    return context


class FakeRelay:
    """Serves each issued URL once, like Imou's ``GetRealTransferStreamUrl`` relays."""

    def __init__(
        self,
        ssl_context: ssl.SSLContext | None = None,
        *,
        asleep: int = 0,
        wake_status: str | None = "500 Internal Server Error",
        wake_delay: float = 0.0,
    ) -> None:
        """``asleep`` sessions answer their first request with ``wake_status``
        (or hang up silently when it is None) after ``wake_delay`` seconds,
        like Imou's relay while it wakes a sleeping camera."""
        self.ssl_context = ssl_context
        self.asleep = asleep
        self.wake_status = wake_status
        self.wake_delay = wake_delay
        self.port = 0
        self.issued: list[str] = []
        self.used: set[str] = set()
        self.requests: list[tuple[str, str]] = []
        self.bodies: list[bytes] = []
        self.frames: list[bytes] = []
        self._server: asyncio.AbstractServer | None = None
        self._writers: set[asyncio.StreamWriter] = set()

    async def start(self) -> int:
        self._server = await asyncio.start_server(
            self._handle, "127.0.0.1", 0, ssl=self.ssl_context
        )
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

    def issue(self) -> str:
        number = len(self.issued) + 1
        url = (
            f"rtsp://127.0.0.1:{self.port}/abc{number}_1"
            f"?expire=9&digest=d{number}&X-LC-TransID=t{number}"
        )
        self.issued.append(url)
        return url

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._writers.add(writer)
        url: str | None = None
        streaming: asyncio.Task[None] | None = None
        try:
            while True:
                first = await reader.readexactly(1)
                if first == b"$":
                    header = await reader.readexactly(3)
                    payload = await reader.readexactly(int.from_bytes(header[1:3], "big"))
                    self.frames.append(first + header + payload)
                    continue
                head = first + await reader.readuntil(b"\r\n\r\n")
                lines = head.decode("utf-8", "replace").split("\r\n")
                method, uri, _ = lines[0].split(" ", 2)
                headers: dict[str, str] = {}
                for line in lines[1:]:
                    name, sep, value = line.partition(":")
                    if sep:
                        headers[name.strip().lower()] = value.strip()
                length = int(headers.get("content-length", "0") or 0)
                if length:
                    self.bodies.append(await reader.readexactly(length))
                self.requests.append((method, uri))
                cseq = headers.get("cseq", "0")
                if url is None:
                    if uri not in self.issued or uri in self.used:
                        return  # Imou closes without answering
                    self.used.add(uri)
                    url = uri
                    if self.asleep > 0:
                        self.asleep -= 1
                        if self.wake_delay > 0:
                            with suppress(TimeoutError):
                                await asyncio.wait_for(reader.read(1), self.wake_delay)
                        if self.wake_status:
                            writer.write(
                                f"RTSP/1.0 {self.wake_status}\r\nCSeq: {cseq}\r\n"
                                "Server: MTS/1.0\r\nContent-Length: 0\r\n\r\n".encode()
                            )
                            await writer.drain()
                        return
                status = "200 OK"
                extra = ""
                body = b""
                if not uri.startswith(url):
                    status = "404 Not Found"
                elif method == "OPTIONS":
                    extra = "Public: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN, SET_PARAMETER\r\n"
                elif method == "DESCRIBE":
                    extra = f"Content-Base: {url}\r\nContent-Type: application/sdp\r\n"
                    body = RELAY_SDP.encode()
                elif method == "SETUP":
                    if uri != f"{url}/trackID=0":
                        status = "404 Not Found"
                    else:
                        extra = (
                            "Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n"
                            "Session: 777;timeout=60\r\n"
                        )
                elif method in ("PLAY", "SET_PARAMETER"):
                    extra = "Session: 777\r\n"
                elif method == "TEARDOWN":
                    writer.write(f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n\r\n".encode())
                    await writer.drain()
                    return
                else:
                    status = "405 Method Not Allowed"
                writer.write(
                    (
                        f"RTSP/1.0 {status}\r\nCSeq: {cseq}\r\nServer: MTS/1.0\r\n{extra}"
                        f"Content-Length: {len(body)}\r\n\r\n"
                    ).encode()
                    + body
                )
                await writer.drain()
                if method == "PLAY" and status == "200 OK" and streaming is None:
                    streaming = asyncio.create_task(stream_rtp(writer))
        except (asyncio.IncompleteReadError, ConnectionError, ValueError, ssl.SSLError):
            pass
        finally:
            if streaming is not None:
                streaming.cancel()
            self._writers.discard(writer)
            writer.close()
