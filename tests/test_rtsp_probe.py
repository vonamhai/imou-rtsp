"""The probe behind the web UI's "Kiểm tra" button must see real video."""

from __future__ import annotations

import asyncio

from fake_rtsp import rtp_packet

from app.rtsp_probe import first_track, probe, track_url

# Like an Imou 4G camera's main stream, with the audio track listed first.
SDP = (
    "v=0\r\n"
    "o=- 0 0 IN IP4 127.0.0.1\r\n"
    "s=Stream\r\n"
    "t=0 0\r\n"
    "a=control:*\r\n"
    "m=audio 0 RTP/AVP 97\r\n"
    "a=rtpmap:97 MPEG4-GENERIC/16000/1\r\n"
    "a=control:trackID=1\r\n"
    "m=video 0 RTP/AVP 98\r\n"
    "a=rtpmap:98 H265/90000\r\n"
    "a=control:trackID=0\r\n"
)


def _frame(channel: int, payload: bytes) -> bytes:
    return b"$" + bytes([channel]) + len(payload).to_bytes(2, "big") + payload


class StubServer:
    """Answers the probe's handshake and then writes ``after_play``."""

    def __init__(
        self, after_play: bytes = b"", setup_status: str = "200 OK", *, hangup: bool = False
    ) -> None:
        self.after_play = after_play
        self.setup_status = setup_status
        self.hangup = hangup
        self.requests: list[tuple[str, str, dict[str, str]]] = []
        self.port = 0
        self._server: asyncio.AbstractServer | None = None

    async def __aenter__(self) -> StubServer:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = int(self._server.sockets[0].getsockname()[1])
        return self

    async def __aexit__(self, *exc: object) -> None:
        assert self._server is not None
        self._server.close()

    @property
    def base(self) -> str:
        return f"rtsp://127.0.0.1:{self.port}/cam/"

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                lines = head.decode().split("\r\n")
                method, uri, _ = lines[0].split(" ", 2)
                headers: dict[str, str] = {}
                for line in lines[1:]:
                    name, sep, value = line.partition(":")
                    if sep:
                        headers[name.strip().lower()] = value.strip()
                self.requests.append((method, uri, headers))
                status, extra, body = "200 OK", "", ""
                if method == "DESCRIBE":
                    extra = f"Content-Base: {self.base}\r\nContent-Type: application/sdp\r\n"
                    body = SDP
                elif method == "SETUP":
                    status = self.setup_status
                    extra = (
                        "Transport: RTP/AVP/TCP;unicast;interleaved=4-5\r\n"
                        "Session: s1;timeout=60\r\n"
                    )
                writer.write(
                    f"RTSP/1.0 {status}\r\nCSeq: {headers['cseq']}\r\n{extra}"
                    f"Content-Length: {len(body)}\r\n\r\n{body}".encode()
                )
                if method == "PLAY":
                    writer.write(self.after_play)
                await writer.drain()
                if method == "PLAY" and self.hangup:
                    return
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()


def test_first_track_prefers_video() -> None:
    assert first_track(SDP) == ("video", "trackID=0")
    assert first_track("v=0\r\nm=audio 0 RTP/AVP 0\r\n") == ("audio", "")
    assert first_track("v=0\r\n") is None


def test_track_url_resolves_controls_against_the_content_base() -> None:
    base = "rtsp://h:8554/cam/"
    assert track_url(base, "trackID=0") == "rtsp://h:8554/cam/trackID=0"
    assert track_url(base.rstrip("/"), "trackID=0") == "rtsp://h:8554/cam/trackID=0"
    assert track_url(base, "rtsp://other/x") == "rtsp://other/x"
    assert track_url(base, "*") == base
    assert track_url(base, "") == base


async def test_probe_waits_for_video_on_the_channel_the_server_assigned() -> None:
    video = rtp_packet(0, 98)[4:]
    noise = (
        _frame(5, b"\x80\xc8\x00\x06" + bytes(24))  # RTCP sender report
        + _frame(2, b"audio")
        + b"RTSP/1.0 200 OK\r\nCSeq: 9\r\nContent-Length: 2\r\n\r\nok"
    )
    async with StubServer(noise + _frame(4, video)) as server:
        result = await probe(
            "127.0.0.1", server.port, "cam", username="u", password="p", timeout=5
        )
    assert result.ok and result.status == 200 and result.error == ""
    assert result.codecs == ["audio MPEG4-GENERIC", "video H265"]
    assert [(method, uri) for method, uri, _ in server.requests] == [
        ("OPTIONS", f"rtsp://127.0.0.1:{server.port}/cam"),
        ("DESCRIBE", f"rtsp://127.0.0.1:{server.port}/cam"),
        ("SETUP", f"{server.base}trackID=0"),
        ("PLAY", server.base),
    ]
    setup, play = server.requests[2][2], server.requests[3][2]
    assert setup["transport"] == "RTP/AVP/TCP;unicast;interleaved=0-1"
    assert play["session"] == "s1"
    assert setup["authorization"].startswith("Basic ") and play["authorization"] == setup["authorization"]


async def test_probe_fails_when_the_handshake_works_but_no_video_arrives() -> None:
    # The 4G camera's main stream: PLAY succeeds, then only a little audio.
    async with StubServer(_frame(2, b"audio") + _frame(0, b"other")) as server:
        result = await probe("127.0.0.1", server.port, "cam", timeout=5, media_timeout=0.3)
    assert not result.ok and result.status == 200
    assert result.codecs == ["audio MPEG4-GENERIC", "video H265"]
    assert "không gửi hình trong 0.3 giây" in result.error


async def test_probe_reports_a_stream_that_ends_before_any_video() -> None:
    # MediaMTX drops its readers when the source fails.
    async with StubServer(_frame(2, b"audio"), hangup=True) as server:
        result = await probe("127.0.0.1", server.port, "cam", timeout=5, media_timeout=5)
    assert not result.ok and result.codecs == ["audio MPEG4-GENERIC", "video H265"]
    assert result.error == "Luồng bị ngắt trước khi nhận được hình."


async def test_probe_accepts_describe_when_tcp_is_disabled() -> None:
    async with StubServer(setup_status="461 Unsupported Transport") as server:
        result = await probe("127.0.0.1", server.port, "cam", timeout=5, media_timeout=5)
    assert result.ok and result.codecs == ["audio MPEG4-GENERIC", "video H265"]
    assert [method for method, _, _ in server.requests] == ["OPTIONS", "DESCRIBE", "SETUP"]
