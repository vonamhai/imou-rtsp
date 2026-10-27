from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import pytest
from fake_relay import FakeRelay, expired_server_context
from helpers import free_tcp_port, make_device, make_settings

from app import cloud_front
from app.cameras import CameraConfig
from app.cloud import CloudManager, CloudStream, SourceError
from app.cloud_front import CloudFront, CloudFrontManager, rewrite_request_head, rewrite_uri
from app.imou.api import ImouAuthError
from app.imou.media import extract_stream
from app.imou.models import ImouChannel
from app.imou.p2p import plain_credential
from app.mediamtx import READ_TIMEOUT, MediaMTX, render_config
from app.relay import P2PManager, front_config
from app.store import Store
from app.streams import StreamManager, camera_credentials

ENCRYPTED = "q83vEjRWeJCrze8SNFZ4kA=="  # 24 base64 chars = one AES block
LOCAL = "rtsp://127.0.0.1:5000/cam"
REMOTE = "rtsp://1.2.3.4:9133/abc_1?expire=9&digest=d&X-LC-TransID=t"


async def _response(reader: asyncio.StreamReader) -> tuple[int, dict[str, str], bytes]:
    head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
    lines = head.decode().split("\r\n")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip().lower()] = value.strip()
    length = int(headers.get("content-length", "0"))
    body = await reader.readexactly(length) if length else b""
    return int(lines[0].split(" ")[1]), headers, body


async def _request(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    method: str,
    uri: str,
    cseq: int,
    extra: str = "",
) -> tuple[int, dict[str, str], bytes]:
    writer.write(f"{method} {uri} RTSP/1.0\r\nCSeq: {cseq}\r\n{extra}\r\n".encode())
    await writer.drain()
    return await _response(reader)


async def _closed(reader: asyncio.StreamReader) -> bool:
    try:
        return await asyncio.wait_for(reader.read(), 5) == b""
    except ConnectionError:
        return True


# --------------------------------------------------------------- helpers


def test_rewrite_uri_maps_loopback_to_signed_url() -> None:
    assert rewrite_uri(LOCAL, LOCAL, REMOTE) == REMOTE
    assert rewrite_uri(f"{LOCAL}/", LOCAL, REMOTE) == REMOTE
    assert rewrite_uri(f"{LOCAL}/trackID=0", LOCAL, REMOTE) == f"{REMOTE}/trackID=0"
    assert rewrite_uri(f"{REMOTE}/trackID=1", LOCAL, REMOTE) == f"{REMOTE}/trackID=1"
    assert rewrite_uri(f"{LOCAL}x", LOCAL, REMOTE) == f"{LOCAL}x"
    assert rewrite_uri("*", LOCAL, REMOTE) == "*"


def test_rewrite_request_head_keeps_headers() -> None:
    head = f"DESCRIBE {LOCAL} RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n\r\n".encode()
    assert rewrite_request_head(head, LOCAL, REMOTE) == (
        f"DESCRIBE {REMOTE} RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n\r\n".encode()
    )
    garbage = b"hello\r\n\r\n"
    assert rewrite_request_head(garbage, LOCAL, REMOTE) == garbage


def test_plain_credential_drops_encrypted_blobs() -> None:
    assert plain_credential(ENCRYPTED) == ""
    assert plain_credential("  admin ") == "admin"
    assert plain_credential("L2A4B6C8") == "L2A4B6C8"
    assert plain_credential("abcdefghijklmnopqrstuvw!") == "abcdefghijklmnopqrstuvw!"
    assert plain_credential(None) == ""


def test_encrypted_cloud_credentials_are_not_used() -> None:
    device = make_device(deviceUsername=ENCRYPTED, devicePassword=ENCRYPTED)
    assert camera_credentials(device, CameraConfig()) == ("admin", "")


def test_front_config_prefers_safety_code_from_ui() -> None:
    device = make_device(
        deviceUsername=ENCRYPTED,
        p2pConfig={"port": 8086, "type": 1, "accountNew": ENCRYPTED, "p2pToken": ENCRYPTED},
    )
    cloud = front_config(device)
    typed = front_config(device, "", "L2A4B6C8")
    assert (cloud.p2p_username, cloud.p2p_password) == (ENCRYPTED, ENCRYPTED)
    assert cloud.rtsp_username == ""
    assert typed.p2p_username == "admin"
    assert typed.p2p_password == "L2A4B6C8"
    assert typed.serial == cloud.serial == device.device_id


def test_extract_stream_reports_the_key() -> None:
    payload = {"data": {"resource": "rtsp://h/a", "tlsResource": "rtsp://h:9133/b"}}
    assert extract_stream(payload) == ("tlsresource", "rtsp://h:9133/b")
    assert extract_stream({"x": 1}) is None


class _LiveClient:
    def __init__(self, payload: dict[str, Any], mode: str = "") -> None:
        self.payload = payload
        self.mode = mode
        self.calls: list[dict[str, Any]] = []
        self.rejected: list[tuple[Any, ...]] = []

    async def async_get_live_url(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        return self.payload

    def live_diagnostic(self, *args: Any) -> str:
        return "test"

    def live_mode(self, *args: Any) -> str:
        return self.mode

    def reject_live_mode(self, *args: Any) -> None:
        self.rejected.append(args)


async def test_live_stream_marks_tls_links_and_can_bypass_cache(tmp_path: Path) -> None:
    store = Store(tmp_path)
    store.load()
    store.add_account("user@example.com", "pw", store.terminal_id)
    cloud = CloudManager(make_settings(tmp_path), store, None)
    account = cloud.accounts[0]
    client = _LiveClient({"tlsResource": "rtsp://1.2.3.4:9133/x_1?digest=d"})
    account.client = client  # type: ignore[assignment]
    account.status = "ok"
    device = make_device()
    account.devices[device.device_id] = device
    channel = ImouChannel(channel_id="0", name="cam")

    stream = await cloud.live_stream(device, channel, sub=True, fresh=True)
    assert stream == CloudStream("rtsp://1.2.3.4:9133/x_1?digest=d", tls=True, key="tlsresource")
    assert client.calls[-1] == {"stream_id": "1", "use_cache": False}
    assert stream.reject is None and stream.label == "tlsresource"

    client.mode = "transfer"
    stream = await cloud.live_stream(device, channel, sub=True, fresh=True)
    assert stream.mode == "transfer" and stream.label == "transfer/tlsresource"
    assert stream.reject is not None and "digest" not in repr(stream.reject)
    stream.reject()
    assert client.rejected == [("P1", "AAA111", "0", "1", "transfer")]

    client.payload = {"data": {"url": "https://cdn/live.m3u8?t=1"}}
    stream = await cloud.live_stream(device, channel, sub=False)
    assert not stream.tls and not stream.is_rtsp
    assert client.calls[-1] == {"stream_id": "0", "use_cache": True}


class _ExpiredClient(_LiveClient):
    async def async_get_live_url(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        raise ImouAuthError("token expired")


async def test_live_stream_prefers_the_owner_and_falls_back_to_a_share(tmp_path: Path) -> None:
    store = Store(tmp_path)
    store.load()
    for name in ("guest@example.com", "owner@example.com"):
        store.add_account(name, "pw", store.unused_terminal_id())
    cloud = CloudManager(make_settings(tmp_path), store, None)
    guest, owner = cloud.accounts
    guest_client = _LiveClient({"resource": "rtsp://guest.example/x"})
    owner_client = _LiveClient({"resource": "rtsp://owner.example/x"})
    for account, client, role in ((guest, guest_client, "share"), (owner, owner_client, "owner")):
        account.client = client  # type: ignore[assignment]
        account.status = "ok"
        account.devices["AAA111"] = make_device(role=role)
    device, channel = cloud.find("AAA111:0")
    assert device is owner.devices["AAA111"] and channel is not None

    stream = await cloud.live_stream(device, channel, sub=False)
    assert stream.url == "rtsp://owner.example/x" and guest_client.calls == []

    expired = _ExpiredClient({})
    owner.client = expired  # type: ignore[assignment]
    stream = await cloud.live_stream(device, channel, sub=False)
    assert stream.url == "rtsp://guest.example/x"
    assert owner.status == "needs_login"
    await cloud.live_stream(device, channel, sub=False)
    assert len(expired.calls) == 1 and len(guest_client.calls) == 2

    guest.status = "needs_login"
    with pytest.raises(SourceError):
        await cloud.live_stream(device, channel, sub=False)
    with pytest.raises(SourceError, match="cần đăng nhập Imou"):
        await cloud.live_stream(make_device(deviceId="ZZZ"), channel, sub=False)


# ----------------------------------------------------------------- front


async def test_front_rewrites_requests_and_fetches_a_new_link_per_client(monkeypatch: Any) -> None:
    monkeypatch.setattr(cloud_front, "_RETRY_PAUSE", 0.01)
    monkeypatch.setattr(cloud_front, "_TLS_PROBE_TIMEOUT", 0.3)
    relay = FakeRelay()
    await relay.start()

    async def fetch() -> CloudStream:
        return CloudStream(relay.issue(), key="resource")

    front = CloudFront("cam", fetch)
    port = await front.open()
    local = front.local_url
    writers: list[asyncio.StreamWriter] = []
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writers.append(writer)
        writer.write(f"OPTIONS {local} RTSP/1.0\r\nCSeq: 1\r\n".encode())
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.write(b"\r\n")
        assert (await _response(reader))[0] == 200

        status, headers, body = await _request(reader, writer, "DESCRIBE", local, 2)
        url = relay.issued[0]
        assert status == 200 and headers["content-base"] == url and b"trackID=0" in body

        transport = "Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n"
        status, _, _ = await _request(reader, writer, "SETUP", f"{local}/trackID=0", 3, transport)
        assert status == 200

        rtcp = b"$\x01\x00\x04abcd"
        payload = b"x-dynamic-rate: 1\r\n"
        writer.write(
            rtcp
            + f"SET_PARAMETER {url} RTSP/1.0\r\nCSeq: 4\r\n".encode()
            + f"Content-Length: {len(payload)}\r\n\r\n".encode()
            + payload
        )
        assert (await _response(reader))[0] == 200
        assert (await _request(reader, writer, "PLAY", url, 5, "Session: 777\r\n"))[0] == 200

        assert relay.requests == [
            ("OPTIONS", url),
            ("DESCRIBE", url),
            ("SETUP", f"{url}/trackID=0"),
            ("SET_PARAMETER", url),
            ("PLAY", url),
        ]
        assert relay.frames == [rtcp]
        assert relay.bodies == [payload]

        second_reader, second = await asyncio.open_connection("127.0.0.1", port)
        writers.append(second)
        assert (await _request(second_reader, second, "OPTIONS", local, 1))[0] == 200
        assert relay.requests[-1] == ("OPTIONS", relay.issued[1])
        assert front.sessions == 2 and front.last_error == ""

        async def stale() -> CloudStream:
            return CloudStream(url)

        front.fetch = stale
        third_reader, third = await asyncio.open_connection("127.0.0.1", port)
        writers.append(third)
        third.write(f"OPTIONS {local} RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
        status, headers, _ = await _response(third_reader)
        assert status == 503 and headers["cseq"] == "1"
        assert await _closed(third_reader)
        # First session + three plain tries; one TLS try in between sends no RTSP.
        assert relay.requests.count(("OPTIONS", url)) == 4
        assert "không trả lời" in front.last_error and "closed without a reply" in front.last_error
    finally:
        for item in writers:
            item.close()
        await front.close()
        await relay.close()


async def test_front_speaks_tls_to_relays_with_expired_certificates(tmp_path: Path) -> None:
    relay = FakeRelay(expired_server_context(tmp_path))
    await relay.start()

    async def fetch() -> CloudStream:
        return CloudStream(relay.issue(), tls=True, key="tlsresource")

    front = CloudFront("cam", fetch)
    port = await front.open()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        status, headers, _ = await _request(reader, writer, "DESCRIBE", front.local_url, 1)
        assert status == 200 and headers["content-base"] == relay.issued[0]
        writer.close()
    finally:
        await front.close()
        await relay.close()


async def test_front_reports_fetch_errors_and_backs_off() -> None:
    calls = 0

    async def fetch() -> CloudStream:
        nonlocal calls
        calls += 1
        raise SourceError("Imou không cấp link")

    front = CloudFront("cam", fetch)
    port = await front.open()
    try:
        for expected in (503, 503, None):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(f"OPTIONS {front.local_url} RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
            if expected:
                assert (await _response(reader))[0] == expected
            assert await _closed(reader)
            writer.close()
        assert calls == 2  # the third client arrives inside the 5 s back-off
        assert front.last_error == "Imou không cấp link"
    finally:
        await front.close()


async def test_front_rejects_links_that_are_not_rtsp() -> None:
    async def fetch() -> CloudStream:
        return CloudStream("https://cdn/live.m3u8")

    front = CloudFront("cam", fetch)
    port = await front.open()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        assert (await _request(reader, writer, "DESCRIBE", front.local_url, 2))[0] == 503
        assert await _closed(reader)
        writer.close()
        assert "RTSP" in front.last_error
    finally:
        await front.close()


async def test_manager_reuses_and_prunes_fronts() -> None:
    async def first_fetch() -> CloudStream:
        return CloudStream("rtsp://h/a")

    async def second_fetch() -> CloudStream:
        return CloudStream("rtsp://h/b")

    manager = CloudFrontManager()
    front = await manager.ensure("cam", first_fetch)
    again = await manager.ensure("cam", second_fetch)
    assert again is front and front.fetch is second_fetch and front.port
    other = await manager.ensure("cam_sub", first_fetch)
    await manager.prune({"cam"})
    assert manager.get("cam") is front and manager.get("cam_sub") is None
    assert other._server is not None and not other._server.is_serving()
    await manager.close()
    assert manager.get("cam") is None


# ------------------------------------------------------------ wake-up


def test_front_answers_before_mediamtx_gives_up(tmp_path: Path) -> None:
    config = render_config(make_settings(tmp_path), "internal", "secret")
    assert config["readTimeout"] == f"{READ_TIMEOUT}s"
    assert cloud_front._ANSWER_DEADLINE + cloud_front._MIN_ATTEMPT_WINDOW <= READ_TIMEOUT


def _relay_fetch(relay: FakeRelay, *, tls: bool = False, rejected: list[str] | None = None) -> Any:
    async def fetch() -> CloudStream:
        reject = None if rejected is None else (lambda: rejected.append("transfer"))
        return CloudStream(relay.issue(), tls=tls, key="tlsresource", mode="transfer", reject=reject)

    return fetch


async def test_front_replays_the_first_request_while_the_camera_wakes_up(
    monkeypatch: Any,
) -> None:
    # A slow refusal means the camera is waking up: try a new link at once.
    monkeypatch.setattr(cloud_front, "_QUICK_FAILURE", 0.2)
    monkeypatch.setattr(cloud_front, "_RETRY_PAUSE", 10.0)
    relay = FakeRelay(asleep=1, wake_delay=0.3)
    await relay.start()
    front = CloudFront("cam", _relay_fetch(relay))
    port = await front.open()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        started = time.monotonic()
        status, headers, _ = await _request(reader, writer, "OPTIONS", front.local_url, 7)
        assert status == 200 and headers["cseq"] == "7"
        assert time.monotonic() - started < 2
        cold, warm = relay.issued
        assert relay.requests == [("OPTIONS", cold), ("OPTIONS", warm)]
        status, headers, _ = await _request(reader, writer, "DESCRIBE", front.local_url, 8)
        assert status == 200 and headers["content-base"] == warm
        assert front.sessions == 1 and front.last_error == ""
        writer.close()
    finally:
        await front.close()
        await relay.close()


async def test_front_retries_relays_that_hang_up_silently(
    tmp_path: Path, monkeypatch: Any
) -> None:
    # TLS links that hang up (a waking camera) get new links, never a reject.
    monkeypatch.setattr(cloud_front, "_RETRY_PAUSE", 0.01)
    relay = FakeRelay(expired_server_context(tmp_path), asleep=2, wake_status=None)
    await relay.start()
    rejected: list[str] = []
    front = CloudFront("cam", _relay_fetch(relay, tls=True, rejected=rejected))
    port = await front.open()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        assert (await _request(reader, writer, "DESCRIBE", front.local_url, 1))[0] == 200
        assert len(relay.issued) == 3 and front.sessions == 1
        assert rejected == []
        writer.close()
    finally:
        await front.close()
        await relay.close()


async def test_front_retries_plain_links_over_tls_and_remembers(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(cloud_front, "_RETRY_PAUSE", 0.01)
    relay = FakeRelay(expired_server_context(tmp_path))
    await relay.start()
    rejected: list[str] = []

    async def fetch() -> CloudStream:
        return CloudStream(
            relay.issue(), key="url", mode="standard-rtsp", reject=lambda: rejected.append("x")
        )

    front = CloudFront("cam", fetch)
    port = await front.open()
    try:
        for expected_links in (2, 3):  # the second client goes straight to TLS
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            status, headers, _ = await _request(reader, writer, "DESCRIBE", front.local_url, 1)
            assert status == 200 and headers["content-base"] == relay.issued[-1]
            assert len(relay.issued) == expected_links
            writer.close()
        assert front.sessions == 2 and rejected == []
    finally:
        await front.close()
        await relay.close()


async def test_front_sets_aside_link_types_that_never_answer(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(cloud_front, "_RETRY_PAUSE", 0.01)

    async def hang_up(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()

    dead = await asyncio.start_server(hang_up, "127.0.0.1", 0)
    dead_port = int(dead.sockets[0].getsockname()[1])
    good = FakeRelay(expired_server_context(tmp_path))
    await good.start()
    rejected: list[str] = []

    async def fetch() -> CloudStream:
        if not rejected:
            return CloudStream(
                f"rtsp://127.0.0.1:{dead_port}/x?digest=d",
                key="url",
                mode="standard-rtsp",
                reject=lambda: rejected.append("standard-rtsp"),
            )
        return CloudStream(good.issue(), tls=True, key="tlsresource", mode="transfer")

    front = CloudFront("cam", fetch)
    port = await front.open()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        status, headers, _ = await _request(reader, writer, "DESCRIBE", front.local_url, 1)
        assert status == 200 and headers["content-base"] == good.issued[0]
        assert rejected == ["standard-rtsp"] and front.sessions == 1
        writer.close()
    finally:
        await front.close()
        dead.close()
        await good.close()


def test_relay_failures_are_described_without_secrets() -> None:
    def partial(data: bytes) -> asyncio.IncompleteReadError:
        return asyncio.IncompleteReadError(data, None)

    assert cloud_front.describe_error(partial(b"")) == "closed without a reply"
    assert "expects TLS" in cloud_front.describe_error(partial(b"\x15\x03\x01\x00\x02\x02\x46"))
    assert cloud_front.describe_reply(b"HTTP/1.1 400 Bad Request\r\n") == "HTTP reply 400"
    assert cloud_front.describe_reply(b"\x00\x01secret-token") == "14 unexpected byte(s) 00017365"
    assert cloud_front.describe_error(ConnectionResetError()) == "connection reset"
    assert cloud_front.describe_error(TimeoutError()) == "timed out"


async def test_front_passes_on_the_relay_error_when_the_camera_stays_asleep(
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr(cloud_front, "_RETRY_PAUSE", 0.01)
    relay = FakeRelay(asleep=10)
    await relay.start()
    front = CloudFront("cam", _relay_fetch(relay))
    port = await front.open()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        status, headers, _ = await _request(reader, writer, "OPTIONS", front.local_url, 3)
        assert status == 500 and headers["cseq"] == "3"
        assert await _closed(reader)
        writer.close()
        assert len(relay.issued) == cloud_front._MAX_ATTEMPTS
        assert "RTSP 500" in front.last_error and front.sessions == 0
    finally:
        await front.close()
        await relay.close()


async def test_front_answers_503_before_the_client_gives_up(monkeypatch: Any) -> None:
    monkeypatch.setattr(cloud_front, "_ANSWER_DEADLINE", 0.5)
    relay = FakeRelay(asleep=1, wake_delay=30)
    await relay.start()
    front = CloudFront("cam", _relay_fetch(relay))
    port = await front.open()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        started = time.monotonic()
        status, headers, _ = await _request(reader, writer, "OPTIONS", front.local_url, 4)
        assert status == 503 and headers["cseq"] == "4"
        assert time.monotonic() - started < 3
        assert len(relay.issued) == 1 and "không trả lời" in front.last_error
        writer.close()
    finally:
        await front.close()
        await relay.close()


async def test_front_waits_for_a_request_before_asking_for_a_link(monkeypatch: Any) -> None:
    monkeypatch.setattr(cloud_front, "_CLIENT_TIMEOUT", 0.2)
    calls = 0

    async def fetch() -> CloudStream:
        nonlocal calls
        calls += 1
        raise SourceError("không được gọi")

    front = CloudFront("cam", fetch)
    port = await front.open()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        assert await _closed(reader)
        writer.close()
        assert calls == 0 and front.last_error == ""
    finally:
        await front.close()


# ------------------------------------------------------ through MediaMTX


class _StubCloud:
    def __init__(self, relay: FakeRelay) -> None:
        self.relay = relay
        self.device = make_device()
        self.channel = ImouChannel(channel_id="0", name="cam")
        self.fresh: list[bool] = []

    def find(self, key: str) -> tuple[Any, Any]:
        return self.device, self.channel

    async def live_stream(
        self, device: Any, channel: Any, *, sub: bool, fresh: bool = False
    ) -> CloudStream:
        self.fresh.append(fresh)
        return CloudStream(self.relay.issue(), tls=True, key="tlsresource")


@pytest.mark.parametrize("asleep", [0, 1], ids=["awake", "waking-up"])
async def test_cloud_relay_is_republished_through_mediamtx(
    tmp_path: Path, mediamtx_bin: str, asleep: int
) -> None:
    # A waking camera's relay answers after 11 s, past MediaMTX's old 10 s readTimeout.
    relay = FakeRelay(expired_server_context(tmp_path), asleep=asleep, wake_delay=11)
    await relay.start()
    settings = make_settings(
        tmp_path,
        MEDIAMTX_BIN=mediamtx_bin,
        RTSP_PORT=str(free_tcp_port()),
        MEDIAMTX_API_PORT=str(free_tcp_port()),
        RTSP_TRANSPORTS="tcp",
    )
    store = Store(tmp_path)
    store.load()
    store.cameras = {"DEV1:0": CameraConfig(enabled=True, path="yard", mode="cloud", channel=1)}
    cloud = _StubCloud(relay)
    mtx = MediaMTX(settings)
    streams = StreamManager(settings, store, cloud, mtx, P2PManager(60))  # type: ignore[arg-type]
    await mtx.start()
    try:
        await asyncio.wait_for(mtx.ready.wait(), 30)
        streams.start()
        results = await streams.test("DEV1:0")
        assert [(item["kind"], item["ok"], item["codecs"]) for item in results] == [
            ("main", True, ["video H264"])
        ]
        # One lookup to learn the link type, then a fresh link per relay session.
        assert cloud.fresh == [False] + [True] * (1 + asleep)
        assert relay.used == set(relay.issued[1:])
        url = relay.issued[-1]
        assert relay.requests[: asleep + 4] == [("OPTIONS", relay.issued[1])] * asleep + [
            ("OPTIONS", url),
            ("DESCRIBE", url),
            ("SETUP", f"{url}/trackID=0"),
            ("PLAY", url),
        ]
        source = (await mtx.list_path_configs())["yard"]["source"]
        assert source.startswith("rtsp://127.0.0.1:") and "digest" not in source
        assert "trung chuyển" in streams.stream_status("DEV1:0", "main")["source"]
    finally:
        await streams.stop()
        await mtx.stop()
        await relay.close()
