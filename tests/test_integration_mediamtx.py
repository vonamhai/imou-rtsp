"""End-to-end: fake Dahua camera -> real MediaMTX binary -> RTSP client.

Runs only when a MediaMTX binary is available (``MEDIAMTX_BIN`` or ``PATH``).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path

from fake_rtsp import FakeCamera
from helpers import free_tcp_port, make_settings

from app.cameras import CameraConfig
from app.cloud import CloudManager
from app.mediamtx import MediaMTX, MediaMTXError
from app.relay import P2PManager
from app.rtsp_probe import probe
from app.store import Store
from app.streams import StreamManager

CAMERA_PASSWORD = "Ab:c@1/2#x"


async def _eventually(check: Callable[[], Awaitable[bool]], timeout: float = 15.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not await check():
        if loop.time() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(0.25)


async def test_lan_camera_is_republished(tmp_path: Path, mediamtx_bin: str) -> None:
    rtsp_port = free_tcp_port()
    settings = make_settings(
        tmp_path,
        MEDIAMTX_BIN=mediamtx_bin,
        RTSP_PORT=str(rtsp_port),
        MEDIAMTX_API_PORT=str(free_tcp_port()),
        RTSP_TRANSPORTS="tcp",
        RTSP_USERNAME="viewer",
        RTSP_PASSWORD="pw",
    )
    camera = FakeCamera(username="admin", password=CAMERA_PASSWORD)
    camera_port = await camera.start()
    # Finishes the handshake but never sends video, like a 4G camera's main stream.
    silent = FakeCamera(stream=False)
    silent_port = await silent.start()
    store = Store(tmp_path)
    store.load()
    store.cameras = {
        "DEV1:0": CameraConfig(
            enabled=True,
            path="front",
            host="127.0.0.1",
            auto_host=False,
            port=camera_port,
            username="admin",
            password=CAMERA_PASSWORD,
            sub=True,
        ),
        "DEV2:0": CameraConfig(
            enabled=True,
            path="dead",
            host="127.0.0.1",
            auto_host=False,
            port=1,
            password="x",
            on_demand=False,
        ),
        "DEV3:0": CameraConfig(
            enabled=True,
            path="silent",
            host="127.0.0.1",
            auto_host=False,
            port=silent_port,
            username=silent.username,
            password=silent.password,
        ),
    }
    mtx = MediaMTX(settings)
    streams = StreamManager(
        settings, store, CloudManager(settings, store, None), mtx, P2PManager(60)
    )
    await mtx.start()
    try:
        await asyncio.wait_for(mtx.ready.wait(), 30)
        streams.start()

        results = await streams.test("DEV1:0")
        assert [(item["kind"], item["ok"], item["codecs"]) for item in results] == [
            ("main", True, ["video H264"]),
            ("sub", True, ["video H264"]),
        ]
        assert any("channel=1&subtype=0" in url for url in camera.authorized)
        assert any("channel=1&subtype=1" in url for url in camera.authorized)

        async def front_live() -> bool:
            await streams.refresh_runtime(max_age=0)
            return streams.stream_status("DEV1:0", "main")["state"] == "live"

        await _eventually(front_live)
        assert "H264" in streams.stream_status("DEV1:0", "main")["detail"]

        async def dead_reports_error() -> bool:
            await streams.refresh_runtime(max_age=0)
            return streams.stream_status("DEV2:0", "main")["state"] == "error"

        await _eventually(dead_reports_error)
        assert "127.0.0.1:1" in streams.stream_status("DEV2:0", "main")["detail"]

        anonymous = await probe("127.0.0.1", rtsp_port, "front")
        assert not anonymous.ok and anonymous.status == 401
        viewer = await probe("127.0.0.1", rtsp_port, "front", username="viewer", password="pw")
        assert viewer.ok and viewer.codecs == ["video H264"]
        wrong = await probe("127.0.0.1", rtsp_port, "front", username="viewer", password="no")
        assert not wrong.ok and wrong.status == 401

        silent_result = await probe(
            "127.0.0.1",
            rtsp_port,
            "silent",
            username="viewer",
            password=settings.rtsp_password,
            media_timeout=1,
        )
        assert not silent_result.ok and silent_result.status == 200
        assert silent_result.codecs == ["video H264"]
        assert "không gửi hình trong 1 giây" in silent_result.error
        assert any(method == "PLAY" for method, _, _ in silent.requests)

        store.cameras["DEV2:0"].enabled = False
        await streams.reconcile()
        configured = await mtx.list_path_configs()
        assert "dead" not in configured
        assert {"front", "front_sub"} <= set(configured)

        process = mtx._process
        assert process is not None
        process.kill()

        async def republished() -> bool:
            if mtx.generation < 2 or not mtx.available:
                return False
            try:
                return "front_sub" in await mtx.list_path_configs()
            except MediaMTXError:
                return False

        await _eventually(republished, timeout=30)
    finally:
        await streams.stop()
        await mtx.stop()
        await camera.close()
        await silent.close()
