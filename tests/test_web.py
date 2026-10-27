from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import pytest
from aiohttp.test_utils import TestClient, TestServer
from helpers import fake_imou_factory, make_settings

from app.bridge import Bridge
from app.mediamtx import basic_auth_header
from app.store import Store
from app.web import create_app

ACCOUNT = "user@example.com"
SECOND = "second@example.com"
PASSWORD = "S3cretPw!"
DEVICES = [
    {"deviceId": "AAA", "productId": "P", "name": "Cổng trước", "status": "online"},
    {"deviceId": "BBB", "productId": "P", "name": "Sân sau", "devicePassword": "CLOUDPW"},
]
SECOND_DEVICES = [{"deviceId": "CCC", "productId": "P", "name": "Nhà kho", "status": "online"}]


async def _client(tmp_path: Path, *, linked: bool = True, **env: str) -> TestClient:
    seed = Store(tmp_path)
    seed.load()
    if linked:
        record = seed.add_account(ACCOUNT, PASSWORD, seed.terminal_id)
        seed.save_devices(record.id, DEVICES)
    settings = make_settings(tmp_path, MEDIAMTX_BIN=str(tmp_path / "no-mediamtx"), **env)
    factory, _ = fake_imou_factory({ACCOUNT: DEVICES, SECOND: SECOND_DEVICES})
    client = TestClient(TestServer(create_app(Bridge(settings, client_factory=factory))))
    await client.start_server()
    return client


async def _wait_state(
    client: TestClient, ready: Callable[[dict[str, Any]], bool], timeout: float = 5.0
) -> dict[str, Any]:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        state = await (await client.get("/api/state")).json()
        if ready(state):
            return state
        if loop.time() > deadline:
            raise AssertionError(f"state not reached: {state['cloud']} {state['login']}")
        await asyncio.sleep(0.02)


def _all_ok(state: dict[str, Any]) -> bool:
    accounts = state["accounts"]
    return bool(accounts) and all(account["status"] == "ok" for account in accounts)


@pytest.fixture
async def client(tmp_path: Path) -> AsyncIterator[TestClient]:
    test_client = await _client(tmp_path)
    try:
        yield test_client
    finally:
        await test_client.close()


async def test_index_static_and_headers(client: TestClient) -> None:
    response = await client.get("/")
    assert response.status == 200
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "static/app.js" in await response.text()
    response = await client.get("/static/app.js")
    assert response.status == 200
    assert response.headers["Cache-Control"] == "no-cache"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert (await client.get("/healthz")).status == 200
    assert (await client.get("/static/../app/web.py")).status in (403, 404)


async def test_state_lists_cameras_without_secrets(client: TestClient) -> None:
    await _wait_state(client, _all_ok)
    response = await client.get("/api/state")
    assert response.status == 200
    text = await response.text()
    for secret in ("CLOUDPW", PASSWORD, ACCOUNT):
        assert secret not in text
    state = json.loads(text)
    assert state["mediamtx"]["state"] == "missing"
    assert state["cloud"]["status"] == "ok" and state["cloud"]["has_account"] is True
    assert state["cloud"]["account_count"] == 1 and state["cloud"]["device_count"] == 2
    assert state["login"]["step"] == "account"
    [account] = state["accounts"]
    assert account["label"] == "us***@example.com" and account["device_count"] == 2
    assert account["updated"] is not None and account["message"] == ""
    cameras = {camera["key"]: camera for camera in state["cameras"]}
    assert set(cameras) == {"AAA:0", "BBB:0"}
    front = cameras["AAA:0"]
    assert front["name"] == "Cổng trước" and front["online"] is True
    assert front["account_id"] == account["id"] and front["account"] == account["label"]
    assert front["config"]["path"] == "cong_truoc" and front["password_known"] is False
    assert front["streams"][0]["url"] == "rtsp://127.0.0.1:8554/cong_truoc"
    assert cameras["BBB:0"]["password_known"] is True
    assert cameras["BBB:0"]["cloud_password"] is True


async def test_post_requires_json_and_same_origin(client: TestClient) -> None:
    response = await client.post("/api/refresh", data="x=1")
    assert response.status == 403
    response = await client.post(
        "/api/refresh", json={}, headers={"Origin": "http://evil.example"}
    )
    assert response.status == 403
    response = await client.post(
        "/api/refresh", json={}, headers={"Sec-Fetch-Site": "cross-site"}
    )
    assert response.status == 403
    origin = f"http://{client.host}:{client.port}"
    response = await client.post(
        "/api/refresh", json={}, headers={"Origin": origin, "Sec-Fetch-Site": "same-origin"}
    )
    assert response.status == 200
    body = await response.json()
    assert body["ok"] is True and body["status"] == "ok"
    response = await client.post(
        "/api/refresh",
        json={},
        headers={"Origin": "https://nas.example", "X-Forwarded-Host": "nas.example"},
    )
    assert response.status == 200


async def test_without_an_account(tmp_path: Path) -> None:
    test_client = await _client(tmp_path, linked=False)
    try:
        state = await (await test_client.get("/api/state")).json()
        assert state["accounts"] == [] and state["cameras"] == []
        assert state["cloud"]["status"] == "not_configured"
        assert state["cloud"]["has_account"] is False and state["cloud"]["account_count"] == 0
        response = await test_client.post("/api/refresh", json={})
        assert response.status == 400
        assert (await response.json())["error"] == "Chưa đăng nhập Imou."
    finally:
        await test_client.close()


async def test_basic_auth(tmp_path: Path) -> None:
    test_client = await _client(tmp_path, WEB_PASSWORD="s3cret")
    try:
        response = await test_client.get("/")
        assert response.status == 401
        assert response.headers["WWW-Authenticate"].startswith("Basic")
        assert (await test_client.get("/healthz")).status == 200
        bad = {"Authorization": basic_auth_header("admin", "nope")}
        assert (await test_client.get("/api/state", headers=bad)).status == 401
        good = {"Authorization": basic_auth_header("admin", "s3cret")}
        assert (await test_client.get("/api/state", headers=good)).status == 200
        utf8 = {"Authorization": "Basic !!!"}
        assert (await test_client.get("/api/state", headers=utf8)).status == 401
    finally:
        await test_client.close()


async def test_camera_update_validation_and_persistence(client: TestClient, tmp_path: Path) -> None:
    url = "/api/cameras/AAA%3A0"
    response = await client.post(url, json={"path": "san_sau"})
    assert response.status == 400
    assert (await response.json())["field"] == "path"
    response = await client.post(url, json={"path": "Bad Path"})
    assert (await response.json())["field"] == "path"
    response = await client.post(url, json={"port": "99999"})
    assert (await response.json())["field"] == "port"

    response = await client.post(
        url,
        json={
            "path": "cong",
            "host": "192.168.1.50",
            "auto_host": False,
            "password": "SAFETY1",
            "sub": True,
        },
    )
    assert response.status == 200
    body = await response.json()
    assert body["config"]["path"] == "cong" and "password" not in body["config"]
    saved = json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
    assert saved["cameras"]["AAA:0"]["password"] == "SAFETY1"
    assert saved["cameras"]["AAA:0"]["host"] == "192.168.1.50"

    state = await (await client.get("/api/state")).json()
    camera = next(item for item in state["cameras"] if item["key"] == "AAA:0")
    assert camera["password_known"] is True
    assert [stream["path"] for stream in camera["streams"]] == ["cong", "cong_sub"]
    assert "SAFETY1" not in json.dumps(state)

    response = await client.post("/api/cameras/AAA%3A0/reset", json={})
    assert response.status == 200
    assert (await response.json())["removed"] is False
    saved = json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
    assert saved["cameras"]["AAA:0"]["host"] == ""
    assert saved["cameras"]["AAA:0"]["path"] == "cong_truoc"

    assert (await client.post("/api/cameras/NOPE%3A0", json={})).status == 404


async def test_login_and_captcha_endpoints(client: TestClient) -> None:
    response = await client.post("/api/login", json={"account": "", "password": ""})
    assert response.status == 200
    login = await (await client.get("/api/login")).json()
    assert login["error"] == "missing_fields"
    response = await client.get("/captcha", allow_redirects=False)
    assert response.status == 302
    assert (await client.get("/captcha/image")).status == 404
    response = await client.post("/api/captcha/submit", json={"generation": 5})
    assert response.status == 409
    assert (await response.json())["generation"] == 0
    assert (await client.post("/api/login/cancel", json={})).status == 200
    assert (await client.post("/api/logout", json={})).status == 404
    logs = await (await client.get("/api/logs")).json()
    assert isinstance(logs["lines"], list)


async def test_link_sign_in_again_refresh_and_remove_accounts(
    client: TestClient, tmp_path: Path
) -> None:
    state = await _wait_state(client, _all_ok)
    [first] = state["accounts"]

    response = await client.post("/api/login", json={"account": SECOND, "password": "pw2"})
    assert response.status == 200
    state = await _wait_state(client, lambda state: len(state["accounts"]) == 2 and _all_ok(state))
    assert state["login"]["step"] == "done" and state["login"]["label"] == "se***@example.com"
    assert state["cloud"]["account_count"] == 2 and state["cloud"]["device_count"] == 3
    second = state["accounts"][1]
    assert second["label"] == "se***@example.com" and second["device_count"] == 1
    cameras = {camera["key"]: camera for camera in state["cameras"]}
    assert cameras["CCC:0"]["account_id"] == second["id"]
    assert cameras["AAA:0"]["account_id"] == first["id"]
    assert (tmp_path / f"devices-{second['id']}.json").is_file()
    text = await (await client.get("/api/state")).text()
    assert SECOND not in text and "pw2" not in text

    response = await client.post("/api/login", json={"account_id": first["id"], "password": ""})
    assert response.status == 200
    state = await _wait_state(
        client,
        lambda state: state["login"]["step"] == "done"
        and not state["login"]["busy"]
        and _all_ok(state),
    )
    assert state["login"]["target"] == first["id"] and state["login"]["label"] == first["label"]
    assert [account["id"] for account in state["accounts"]] == [first["id"], second["id"]]

    response = await client.post(f"/api/accounts/{second['id']}/refresh", json={})
    assert response.status == 200
    assert (await response.json())["status"] == "ok"
    for action in ("refresh", "remove"):
        response = await client.post(f"/api/accounts/nope1234/{action}", json={})
        assert response.status == 404
        assert (await response.json())["error"] == "Không tìm thấy tài khoản."
    response = await client.post("/api/login", json={"account_id": "nope1234", "password": ""})
    assert response.status == 404

    response = await client.post(f"/api/accounts/{second['id']}/remove", json={})
    assert response.status == 200
    state = await (await client.get("/api/state")).json()
    assert [account["id"] for account in state["accounts"]] == [first["id"]]
    cameras = {camera["key"]: camera for camera in state["cameras"]}
    assert cameras["CCC:0"]["in_account"] is False and cameras["CCC:0"]["account_id"] == ""
    assert cameras["AAA:0"]["in_account"] is True
    assert not (tmp_path / f"devices-{second['id']}.json").exists()
    saved = json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
    assert "CCC:0" in saved["cameras"]
    assert [entry["id"] for entry in saved["accounts"]] == [first["id"]]
