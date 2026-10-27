"""aiohttp web UI and JSON API."""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import logging
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from aiohttp import web

from . import __version__
from .bridge import Bridge
from .cameras import SUB_SUFFIX, ConfigError, apply_update
from .captcha_page import NO_STORE_HEADERS, decode_image, render_page
from .cloud import (
    BUSY_TEXT,
    NOT_FOUND_TEXT,
    AccountError,
    CloudAccount,
    CloudManager,
    camera_name,
    split_key,
    used_paths,
)
from .login import STEP_CAPTCHA, STEP_DONE
from .streams import camera_credentials, cloud_lan_ip, public_url
from .util import mask_account

_LOGGER = logging.getLogger(__name__)
STATIC_DIR = Path(__file__).with_name("static")
BRIDGE_KEY: web.AppKey[Bridge] = web.AppKey("bridge", Bridge)
_MAX_BODY = 64 * 1024
_PUBLIC_PATHS = {"/healthz"}
_INDEX_CSP = (
    "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)

Handler = Callable[[web.Request], Awaitable[web.StreamResponse]]


def _json(data: Any, status: int = 200) -> web.Response:
    return web.json_response(data, status=status, headers={"Cache-Control": "no-store"})


def _error(message: str, status: int = 400, **extra: Any) -> web.Response:
    return _json({"ok": False, "error": message, **extra}, status)


def _busy() -> web.Response:
    return _error(BUSY_TEXT, 409)


# ------------------------------------------------------------------ middleware


@web.middleware
async def security_middleware(request: web.Request, handler: Handler) -> web.StreamResponse:
    bridge = request.app[BRIDGE_KEY]
    settings = bridge.settings
    if settings.web_password and request.path not in _PUBLIC_PATHS:
        if not _authorized(request, settings.web_username, settings.web_password):
            return web.Response(
                status=401,
                text="Cần đăng nhập",
                headers={"WWW-Authenticate": 'Basic realm="Imou RTSP", charset="UTF-8"'},
            )
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        problem = _csrf_problem(request)
        if problem:
            return _error(problem, 403)
    response = await handler(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.path.startswith("/static/"):
        response.headers.setdefault("Cache-Control", "no-cache")
    return response


def _authorized(request: web.Request, username: str, password: str) -> bool:
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "basic" or not token:
        return False
    try:
        decoded = base64.b64decode(token.strip(), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return False
    user, separator, secret = decoded.partition(":")
    if not separator:
        return False
    user_ok = hmac.compare_digest(user.encode(), username.encode())
    pass_ok = hmac.compare_digest(secret.encode(), password.encode())
    return user_ok and pass_ok


def _csrf_problem(request: web.Request) -> str:
    if request.content_type != "application/json":
        return "Yêu cầu phải là JSON."
    fetch_site = request.headers.get("Sec-Fetch-Site")
    if fetch_site and fetch_site not in ("same-origin", "none"):
        return "Yêu cầu từ trang khác bị từ chối."
    origin = request.headers.get("Origin")
    if origin and origin != "null":
        try:
            origin_host = urlsplit(origin).netloc.lower()
        except ValueError:
            return "Origin không hợp lệ."
        allowed = {request.host.lower()}
        forwarded = request.headers.get("X-Forwarded-Host")
        if forwarded:
            allowed.add(forwarded.split(",")[0].strip().lower())
        if origin_host not in allowed:
            return "Yêu cầu từ trang khác bị từ chối."
    return ""


async def _body(request: web.Request) -> dict[str, Any]:
    if request.content_length is not None and request.content_length > _MAX_BODY:
        raise web.HTTPRequestEntityTooLarge(max_size=_MAX_BODY, actual_size=request.content_length)
    try:
        data = await request.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


# ---------------------------------------------------------------------- pages


async def index(request: web.Request) -> web.StreamResponse:
    return web.FileResponse(
        STATIC_DIR / "index.html",
        headers={
            "Cache-Control": "no-cache",
            "Content-Security-Policy": _INDEX_CSP,
            "X-Frame-Options": "DENY",
        },
    )


async def healthz(request: web.Request) -> web.Response:
    return web.Response(text="ok", headers={"Cache-Control": "no-store"})


async def captcha_page(request: web.Request) -> web.Response:
    cloud = request.app[BRIDGE_KEY].cloud
    assert cloud is not None
    flow = cloud.login
    if flow.step != STEP_CAPTCHA or flow.challenge is None:
        raise web.HTTPFound("./")
    page = render_page(flow.challenge, flow.generation, flow.fingerprint, flow.first_seen)
    return web.Response(text=page, content_type="text/html", headers=NO_STORE_HEADERS)


async def captcha_image(request: web.Request) -> web.Response:
    cloud = request.app[BRIDGE_KEY].cloud
    assert cloud is not None
    challenge = cloud.login.challenge
    if cloud.login.step != STEP_CAPTCHA or challenge is None or not challenge.is_image:
        raise web.HTTPNotFound()
    try:
        image, content_type = decode_image(challenge.image)
    except ValueError:
        raise web.HTTPNotFound() from None
    return web.Response(body=image, content_type=content_type, headers=NO_STORE_HEADERS)


# ------------------------------------------------------------------- state


def _rtsp_host(request: web.Request, bridge: Bridge) -> str:
    return bridge.settings.public_host or request.url.host or "127.0.0.1"


def _login_snapshot(cloud: CloudManager, labels: dict[str, str]) -> dict[str, Any]:
    flow = cloud.login
    label = labels.get(flow.target) or (mask_account(flow.account) if flow.account else "")
    snapshot = {**flow.snapshot(), "label": label}
    if flow.step == STEP_DONE:
        # Only a failed sign-in needs the typed name back; linked accounts stay masked.
        snapshot["account"] = ""
    return snapshot


async def state(request: web.Request) -> web.Response:
    bridge = request.app[BRIDGE_KEY]
    cloud = bridge.cloud
    streams = bridge.streams
    assert cloud is not None and streams is not None
    settings = bridge.settings
    await streams.refresh_runtime()
    host = _rtsp_host(request, bridge)
    labels = cloud.labels()

    cameras: list[dict[str, Any]] = []
    for key, config in bridge.store.cameras.items():
        owner, device, channel = cloud.locate(key)
        device_id, channel_id = split_key(key)
        if device is not None and channel is not None:
            name = camera_name(device, channel)
        else:
            name = config.path or device_id
        raw = device.raw if device is not None else {}
        username, password = camera_credentials(device, config)
        stream_list = []
        for kind, path in config.stream_paths():
            status = streams.stream_status(key, kind)
            stream_list.append(
                {
                    "kind": kind,
                    "path": path,
                    "url": public_url(host, settings.rtsp_port, path),
                    **status,
                }
            )
        cameras.append(
            {
                "key": key,
                "device_id": device_id,
                "channel_id": channel_id,
                "name": name,
                "device_name": device.name if device is not None else "",
                "model": (device.model or "") if device is not None else "",
                "online": device.online if device is not None else None,
                "multi_channel": bool(device is not None and len(device.channels) > 1),
                "in_account": device is not None,
                "account_id": owner.id if owner is not None else "",
                "account": labels.get(owner.id, "") if owner is not None else "",
                "config": config.public_dict(),
                "effective_username": username,
                "password_known": bool(password),
                "cloud_password": bool(str(raw.get("devicePassword") or "").strip()),
                "discovered_ip": bridge.discovered_ip(device_id),
                "cloud_ip": cloud_lan_ip(device),
                "streams": stream_list,
            }
        )
    cameras.sort(key=lambda item: (not item["in_account"], item["name"].casefold(), item["key"]))
    accounts = [
        {
            "id": account.id,
            "label": labels[account.id],
            "status": account.status,
            "message": account.message,
            "updated": account.updated,
            "device_count": len(account.devices),
        }
        for account in cloud.accounts
    ]

    return _json(
        {
            "version": __version__,
            "cloud": {
                "status": cloud.status,
                "message": cloud.message,
                "has_account": bool(cloud.accounts),
                "account_count": len(cloud.accounts),
                "updated": cloud.updated,
                "device_count": len(cloud.devices),
            },
            "accounts": accounts,
            "login": _login_snapshot(cloud, labels),
            "mediamtx": {"state": bridge.mediamtx.state, "message": bridge.mediamtx.message},
            "rtsp": {
                "host": host,
                "port": settings.rtsp_port,
                "auth": bool(settings.rtsp_username),
                "username": settings.rtsp_username,
                "transports": list(settings.rtsp_transports),
                "hls": settings.enable_hls,
                "hls_port": settings.hls_port,
                "webrtc": settings.enable_webrtc,
                "webrtc_port": settings.webrtc_port,
            },
            "discovery": {
                "running": bridge.discovery_running,
                "last": bridge.discovery_last,
                "found": len(bridge.discovered),
                "error": bridge.discovery_error,
            },
            "streams_error": streams.last_error,
            "cameras": cameras,
        }
    )


async def login_state(request: web.Request) -> web.Response:
    cloud = request.app[BRIDGE_KEY].cloud
    assert cloud is not None
    return _json(_login_snapshot(cloud, cloud.labels()))


async def logs(request: web.Request) -> web.Response:
    return _json({"lines": list(request.app[BRIDGE_KEY].logs.lines)})


# ------------------------------------------------------------------ actions


async def login(request: web.Request) -> web.Response:
    """Link a new account, or sign in again with ``account_id`` (empty password = stored)."""
    cloud = request.app[BRIDGE_KEY].cloud
    assert cloud is not None
    data = await _body(request)
    account = str(data.get("account") or "").strip()
    password = data.get("password")
    password = password if isinstance(password, str) else ""
    account_id = data.get("account_id")
    account_id = account_id if isinstance(account_id, str) else ""
    try:
        cloud.begin_login(account, password, account_id or None)
    except AccountError as err:
        return _error(err.message, err.status)
    return _json({"ok": True})


async def login_cancel(request: web.Request) -> web.Response:
    cloud = request.app[BRIDGE_KEY].cloud
    assert cloud is not None
    cloud.login.cancel()
    return _json({"ok": True})


async def otp(request: web.Request) -> web.Response:
    cloud = request.app[BRIDGE_KEY].cloud
    assert cloud is not None
    data = await _body(request)
    started = cloud.login.submit_otp(str(data.get("code") or ""))
    return _json({"ok": True}) if started else _busy()


async def otp_resend(request: web.Request) -> web.Response:
    cloud = request.app[BRIDGE_KEY].cloud
    assert cloud is not None
    return _json({"ok": True}) if cloud.login.resend_otp() else _busy()


async def captcha_submit(request: web.Request) -> web.Response:
    cloud = request.app[BRIDGE_KEY].cloud
    assert cloud is not None
    flow = cloud.login
    data = await _body(request)
    try:
        generation = int(data.get("generation"))
    except (TypeError, ValueError):
        generation = -1
    if flow.step != STEP_CAPTCHA or generation != flow.generation:
        return _error(
            "Phiên CAPTCHA đã thay đổi; trang sẽ tải lại.", 409, generation=flow.generation
        )
    result = {key: value for key, value in data.items() if key != "generation"}
    if not flow.submit_captcha(generation, result):
        return _busy()
    return _json({"ok": True, "generation": flow.generation})


async def captcha_refresh(request: web.Request) -> web.Response:
    cloud = request.app[BRIDGE_KEY].cloud
    assert cloud is not None
    return _json({"ok": True}) if cloud.login.refresh_captcha() else _busy()


async def refresh(request: web.Request) -> web.Response:
    cloud = request.app[BRIDGE_KEY].cloud
    assert cloud is not None
    if not cloud.accounts:
        return _error("Chưa đăng nhập Imou.", 400)
    if not any(account.usable for account in cloud.accounts):
        return _error("Imou yêu cầu đăng nhập lại trước.", 400)
    await cloud.refresh_all()
    return _json({"ok": True, "status": cloud.status, "message": cloud.message})


def _account(request: web.Request) -> CloudAccount:
    cloud = request.app[BRIDGE_KEY].cloud
    assert cloud is not None
    account = cloud.get(request.match_info["account_id"])
    if account is None:
        raise web.HTTPNotFound(
            text=json.dumps({"ok": False, "error": NOT_FOUND_TEXT}, ensure_ascii=False),
            content_type="application/json",
        )
    return account


async def account_refresh(request: web.Request) -> web.Response:
    account = _account(request)
    if not account.usable:
        return _error("Imou yêu cầu đăng nhập lại trước.", 400)
    await account.refresh()
    return _json({"ok": True, "status": account.status, "message": account.message})


async def account_remove(request: web.Request) -> web.Response:
    account = _account(request)
    cloud = request.app[BRIDGE_KEY].cloud
    assert cloud is not None
    await cloud.remove_account(account.id)
    return _json({"ok": True})


async def discover(request: web.Request) -> web.Response:
    bridge = request.app[BRIDGE_KEY]
    found = await bridge.scan_lan()
    return _json({"ok": True, "found": found, "error": bridge.discovery_error})


def _camera_key(request: web.Request) -> str:
    key = request.match_info["key"]
    if key not in request.app[BRIDGE_KEY].store.cameras:
        raise web.HTTPNotFound(
            text='{"ok": false, "error": "Không tìm thấy camera."}',
            content_type="application/json",
        )
    return key


async def camera_update(request: web.Request) -> web.Response:
    bridge = request.app[BRIDGE_KEY]
    key = _camera_key(request)
    data = await _body(request)
    current = bridge.store.cameras[key]
    try:
        updated = apply_update(current, data)
    except ConfigError as err:
        return _error(err.message, 400, field=err.field)
    used = used_paths(bridge.store.cameras, exclude=key)
    if updated.path and (updated.path in used or f"{updated.path}{SUB_SUFFIX}" in used):
        return _error("Tên đường dẫn đã được camera khác dùng.", 400, field="path")
    bridge.store.cameras[key] = updated
    bridge.store.save()
    if updated.auto_host:
        bridge.apply_discovery()
    assert bridge.streams is not None
    bridge.streams.mark_dirty()
    return _json({"ok": True, "config": updated.public_dict()})


async def camera_reset(request: web.Request) -> web.Response:
    bridge = request.app[BRIDGE_KEY]
    key = _camera_key(request)
    del bridge.store.cameras[key]
    assert bridge.cloud is not None and bridge.streams is not None
    if not bridge.cloud.sync_cameras():
        bridge.store.save()
    bridge.apply_discovery()
    bridge.streams.mark_dirty()
    return _json({"ok": True, "removed": key not in bridge.store.cameras})


async def camera_test(request: web.Request) -> web.Response:
    bridge = request.app[BRIDGE_KEY]
    key = _camera_key(request)
    assert bridge.streams is not None
    results = await bridge.streams.test(key)
    return _json({"ok": all(item["ok"] for item in results) and bool(results), "results": results})


# --------------------------------------------------------------------- app


def create_app(bridge: Bridge) -> web.Application:
    app = web.Application(middlewares=[security_middleware], client_max_size=_MAX_BODY)
    app[BRIDGE_KEY] = bridge

    async def on_startup(_: web.Application) -> None:
        await bridge.start()

    async def on_cleanup(_: web.Application) -> None:
        await bridge.stop()

    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    router = app.router
    router.add_get("/", index)
    router.add_get("/healthz", healthz)
    router.add_get("/captcha", captcha_page)
    router.add_get("/captcha/image", captcha_image)
    router.add_get("/api/state", state)
    router.add_get("/api/login", login_state)
    router.add_get("/api/logs", logs)
    router.add_post("/api/login", login)
    router.add_post("/api/login/cancel", login_cancel)
    router.add_post("/api/otp", otp)
    router.add_post("/api/otp/resend", otp_resend)
    router.add_post("/api/captcha/submit", captcha_submit)
    router.add_post("/api/captcha/refresh", captcha_refresh)
    router.add_post("/api/refresh", refresh)
    router.add_post("/api/accounts/{account_id}/refresh", account_refresh)
    router.add_post("/api/accounts/{account_id}/remove", account_remove)
    router.add_post("/api/discover", discover)
    router.add_post("/api/cameras/{key}", camera_update)
    router.add_post("/api/cameras/{key}/reset", camera_reset)
    router.add_post("/api/cameras/{key}/test", camera_test)
    router.add_static("/static/", STATIC_DIR, show_index=False)
    return app
