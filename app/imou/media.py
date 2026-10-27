"""Helpers for extracting signed media URLs from Imou responses."""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import quote, urlparse, urlsplit

from .const import (
    CONF_LOCAL_CAMERAS,
    CONF_LOCAL_HOST,
    CONF_LOCAL_PASSWORD,
    CONF_LOCAL_USERNAME,
    CONF_ONVIF_PORT,
    CONF_ONVIF_PROFILE,
    CONF_ONVIF_PTZ,
    CONF_RTSP_PATH,
    CONF_RTSP_PORT,
    DEFAULT_ONVIF_PORT,
)

_STREAM_KEY_PRIORITY = (
    "hlsurl",
    "rtspurl",
    "rtmpurl",
    "flvurl",
    "playurl",
    "streamurl",
    "liveurl",
    "tlsresource",
    "resource",
    "url",
    "",
)
_IMAGE_KEY_PARTS = ("snapshot", "thumbnail", "picture", "image", "picurl")
_SUPPORTED_SCHEMES = frozenset(
    {"http", "https", "rtmp", "rtmps", "rtsp", "rtsps"}
)


def _normalized_key(value: Any) -> str:
    return "".join(
        character for character in str(value).casefold() if character.isalnum()
    )


def _decoded_json(value: str) -> Any:
    stripped = value.strip()
    if not stripped.startswith(("{", "[")):
        return None
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return None


def _valid_url(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate or len(candidate) > 16384:
        return None
    parsed = urlparse(candidate)
    if parsed.scheme.casefold() not in _SUPPORTED_SCHEMES or not parsed.netloc:
        return None
    marker = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".casefold()
    if any(part in marker for part in ("rtsv1", "rtsv2", "lchttp")):
        return None
    return candidate


def _walk(value: Any, depth: int = 0) -> Iterable[tuple[str, str]]:
    if depth > 5:
        return
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = _normalized_key(key)
            if url := _valid_url(child):
                yield key_text, url
                continue
            if isinstance(child, str) and (decoded := _decoded_json(child)) is not None:
                yield from _walk(decoded, depth + 1)
            elif isinstance(child, (Mapping, list, tuple)):
                yield from _walk(child, depth + 1)
    elif isinstance(value, (list, tuple)):
        for child in value:
            if url := _valid_url(child):
                yield "", url
            elif isinstance(child, str) and (decoded := _decoded_json(child)) is not None:
                yield from _walk(decoded, depth + 1)
            elif isinstance(child, (Mapping, list, tuple)):
                yield from _walk(child, depth + 1)
    elif url := _valid_url(value):
        yield "", url


def extract_stream(payload: Any) -> tuple[str, str] | None:
    """Return ``(normalized_key, url)`` of the best stream URL in a cloud response."""
    urls = list(_walk(payload))
    for preferred_key in _STREAM_KEY_PRIORITY:
        for key, url in urls:
            if key == preferred_key:
                return key, url
    return None


def extract_stream_url(payload: Any) -> str | None:
    """Return the best HA-compatible stream URL from a cloud response."""
    found = extract_stream(payload)
    return found[1] if found else None


def extract_image_url(payload: Any) -> str | None:
    """Return a URL explicitly identified as an image or snapshot."""
    for key, url in _walk(payload):
        if any(part in key for part in _IMAGE_KEY_PARTS):
            return url
    return None


def local_camera_key(device_id: str, channel_id: str) -> str:
    return json.dumps([str(device_id), str(channel_id)], separators=(",", ":"))


def normalize_local_host(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("invalid_host")
    host = value.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host or len(host) > 253 or any(char in host for char in "/\\@?#%"):
        raise ValueError("invalid_host")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if ":" in host or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
            raise ValueError("invalid_host") from None
        labels = host.rstrip(".").split(".")
        if not all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in labels
        ):
            raise ValueError("invalid_host")
        if all(label.isdigit() for label in labels):
            raise ValueError("invalid_host")
        return host.rstrip(".").lower()
    if address.is_unspecified or address.is_multicast:
        raise ValueError("invalid_host")
    return address.compressed


def normalize_local_camera(value: Mapping[str, Any]) -> dict[str, Any]:
    host = normalize_local_host(value.get(CONF_LOCAL_HOST))
    raw_port = value.get(CONF_RTSP_PORT, 554)
    if isinstance(raw_port, bool) or not re.fullmatch(r"[0-9]{1,5}", str(raw_port)):
        raise ValueError("invalid_port")
    port = int(raw_port)
    if not 1 <= port <= 65535:
        raise ValueError("invalid_port")
    username = value.get(CONF_LOCAL_USERNAME, "")
    password = value.get(CONF_LOCAL_PASSWORD, "")
    if not isinstance(username, str) or not isinstance(password, str):
        raise ValueError("invalid_credentials")
    if len(username) > 256 or len(password) > 1024 or (password and not username):
        raise ValueError("invalid_credentials")
    path = value.get(CONF_RTSP_PATH, "")
    if not isinstance(path, str):
        raise ValueError("invalid_path")
    path = path.strip()
    if not path.startswith("/") or path.startswith("//") or len(path) > 2048:
        raise ValueError("invalid_path")
    if any(ord(char) <= 32 or ord(char) == 127 or char in "#\\" for char in path):
        raise ValueError("invalid_path")
    parts = urlsplit(path)
    if parts.scheme or parts.netloc or parts.fragment:
        raise ValueError("invalid_path")
    raw_onvif_port = value.get(CONF_ONVIF_PORT, DEFAULT_ONVIF_PORT)
    if isinstance(raw_onvif_port, bool) or not re.fullmatch(
        r"[0-9]{1,5}", str(raw_onvif_port)
    ):
        raise ValueError("invalid_onvif_port")
    onvif_port = int(raw_onvif_port)
    if not 1 <= onvif_port <= 65535:
        raise ValueError("invalid_onvif_port")
    onvif_profile = value.get(CONF_ONVIF_PROFILE, "")
    if (
        not isinstance(onvif_profile, str)
        or len(onvif_profile) > 256
        or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in onvif_profile)
    ):
        raise ValueError("invalid_onvif_profile")
    onvif_ptz = value.get(CONF_ONVIF_PTZ, True)
    if isinstance(onvif_ptz, str):
        onvif_ptz = onvif_ptz.strip().casefold() in {"1", "true", "on", "yes"}
    camera = {
        CONF_LOCAL_HOST: host,
        CONF_RTSP_PORT: port,
        CONF_LOCAL_USERNAME: username,
        CONF_LOCAL_PASSWORD: password,
        CONF_RTSP_PATH: path,
        CONF_ONVIF_PORT: onvif_port,
        CONF_ONVIF_PTZ: bool(onvif_ptz),
    }
    if onvif_profile:
        camera[CONF_ONVIF_PROFILE] = onvif_profile
    return camera


def configured_local_cameras(options: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    raw = options.get(CONF_LOCAL_CAMERAS)
    if not isinstance(raw, Mapping):
        return {}
    cameras: dict[str, dict[str, Any]] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not isinstance(value, Mapping):
            continue
        try:
            identity = json.loads(key)
            if not isinstance(identity, list) or len(identity) != 2:
                continue
            if not all(isinstance(item, str) and item for item in identity):
                continue
            camera = normalize_local_camera(value)
        except (ValueError, TypeError):
            continue
        cameras[local_camera_key(*identity)] = camera
    return cameras


def local_rtsp_source(value: Mapping[str, Any]) -> str:
    camera = normalize_local_camera(value)
    host = camera[CONF_LOCAL_HOST]
    if ":" in host:
        host = f"[{host}]"
    username = camera[CONF_LOCAL_USERNAME]
    password = camera[CONF_LOCAL_PASSWORD]
    user_info = ""
    if username:
        user_info = f"{quote(username, safe='')}:{quote(password, safe='')}@"
    return f"rtsp://{user_info}{host}:{camera[CONF_RTSP_PORT]}{camera[CONF_RTSP_PATH]}"
