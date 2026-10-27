"""Per-camera stream configuration and its validation."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass, fields, replace
from typing import Any
from urllib.parse import urlsplit

from .imou.media import normalize_local_host

MODES = ("lan", "p2p", "cloud", "custom")
RTSP_TRANSPORTS = ("tcp", "udp", "automatic")
CUSTOM_SCHEMES = ("rtsp", "rtsps", "rtmp", "rtmps", "http", "https", "srt", "whep", "wheps")
PATH_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
SUB_SUFFIX = "_sub"


class ConfigError(ValueError):
    """A user supplied camera setting is invalid."""

    def __init__(self, field_name: str, message: str) -> None:
        super().__init__(message)
        self.field = field_name
        self.message = message


@dataclass(slots=True)
class CameraConfig:
    """How one Imou channel is published by MediaMTX."""

    enabled: bool = False
    path: str = ""
    mode: str = "lan"
    host: str = ""
    auto_host: bool = True
    port: int = 554
    username: str = ""
    password: str = ""
    channel: int = 0
    main: bool = True
    sub: bool = False
    on_demand: bool = True
    rtsp_transport: str = "tcp"
    custom_url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def public_dict(self) -> dict[str, Any]:
        """Return the config without secrets for the web UI."""
        data = asdict(self)
        data.pop("password")
        data["password_set"] = bool(self.password)
        data["custom_url"] = self.custom_url
        return data

    def stream_paths(self) -> list[tuple[str, str]]:
        """Return ``(kind, path)`` pairs published for this camera."""
        if not self.enabled or not self.path:
            return []
        result: list[tuple[str, str]] = []
        if self.main or self.mode == "custom":
            result.append(("main", self.path))
        if self.sub and self.mode != "custom":
            result.append(("sub", f"{self.path}{SUB_SUFFIX}"))
        return result

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CameraConfig:
        """Leniently load a stored config, falling back to defaults."""
        config = cls()
        for item in fields(cls):
            if item.name not in data:
                continue
            value = data[item.name]
            default = getattr(config, item.name)
            if isinstance(default, bool):
                if isinstance(value, bool):
                    setattr(config, item.name, value)
            elif isinstance(default, int):
                if isinstance(value, int) and not isinstance(value, bool):
                    setattr(config, item.name, value)
            elif isinstance(value, str):
                setattr(config, item.name, value)
        if config.mode not in MODES:
            config.mode = "lan"
        if config.rtsp_transport not in RTSP_TRANSPORTS:
            config.rtsp_transport = "tcp"
        if not 1 <= config.port <= 65535:
            config.port = 554
        if not 0 <= config.channel <= 256:
            config.channel = 0
        if config.path and not PATH_RE.fullmatch(config.path):
            config.path = ""
        return config


def _bool_value(payload: Mapping[str, Any], name: str, current: bool) -> bool:
    if name not in payload:
        return current
    value = payload[name]
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in {"true", "1", "on", "yes"}:
        return True
    if isinstance(value, str) and value.lower() in {"false", "0", "off", "no", ""}:
        return False
    raise ConfigError(name, "Giá trị bật/tắt không hợp lệ.")


def _int_value(
    payload: Mapping[str, Any], name: str, current: int, low: int, high: int
) -> int:
    if name not in payload:
        return current
    value = payload[name]
    if isinstance(value, bool):
        raise ConfigError(name, "Giá trị số không hợp lệ.")
    if isinstance(value, str):
        value = value.strip()
        if not value.isdigit():
            raise ConfigError(name, "Giá trị số không hợp lệ.")
        value = int(value)
    if not isinstance(value, int) or not low <= value <= high:
        raise ConfigError(name, f"Giá trị phải từ {low} đến {high}.")
    return value


def _text_value(
    payload: Mapping[str, Any], name: str, current: str, limit: int
) -> str:
    if name not in payload or payload[name] is None:
        return current
    value = payload[name]
    if not isinstance(value, str):
        raise ConfigError(name, "Giá trị chữ không hợp lệ.")
    value = value.strip()
    if len(value) > limit or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ConfigError(name, "Giá trị chứa ký tự không hợp lệ hoặc quá dài.")
    return value


def validate_custom_url(value: str) -> str:
    if not value:
        raise ConfigError("custom_url", "Hãy nhập URL nguồn.")
    if len(value) > 2048 or any(ord(char) <= 32 or ord(char) == 127 for char in value):
        raise ConfigError("custom_url", "URL không hợp lệ.")
    try:
        parts = urlsplit(value)
    except ValueError:
        raise ConfigError("custom_url", "URL không hợp lệ.") from None
    if parts.scheme.lower() not in CUSTOM_SCHEMES or not parts.netloc:
        raise ConfigError(
            "custom_url",
            "Chỉ hỗ trợ rtsp://, rtsps://, rtmp://, http(s)://...m3u8, srt://, whep(s)://.",
        )
    return value


def apply_update(current: CameraConfig, payload: Mapping[str, Any]) -> CameraConfig:
    """Validate a partial update coming from the web UI."""
    updated = replace(current)
    updated.enabled = _bool_value(payload, "enabled", current.enabled)
    updated.auto_host = _bool_value(payload, "auto_host", current.auto_host)
    updated.main = _bool_value(payload, "main", current.main)
    updated.sub = _bool_value(payload, "sub", current.sub)
    updated.on_demand = _bool_value(payload, "on_demand", current.on_demand)
    updated.port = _int_value(payload, "port", current.port, 1, 65535)
    updated.channel = _int_value(payload, "channel", current.channel, 0, 256)

    mode = _text_value(payload, "mode", current.mode, 16).lower()
    if mode not in MODES:
        raise ConfigError("mode", "Chế độ không hợp lệ.")
    updated.mode = mode

    transport = _text_value(payload, "rtsp_transport", current.rtsp_transport, 16).lower()
    if transport not in RTSP_TRANSPORTS:
        raise ConfigError("rtsp_transport", "Giao thức RTSP không hợp lệ.")
    updated.rtsp_transport = transport

    path = _text_value(payload, "path", current.path, 64).lower()
    if path and not PATH_RE.fullmatch(path):
        raise ConfigError(
            "path", "Tên đường dẫn chỉ gồm a-z, 0-9, '_' hoặc '-' (tối đa 64 ký tự)."
        )
    updated.path = path

    host = _text_value(payload, "host", current.host, 253)
    if host:
        try:
            host = normalize_local_host(host)
        except ValueError:
            raise ConfigError("host", "Địa chỉ IP/hostname không hợp lệ.") from None
    updated.host = host

    updated.username = _text_value(payload, "username", current.username, 128)
    if payload.get("password_clear") is True:
        updated.password = ""
    elif isinstance(payload.get("password"), str) and payload["password"] != "":
        password = payload["password"]
        if len(password) > 256 or any(ord(char) < 32 or ord(char) == 127 for char in password):
            raise ConfigError("password", "Mật khẩu chứa ký tự không hợp lệ hoặc quá dài.")
        updated.password = password

    custom_url = _text_value(payload, "custom_url", current.custom_url, 2048)
    if custom_url:
        custom_url = validate_custom_url(custom_url)
    updated.custom_url = custom_url

    if updated.enabled:
        if not updated.path:
            raise ConfigError("path", "Hãy đặt tên đường dẫn RTSP.")
        if updated.mode == "custom" and not updated.custom_url:
            raise ConfigError("custom_url", "Hãy nhập URL nguồn.")
        if updated.mode != "custom" and not (updated.main or updated.sub):
            raise ConfigError("main", "Chọn ít nhất một luồng (chính hoặc phụ).")
    return updated
