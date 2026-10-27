"""Runtime settings read from environment variables."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}
_RTSP_TRANSPORTS = ("udp", "multicast", "tcp")
_LOG_LEVELS = ("debug", "info", "warn", "error")


def _text(env: Mapping[str, str], name: str, default: str = "") -> str:
    value = env.get(name)
    return default if value is None else value.strip()


def _int(env: Mapping[str, str], name: str, default: int, low: int, high: int) -> int:
    raw = _text(env, name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer") from None
    if not low <= value <= high:
        raise ValueError(f"{name} must be between {low} and {high}")
    return value


def _bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = _text(env, name).lower()
    if not raw:
        return default
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    raise ValueError(f"{name} must be true or false")


def _port(env: Mapping[str, str], name: str, default: int) -> int:
    return _int(env, name, default, 1, 65535)


@dataclass(frozen=True, slots=True)
class Settings:
    """All tunables of the bridge."""

    data_dir: Path
    web_host: str
    web_port: int
    web_username: str
    web_password: str
    public_host: str
    rtsp_port: int
    rtp_port: int
    rtcp_port: int
    rtsp_transports: tuple[str, ...]
    rtsp_username: str
    rtsp_password: str
    enable_hls: bool
    hls_port: int
    enable_webrtc: bool
    webrtc_port: int
    webrtc_udp_port: int
    mediamtx_bin: str
    mediamtx_api_port: int
    mediamtx_log_level: str
    refresh_interval: int
    lan_scan_interval: int
    p2p_idle_timeout: int
    cloud_url_ttl: int
    language: str
    log_level: str

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if env is None else env
        transports = tuple(
            dict.fromkeys(
                item.strip().lower()
                for item in _text(env, "RTSP_TRANSPORTS", "udp,tcp").split(",")
                if item.strip()
            )
        )
        if not transports or any(item not in _RTSP_TRANSPORTS for item in transports):
            raise ValueError("RTSP_TRANSPORTS accepts udp, multicast, tcp")
        mediamtx_log_level = _text(env, "MEDIAMTX_LOG_LEVEL", "info").lower()
        if mediamtx_log_level not in _LOG_LEVELS:
            raise ValueError("MEDIAMTX_LOG_LEVEL accepts debug, info, warn, error")
        rtsp_username = _text(env, "RTSP_USERNAME")
        rtsp_password = env.get("RTSP_PASSWORD", "")
        if bool(rtsp_username) != bool(rtsp_password):
            raise ValueError("RTSP_USERNAME and RTSP_PASSWORD must be set together")
        if rtsp_username.lower() == "any":
            raise ValueError("RTSP_USERNAME cannot be 'any'")
        web_password = env.get("WEB_PASSWORD", "")
        return cls(
            data_dir=Path(_text(env, "DATA_DIR", "/data")),
            web_host=_text(env, "WEB_HOST", "0.0.0.0"),
            web_port=_port(env, "WEB_PORT", 8090),
            web_username=_text(env, "WEB_USERNAME", "admin") or "admin",
            web_password=web_password,
            public_host=_text(env, "PUBLIC_HOST"),
            rtsp_port=_port(env, "RTSP_PORT", 8554),
            rtp_port=_port(env, "RTP_PORT", 8000),
            rtcp_port=_port(env, "RTCP_PORT", 8001),
            rtsp_transports=transports,
            rtsp_username=rtsp_username,
            rtsp_password=rtsp_password,
            enable_hls=_bool(env, "ENABLE_HLS", False),
            hls_port=_port(env, "HLS_PORT", 8888),
            enable_webrtc=_bool(env, "ENABLE_WEBRTC", False),
            webrtc_port=_port(env, "WEBRTC_PORT", 8889),
            webrtc_udp_port=_port(env, "WEBRTC_UDP_PORT", 8189),
            mediamtx_bin=_text(env, "MEDIAMTX_BIN", "/usr/local/bin/mediamtx"),
            mediamtx_api_port=_port(env, "MEDIAMTX_API_PORT", 9997),
            mediamtx_log_level=mediamtx_log_level,
            refresh_interval=_int(env, "REFRESH_INTERVAL", 600, 60, 86400),
            lan_scan_interval=_int(env, "LAN_SCAN_INTERVAL", 900, 0, 86400),
            p2p_idle_timeout=_int(env, "P2P_IDLE_TIMEOUT", 60, 5, 3600),
            cloud_url_ttl=_int(env, "CLOUD_URL_TTL", 600, 30, 86400),
            language=_text(env, "IMOU_LANGUAGE", "en_US") or "en_US",
            log_level=_text(env, "LOG_LEVEL", "info").lower() or "info",
        )
