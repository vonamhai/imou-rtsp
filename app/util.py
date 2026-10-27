"""Small helpers shared by the bridge modules."""

from __future__ import annotations

import logging
import re
import time
import unicodedata
from collections import deque
from urllib.parse import urlsplit, urlunsplit

_SLUG_RE = re.compile(r"[^a-z0-9]+")
_URL_USERINFO_RE = re.compile(r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\s]+@")


def slugify(text: str, fallback: str = "camera", limit: int = 48) -> str:
    """Return an ASCII path name such as ``cong_truoc`` from ``Cổng trước``."""
    normalized = unicodedata.normalize("NFKD", text.replace("đ", "d").replace("Đ", "D"))
    ascii_text = normalized.encode("ascii", "ignore").decode("ascii").lower()
    slug = _SLUG_RE.sub("_", ascii_text).strip("_")[:limit].strip("_")
    return slug or fallback


def redact_url(value: str) -> str:
    """Hide credentials embedded in URLs inside arbitrary text."""
    return _URL_USERINFO_RE.sub(r"\g<scheme>***@", value)


def redact_query(url: str) -> str:
    """Hide credentials and signed query strings of a media URL."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<url>"
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    if parts.username:
        host = f"***@{host}"
    query = "***" if parts.query else ""
    return urlunsplit((parts.scheme, host, parts.path, query, ""))


def mask_account(account: str) -> str:
    """Return a recognisable but non-identifying account label."""
    account = account.strip()
    if "@" in account:
        name, _, domain = account.partition("@")
        visible = name[:2] if len(name) > 2 else name[:1]
        return f"{visible}***@{domain}"
    if len(account) <= 4:
        return "***"
    return f"{account[:3]}***{account[-2:]}"


class LogBuffer(logging.Handler):
    """Keep the most recent log lines in memory for the web UI."""

    def __init__(self, capacity: int = 600) -> None:
        super().__init__()
        self.lines: deque[str] = deque(maxlen=capacity)
        self.setFormatter(logging.Formatter("%(levelname)s [%(name)s] %(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = redact_url(self.format(record))
        except Exception:  # noqa: BLE001 - logging must never raise
            return
        self.append(message)

    def append(self, message: str) -> None:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.lines.append(f"{stamp} {message}")
