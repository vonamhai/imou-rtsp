"""Entry point: ``python -m app``."""

from __future__ import annotations

import logging
import sys

from aiohttp import web

from . import __version__
from .bridge import Bridge
from .mediamtx import default_data_dir_ok
from .settings import Settings
from .util import LogBuffer, redact_url
from .web import create_app

_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warn": logging.WARNING,
    "warning": logging.WARNING,
    "error": logging.ERROR,
}


class RedactingFormatter(logging.Formatter):
    """Never print credentials embedded in URLs."""

    def format(self, record: logging.LogRecord) -> str:
        return redact_url(super().format(record))


def setup_logging(level_name: str) -> LogBuffer:
    root = logging.getLogger()
    root.setLevel(_LEVELS.get(level_name, logging.INFO))
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(
        RedactingFormatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    )
    root.addHandler(console)
    buffer = LogBuffer()
    root.addHandler(buffer)
    logging.getLogger("aiohttp.access").setLevel(logging.WARNING)
    return buffer


def main() -> int:
    try:
        settings = Settings.from_env()
    except ValueError as err:
        print(f"Cấu hình không hợp lệ: {err}", file=sys.stderr)
        return 2
    logs = setup_logging(settings.log_level)
    logger = logging.getLogger("app")
    if not default_data_dir_ok(settings.data_dir):
        logger.error(
            "DATA_DIR %s is not writable; mount a writable folder at this path",
            settings.data_dir,
        )
        return 2
    if not settings.web_password:
        logger.warning("WEB_PASSWORD is not set: anyone on the LAN can open the web UI")
    if not settings.rtsp_username:
        logger.warning("RTSP_USERNAME is not set: RTSP links can be watched without a password")
    logger.info("Imou RTSP bridge %s", __version__)
    bridge = Bridge(settings, logs)
    web.run_app(
        create_app(bridge),
        host=settings.web_host,
        port=settings.web_port,
        access_log=None,
        print=None,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
