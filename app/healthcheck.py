"""Docker HEALTHCHECK: ``python -m app.healthcheck`` exits 0 when the web UI answers."""

from __future__ import annotations

import sys
import urllib.request

from .settings import Settings


def main() -> int:
    try:
        settings = Settings.from_env()
    except ValueError:
        return 1
    host = settings.web_host
    if host in ("", "0.0.0.0", "::", "[::]"):
        host = "127.0.0.1"
    elif ":" in host and not host.startswith("["):
        host = f"[{host}]"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(f"http://{host}:{settings.web_port}/healthz", timeout=5) as response:
            return 0 if response.status == 200 else 1
    except OSError:
        return 1


if __name__ == "__main__":
    sys.exit(main())
