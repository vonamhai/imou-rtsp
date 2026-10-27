from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest


@pytest.fixture
def mediamtx_bin() -> str:
    candidate = os.environ.get("MEDIAMTX_BIN") or shutil.which("mediamtx") or ""
    if not candidate or not Path(candidate).is_file():
        pytest.skip("MediaMTX binary not available (set MEDIAMTX_BIN)")
    return candidate
