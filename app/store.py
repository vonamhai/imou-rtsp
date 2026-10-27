"""Atomic JSON persistence inside DATA_DIR."""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any
from uuid import uuid4

from .cameras import CameraConfig

_LOGGER = logging.getLogger(__name__)
CONFIG_VERSION = 2
_ACCOUNT_ID_RE = re.compile(r"[a-z0-9]{4,32}")


def atomic_write(path: Path, text: str, *, private: bool = True) -> None:
    """Write a file so readers never observe partial content."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        if private:
            with suppress(OSError):
                os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
    except BaseException:
        with suppress(OSError):
            os.unlink(tmp_name)
        raise


def _read_json(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    try:
        return json.loads(text)
    except ValueError:
        backup = path.with_name(f"{path.name}.corrupt-{int(time.time())}")
        with suppress(OSError):
            path.replace(backup)
        _LOGGER.error("%s is not valid JSON; moved it to %s", path.name, backup.name)
        return None


def _valid_terminal_id(value: Any) -> bool:
    return isinstance(value, str) and 16 <= len(value) <= 64


def _credentials(value: Any) -> tuple[str, str] | None:
    if (
        isinstance(value, Mapping)
        and isinstance(value.get("account"), str)
        and isinstance(value.get("password"), str)
        and value["account"].strip()
    ):
        return value["account"], value["password"]
    return None


def migrated_account_id(terminal_id: str) -> str:
    """Id given to the account of a version 1 config (the same on every retry)."""
    return sha256(f"account:{terminal_id}".encode()).hexdigest()[:8]


@dataclass(slots=True)
class AccountRecord:
    """One linked Imou Life account; the password is stored in clear text."""

    id: str
    account: str
    password: str
    terminal_id: str

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "account": self.account,
            "password": self.password,
            "terminal_id": self.terminal_id,
        }


class Store:
    """Imou accounts, terminal ids and camera settings in ``config.json``.

    Each account keeps its cached device list in ``devices-<id>.json``.
    """

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.config_path = data_dir / "config.json"
        self.legacy_devices_path = data_dir / "devices.json"
        self.terminal_id = ""
        self.accounts: list[AccountRecord] = []
        self.cameras: dict[str, CameraConfig] = {}

    def load(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        data = _read_json(self.config_path)
        if not isinstance(data, Mapping):
            data = {}
        terminal_id = data.get("terminal_id")
        self.terminal_id = terminal_id if _valid_terminal_id(terminal_id) else uuid4().hex
        dirty = (
            not self.config_path.exists()
            or terminal_id != self.terminal_id
            or data.get("version") != CONFIG_VERSION
        )
        self.accounts = []
        entries = data.get("accounts")
        if isinstance(entries, list):
            for entry in entries:
                credentials = _credentials(entry)
                if credentials is None:
                    dirty = True
                    continue
                account_id = entry.get("id")
                if (
                    not isinstance(account_id, str)
                    or not _ACCOUNT_ID_RE.fullmatch(account_id)
                    or self.get_account(account_id) is not None
                ):
                    account_id = self._new_account_id()
                    dirty = True
                account_terminal = entry.get("terminal_id")
                if not _valid_terminal_id(account_terminal):
                    account_terminal = uuid4().hex
                    dirty = True
                self.accounts.append(AccountRecord(account_id, *credentials, account_terminal))
        else:
            credentials = _credentials(data.get("account"))
            if credentials is not None:
                # Version 1 had one account signed in with the shared terminal id;
                # keeping that id spares the user a new CAPTCHA/OTP.
                record = AccountRecord(
                    migrated_account_id(self.terminal_id), *credentials, self.terminal_id
                )
                self.accounts.append(record)
                self._adopt_legacy_devices(record.id)
                _LOGGER.info("Moved the saved Imou account to the multi-account format")
        cameras = data.get("cameras")
        self.cameras = {}
        if isinstance(cameras, Mapping):
            for key, value in cameras.items():
                if isinstance(key, str) and isinstance(value, Mapping):
                    self.cameras[key] = CameraConfig.from_dict(value)
        if dirty:
            self.save()

    def save(self) -> None:
        payload = {
            "version": CONFIG_VERSION,
            "terminal_id": self.terminal_id,
            "accounts": [record.to_dict() for record in self.accounts],
            "cameras": {key: config.to_dict() for key, config in sorted(self.cameras.items())},
        }
        atomic_write(self.config_path, json.dumps(payload, ensure_ascii=False, indent=2))

    # ------------------------------------------------------------- accounts

    def get_account(self, account_id: str) -> AccountRecord | None:
        return next((record for record in self.accounts if record.id == account_id), None)

    def add_account(self, account: str, password: str, terminal_id: str) -> AccountRecord:
        record = AccountRecord(self._new_account_id(), account, password, terminal_id)
        self.accounts.append(record)
        self.save()
        return record

    def update_account(
        self, account_id: str, account: str, password: str, terminal_id: str | None = None
    ) -> None:
        record = self.get_account(account_id)
        if record is None:
            raise KeyError(account_id)
        record.account = account
        record.password = password
        if terminal_id:
            record.terminal_id = terminal_id
        self.save()

    def remove_account(self, account_id: str) -> bool:
        """Forget an account and its cached device list (camera settings stay)."""
        record = self.get_account(account_id)
        if record is None:
            return False
        self.accounts.remove(record)
        self.save()
        self.clear_devices(account_id)
        return True

    def unused_terminal_id(self) -> str:
        """Terminal id for a new account: Imou authorizes each account separately."""
        if any(record.terminal_id == self.terminal_id for record in self.accounts):
            return uuid4().hex
        return self.terminal_id

    def _new_account_id(self) -> str:
        while True:
            candidate = uuid4().hex[:8]
            if self.get_account(candidate) is None:
                return candidate

    def _adopt_legacy_devices(self, account_id: str) -> None:
        target = self.devices_path(account_id)
        if target.exists() or not self.legacy_devices_path.exists():
            return
        try:
            self.legacy_devices_path.replace(target)
        except OSError as err:
            _LOGGER.warning("Could not move devices.json to %s: %s", target.name, err)

    # -------------------------------------------------------------- devices

    def devices_path(self, account_id: str) -> Path:
        if not _ACCOUNT_ID_RE.fullmatch(account_id):
            raise ValueError("Invalid account id")
        return self.data_dir / f"devices-{account_id}.json"

    def load_devices(self, account_id: str) -> list[dict[str, Any]]:
        data = _read_json(self.devices_path(account_id))
        if not isinstance(data, Mapping) or not isinstance(data.get("devices"), list):
            return []
        return [dict(item) for item in data["devices"] if isinstance(item, Mapping)]

    def save_devices(self, account_id: str, raws: list[Mapping[str, Any]]) -> None:
        payload = {"saved_at": int(time.time()), "devices": [dict(raw) for raw in raws]}
        atomic_write(
            self.devices_path(account_id),
            json.dumps(payload, ensure_ascii=False, default=str, indent=1),
        )

    def clear_devices(self, account_id: str) -> None:
        with suppress(FileNotFoundError):
            self.devices_path(account_id).unlink()
