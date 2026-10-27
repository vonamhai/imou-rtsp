from __future__ import annotations

import asyncio
import socket
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.imou.api import ImouApiError
from app.imou.models import ImouDevice, device_from_api
from app.settings import Settings


def make_settings(data_dir: Path, **env: str) -> Settings:
    values = {"DATA_DIR": str(data_dir), "LAN_SCAN_INTERVAL": "0"}
    values.update(env)
    return Settings.from_env(values)


def make_device(**raw: Any) -> ImouDevice:
    values: dict[str, Any] = {
        "deviceId": "AAA111",
        "productId": "P1",
        "name": "Cổng trước",
        "status": "online",
    }
    values.update(raw)
    device = device_from_api(values)
    assert device is not None
    return device


def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class FakeImou:
    """Stands in for ImouApiClient: signs in at once and lists scripted devices."""

    def __init__(
        self,
        account: str,
        password: str,
        terminal_id: str,
        devices: dict[str, list[dict[str, Any]]],
        auth_errors: dict[str, list[BaseException]],
    ) -> None:
        self.account = account
        self.password = password
        self.terminal_id = terminal_id
        self._devices = devices
        self._auth_errors = auth_errors
        self.list_error: BaseException | None = None
        self.list_gate: asyncio.Event | None = None
        self.list_calls = 0

    async def async_authenticate(self, **kwargs: Any) -> None:
        errors = self._auth_errors.get(self.account)
        if errors:
            raise errors.pop(0)

    async def async_request_two_step_code(self) -> dict[str, Any]:
        return {}

    async def async_list_devices(self) -> list[ImouDevice]:
        self.list_calls += 1
        if self.list_gate is not None:
            await self.list_gate.wait()
        if self.list_error is not None:
            raise self.list_error
        raws = self._devices.get(self.account, [])
        return [device for raw in raws if (device := device_from_api(raw)) is not None]

    async def async_get_live_url(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        raise ImouApiError("no live URLs in tests")

    def live_diagnostic(self, *args: Any) -> str:
        return "test"


def fake_imou_factory(
    devices: dict[str, list[dict[str, Any]]] | None = None,
    auth_errors: dict[str, list[BaseException]] | None = None,
) -> tuple[Callable[..., FakeImou], list[FakeImou]]:
    """A client factory for CloudManager/Bridge and the clients it has built."""
    made: list[FakeImou] = []
    device_map = devices if devices is not None else {}
    error_map = auth_errors if auth_errors is not None else {}

    def factory(
        session: Any, account: str, password: str, terminal_id: str, **kwargs: Any
    ) -> FakeImou:
        client = FakeImou(account, password, terminal_id, device_map, error_map)
        made.append(client)
        return client

    return factory, made


async def settle(flow: Any) -> None:
    """Wait until a LoginFlow has finished its current step."""
    for _ in range(300):
        if not flow.busy:
            return
        await asyncio.sleep(0.01)
    raise AssertionError("login flow did not settle")
