"""Imou cloud accounts: device lists, camera bookkeeping and live URLs."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import Counter
from collections.abc import Awaitable, Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from typing import Any

from .cameras import SUB_SUFFIX, CameraConfig
from .imou.api import (
    ImouApiClient,
    ImouApiError,
    ImouAuthError,
    ImouConnectionError,
    normalize_login_account,
)
from .imou.media import extract_stream
from .imou.models import ImouChannel, ImouDevice, device_from_api
from .login import STEP_CAPTCHA, STEP_OTP, LoginFlow
from .settings import Settings
from .store import AccountRecord, Store
from .util import mask_account, slugify

_LOGGER = logging.getLogger(__name__)

STATUS_NOT_CONFIGURED = "not_configured"
STATUS_CONNECTING = "connecting"
STATUS_OK = "ok"
STATUS_NEEDS_LOGIN = "needs_login"
STATUS_ERROR = "error"

# Most urgent first: the summary of several accounts shows the worst state.
_STATUS_ORDER = (STATUS_NEEDS_LOGIN, STATUS_ERROR, STATUS_CONNECTING, STATUS_OK)

MAX_ACCOUNTS = 20
BUSY_TEXT = "Đang xử lý yêu cầu đăng nhập trước, hãy chờ."
PENDING_TEXT = "Đang có phiên đăng nhập chờ xác minh; hãy hoàn tất hoặc bấm Hủy trước."
NOT_FOUND_TEXT = "Không tìm thấy tài khoản."
RELOGIN_TEXT = "Imou yêu cầu đăng nhập lại (CAPTCHA/mã xác minh hoặc mật khẩu đã đổi)."

_TLS_STREAM_KEYS = frozenset({"tlsresource", "ipv6tlsresource"})

ChangeCallback = Callable[[], Awaitable[None] | None]


class SourceError(Exception):
    """A stream source cannot be built; ``message`` is shown in the UI."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class AccountError(Exception):
    """An account action was refused; ``message`` is shown in the UI."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


@dataclass(frozen=True, slots=True)
class CloudStream:
    """One live URL handed out by Imou (``url`` is secret: it is signed)."""

    url: str
    tls: bool = False
    key: str = ""

    @property
    def is_rtsp(self) -> bool:
        return self.url.lower().startswith(("rtsp://", "rtsps://"))


def camera_key(device_id: str, channel_id: str) -> str:
    return f"{device_id}:{channel_id}"


def split_key(key: str) -> tuple[str, str]:
    device_id, _, channel_id = key.rpartition(":")
    return device_id, channel_id


def camera_name(device: ImouDevice, channel: ImouChannel) -> str:
    if len(device.channels) <= 1:
        return device.name
    name = (channel.name or "").strip()
    if not name or name == device.name:
        return f"{device.name} {channel.channel_id}"
    return name


def unique_path(base: str, used: set[str]) -> str:
    """Return ``base`` or ``base_2``… so neither it nor its ``_sub`` is taken."""
    base = base[:48].strip("_-") or "camera"
    candidate = base
    index = 2
    while candidate in used or f"{candidate}{SUB_SUFFIX}" in used:
        candidate = f"{base}_{index}"
        index += 1
    return candidate


def used_paths(cameras: Mapping[str, CameraConfig], exclude: str | None = None) -> set[str]:
    used: set[str] = set()
    for key, config in cameras.items():
        if key == exclude or not config.path:
            continue
        used.add(config.path)
        used.add(f"{config.path}{SUB_SUFFIX}")
    return used


def account_identity(account: str) -> str:
    """Compare accounts the way Imou does (``+84912…`` is ``0912…``; e-mail ignores case)."""
    normalized, area_code = normalize_login_account(account)
    return f"{area_code}:{normalized.casefold()}"


def _is_owner(device: ImouDevice) -> bool:
    return str(device.raw.get("role") or "").casefold() == "owner"


def _channel(device: ImouDevice, channel_id: str) -> ImouChannel | None:
    return next((item for item in device.channels if item.channel_id == channel_id), None)


class CloudAccount:
    """One linked Imou Life account: its client, state and cached device list."""

    def __init__(self, manager: CloudManager, record: AccountRecord) -> None:
        self.manager = manager
        self.record = record
        self.status = STATUS_CONNECTING
        self.message = ""
        self.updated: float | None = None
        self.client: ImouApiClient | None = None
        self.devices: dict[str, ImouDevice] = {}
        self._lock = asyncio.Lock()
        for raw in manager.store.load_devices(record.id):
            device = device_from_api(raw)
            if device is not None:
                self.devices[device.device_id] = device

    @property
    def id(self) -> str:
        return self.record.id

    @property
    def label(self) -> str:
        return mask_account(self.record.account)

    @property
    def usable(self) -> bool:
        return self.client is not None and self.status != STATUS_NEEDS_LOGIN

    def connect(self, client: ImouApiClient | None = None) -> None:
        """Use ``client`` from a fresh sign-in, or build one from the stored password."""
        if client is None and self.record.password:
            client = self.manager.make_client(self.record)
        self.client = client
        if client is None:
            self.status = STATUS_NEEDS_LOGIN
            self.message = "Chưa có mật khẩu; hãy đăng nhập lại."
        else:
            self.status = STATUS_CONNECTING
            self.message = ""

    def disconnect(self) -> None:
        """Drop the client so in-flight requests of a removed account are ignored."""
        self.client = None
        self.status = STATUS_NOT_CONFIGURED
        self.message = ""

    def _needs_login(self, err: ImouApiError) -> None:
        self.status = STATUS_NEEDS_LOGIN
        self.message = RELOGIN_TEXT
        _LOGGER.warning(
            "Imou account %s needs a new sign-in: %s", self.label, type(err).__name__
        )

    async def refresh(self) -> None:
        async with self._lock:
            client = self.client
            if client is None:
                return
            try:
                devices = await client.async_list_devices()
            except ImouAuthError as err:
                if client is self.client:
                    self._needs_login(err)
                return
            except ImouConnectionError as err:
                if client is self.client:
                    self.status = STATUS_ERROR
                    self.message = f"Không kết nối được Imou cloud: {err}"
                    _LOGGER.warning("Imou cloud unreachable for %s: %s", self.label, err)
                return
            except ImouApiError as err:
                if client is self.client:
                    self.status = STATUS_ERROR
                    self.message = f"Imou trả về lỗi khi lấy danh sách thiết bị: {err}"
                    _LOGGER.warning("Imou device list failed for %s: %s", self.label, err)
                return
            if client is not self.client:
                return
            if not devices and self.devices:
                self.status = STATUS_OK
                self.message = "Imou trả về danh sách rỗng; tạm giữ danh sách cũ."
                self.updated = time.time()
                return
            self.devices = {device.device_id: device for device in devices}
            try:
                self.manager.store.save_devices(
                    self.id, [dict(device.raw) for device in devices]
                )
            except OSError as err:
                _LOGGER.error("Could not cache the device list: %s", err)
            added = self.manager.sync_cameras()
            self.status = STATUS_OK
            self.message = ""
            self.updated = time.time()
            _LOGGER.info(
                "Imou account %s has %s device(s); %s new camera(s)",
                self.label,
                len(devices),
                added,
            )
        await self.manager.notify()

    async def live_stream(
        self,
        device: ImouDevice,
        channel: ImouChannel,
        *,
        sub: bool,
        fresh: bool = False,
    ) -> CloudStream:
        """Ask Imou for a live URL; ``fresh`` bypasses the short API cache."""
        client = self.client
        if client is None:
            raise SourceError("Chế độ cloud cần đăng nhập Imou.")
        if self.status == STATUS_NEEDS_LOGIN:
            raise SourceError("Imou yêu cầu đăng nhập lại trước khi lấy luồng cloud.")
        product_id = channel.product_id or device.product_id
        stream_id = "1" if sub else "0"
        try:
            payload = await client.async_get_live_url(
                product_id,
                device.device_id,
                channel.channel_id,
                stream_id=stream_id,
                use_cache=not fresh,
            )
        except ImouAuthError as err:
            if client is self.client:
                self._needs_login(err)
            raise SourceError("Imou yêu cầu đăng nhập lại.") from err
        except ImouApiError as err:
            diagnostic = client.live_diagnostic(
                product_id, device.device_id, channel.channel_id, stream_id
            )
            if diagnostic == "private_transport":
                raise SourceError(
                    "Imou chỉ trả về luồng mã hóa riêng (private transport); "
                    "hãy dùng chế độ LAN hoặc P2P."
                ) from err
            raise SourceError(f"Imou không cấp link xem trực tiếp ({diagnostic}).") from err
        found = extract_stream(payload)
        if not found:
            raise SourceError("Imou không trả về link xem trực tiếp có thể dùng.")
        key, url = found
        lowered = url.lower()
        if lowered.startswith(("http://", "https://")) and ".m3u8" not in lowered:
            raise SourceError("Link cloud không phải HLS (.m3u8); MediaMTX không đọc được.")
        if not lowered.startswith(("rtsp://", "rtsps://", "rtmp://", "rtmps://", "http://", "https://")):
            raise SourceError("Link cloud dùng giao thức MediaMTX không hỗ trợ.")
        # Imou's *TlsResource URLs say rtsp:// but the relay only speaks TLS.
        tls = key in _TLS_STREAM_KEYS or lowered.startswith("rtsps://")
        return CloudStream(url=url, tls=tls, key=key)


class CloudManager:
    """Every linked Imou account, their merged device list and the sign-in flow.

    A device shared between accounts keeps one camera key (and RTSP path); its
    live URLs are requested through the owner's account when possible.
    """

    def __init__(
        self,
        settings: Settings,
        store: Store,
        session: Any,
        *,
        on_change: ChangeCallback | None = None,
        client_factory: Callable[..., ImouApiClient] = ImouApiClient,
    ) -> None:
        self.settings = settings
        self.store = store
        self.session = session
        self._on_change = on_change
        self._client_factory = client_factory
        self._wake = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self.login = LoginFlow(
            session,
            store.terminal_id,
            language=settings.language,
            on_success=self._adopt,
            client_factory=client_factory,
        )
        self.accounts = [CloudAccount(self, record) for record in store.accounts]

    # ----------------------------------------------------------- lifecycle

    def make_client(self, record: AccountRecord) -> ImouApiClient:
        return self._client_factory(
            self.session,
            record.account,
            record.password,
            record.terminal_id,
            language=self.settings.language,
        )

    def start(self) -> None:
        for account in self.accounts:
            account.connect()
        self._task = asyncio.create_task(self._loop(), name="imou cloud refresh")

    async def stop(self) -> None:
        self.login.cancel()
        if self._task is not None:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task

    def request_refresh(self) -> None:
        self._wake.set()

    async def _loop(self) -> None:
        while True:
            await self.refresh_all()
            try:
                await asyncio.wait_for(self._wake.wait(), self.settings.refresh_interval)
            except TimeoutError:
                pass
            self._wake.clear()

    async def refresh_all(self) -> None:
        accounts = [account for account in self.accounts if account.usable]
        results = await asyncio.gather(
            *(account.refresh() for account in accounts), return_exceptions=True
        )
        for account, result in zip(accounts, results, strict=True):
            if isinstance(result, Exception):
                _LOGGER.error(
                    "Imou device refresh failed for %s", account.label, exc_info=result
                )

    async def notify(self) -> None:
        if self._on_change is None:
            return
        result = self._on_change()
        if asyncio.iscoroutine(result):
            await result

    # ------------------------------------------------------------ accounts

    def get(self, account_id: str) -> CloudAccount | None:
        return next((account for account in self.accounts if account.id == account_id), None)

    def match(self, account: str) -> CloudAccount | None:
        identity = account_identity(account)
        return next(
            (item for item in self.accounts if account_identity(item.record.account) == identity),
            None,
        )

    def labels(self) -> dict[str, str]:
        """Masked account names for the UI, numbered when two of them look alike."""
        labels = {account.id: account.label for account in self.accounts}
        counts = Counter(labels.values())
        seen: Counter[str] = Counter()
        for account in self.accounts:
            label = labels[account.id]
            if counts[label] > 1:
                seen[label] += 1
                labels[account.id] = f"{label} ({seen[label]})"
        return labels

    @property
    def status(self) -> str:
        if not self.accounts:
            return STATUS_NOT_CONFIGURED
        states = {account.status for account in self.accounts}
        return next((status for status in _STATUS_ORDER if status in states), STATUS_OK)

    @property
    def message(self) -> str:
        if len(self.accounts) == 1:
            return self.accounts[0].message
        labels = self.labels()
        return "; ".join(
            f"{labels[account.id]}: {account.message}"
            for account in self.accounts
            if account.message
        )

    @property
    def updated(self) -> float | None:
        times = [account.updated for account in self.accounts if account.updated is not None]
        return max(times) if times else None

    def begin_login(self, account: str, password: str, account_id: str | None = None) -> None:
        """Start signing in a new account, or again into a stored one.

        An empty ``password`` re-uses the stored one. Typing the name of an
        account that is already linked signs that account in again.
        """
        flow = self.login
        if flow.busy:
            raise AccountError(BUSY_TEXT, 409)
        if flow.step in (STEP_CAPTCHA, STEP_OTP):
            raise AccountError(PENDING_TEXT, 409)
        if account_id:
            target = self.get(account_id)
            if target is None:
                raise AccountError(NOT_FOUND_TEXT, 404)
        else:
            target = self.match(account) if account.strip() else None
        if target is not None:
            record = target.record
            started = flow.start(
                record.account,
                password or record.password,
                terminal_id=record.terminal_id,
                target=record.id,
            )
        else:
            if len(self.accounts) >= MAX_ACCOUNTS:
                raise AccountError(f"Chỉ gắn được tối đa {MAX_ACCOUNTS} tài khoản Imou.")
            started = flow.start(
                account, password, terminal_id=self.store.unused_terminal_id(), target=""
            )
        if not started:
            raise AccountError(BUSY_TEXT, 409)

    async def _adopt(self, client: ImouApiClient, account: str, password: str) -> None:
        """Called by the login flow after a successful sign-in."""
        target = self.get(self.login.target) if self.login.target else None
        if target is None:
            target = self.match(account)
        if target is not None:
            self.store.update_account(target.id, account, password, self.login.terminal_id)
            target.connect(client)
            _LOGGER.info("Imou account %s signed in again", target.label)
        else:
            record = self.store.add_account(account, password, self.login.terminal_id)
            target = CloudAccount(self, record)
            self.accounts.append(target)
            target.connect(client)
            _LOGGER.info("Linked Imou account %s", target.label)
        self.request_refresh()
        await self.notify()

    async def remove_account(self, account_id: str) -> bool:
        """Unlink an account; its camera settings and RTSP paths are kept."""
        account = self.get(account_id)
        if account is None:
            return False
        if self.login.target == account_id:
            self.login.cancel()
        self.accounts.remove(account)
        account.disconnect()
        self.store.remove_account(account_id)
        _LOGGER.info("Removed Imou account %s", account.label)
        await self.notify()
        return True

    # ------------------------------------------------------------- devices

    def _owners(self, device_id: str) -> list[tuple[CloudAccount, ImouDevice]]:
        """Accounts that list ``device_id``: the owner first, then in link order."""
        found = [
            (account, account.devices[device_id])
            for account in self.accounts
            if device_id in account.devices
        ]
        found.sort(key=lambda pair: not _is_owner(pair[1]))
        return found

    @property
    def devices(self) -> dict[str, ImouDevice]:
        merged: dict[str, ImouDevice] = {}
        for account in self.accounts:
            for device_id in account.devices:
                if device_id not in merged:
                    merged[device_id] = self._owners(device_id)[0][1]
        return merged

    def locate(
        self, key: str
    ) -> tuple[CloudAccount | None, ImouDevice | None, ImouChannel | None]:
        device_id, channel_id = split_key(key)
        owners = self._owners(device_id)
        for account, device in owners:
            channel = _channel(device, channel_id)
            if channel is not None:
                return account, device, channel
        if owners:
            account, device = owners[0]
            return account, device, None
        return None, None, None

    def find(self, key: str) -> tuple[ImouDevice | None, ImouChannel | None]:
        _, device, channel = self.locate(key)
        return device, channel

    def sync_cameras(self) -> int:
        """Create a default config for every channel that has none yet."""
        used = used_paths(self.store.cameras)
        added = 0
        for device_id in self.devices:
            for _, device in self._owners(device_id):
                for channel in device.channels:
                    key = camera_key(device.device_id, channel.channel_id)
                    if key in self.store.cameras:
                        continue
                    path = unique_path(slugify(camera_name(device, channel)), used)
                    used.update({path, f"{path}{SUB_SUFFIX}"})
                    self.store.cameras[key] = CameraConfig(enabled=True, path=path)
                    added += 1
        if added:
            self.store.save()
        return added

    # ------------------------------------------------------------ live URL

    async def live_stream(
        self,
        device: ImouDevice,
        channel: ImouChannel,
        *,
        sub: bool,
        fresh: bool = False,
    ) -> CloudStream:
        """Ask the best account that lists the channel for a live URL."""
        candidates = [
            (account, own_device, own_channel)
            for account, own_device in self._owners(device.device_id)
            if (own_channel := _channel(own_device, channel.channel_id)) is not None
        ]
        if not candidates:
            raise SourceError("Chế độ cloud cần đăng nhập Imou.")
        failure: SourceError | None = None
        for account, own_device, own_channel in candidates:
            if not account.usable:
                continue
            try:
                return await account.live_stream(own_device, own_channel, sub=sub, fresh=fresh)
            except SourceError as err:
                # Another account that shares the camera may still be signed in.
                if account.status != STATUS_NEEDS_LOGIN:
                    raise
                failure = err
        raise failure or SourceError("Imou yêu cầu đăng nhập lại trước khi lấy luồng cloud.")
