from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any

import pytest
from helpers import fake_imou_factory, make_settings, settle

from app import cloud as cloud_module
from app.cloud import AccountError, CloudManager, account_identity
from app.imou.api import ImouAuthError, ImouTwoStepVerificationRequired
from app.login import STEP_ACCOUNT, STEP_DONE, STEP_OTP
from app.store import Store, migrated_account_id

TERMINAL = "0123456789abcdef0123456789abcdef"
GATE = {"deviceId": "AAA", "productId": "P", "name": "Cổng trước"}
YARD = {"deviceId": "BBB", "productId": "P", "name": "Sân sau"}


def _write(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


def _saved(tmp_path: Path) -> dict[str, Any]:
    return json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))


def _linked(
    tmp_path: Path, *accounts: tuple[str, list[dict[str, Any]]]
) -> tuple[Store, CloudManager]:
    store = Store(tmp_path)
    store.load()
    for account, raws in accounts:
        record = store.add_account(account, "pw", store.unused_terminal_id())
        store.save_devices(record.id, raws)
    return store, CloudManager(make_settings(tmp_path), store, None)


# ------------------------------------------------------------------ store


def test_store_migrates_a_version_1_config(tmp_path: Path) -> None:
    _write(
        tmp_path / "config.json",
        {
            "terminal_id": TERMINAL,
            "account": {"account": "user@example.com", "password": "pw"},
            "cameras": {"AAA:0": {"enabled": True, "path": "cong"}},
        },
    )
    _write(tmp_path / "devices.json", {"saved_at": 1, "devices": [GATE]})
    store = Store(tmp_path)
    store.load()

    [record] = store.accounts
    assert record.id == migrated_account_id(TERMINAL)
    assert (record.account, record.password) == ("user@example.com", "pw")
    assert record.terminal_id == store.terminal_id == TERMINAL
    assert not (tmp_path / "devices.json").exists()
    assert store.load_devices(record.id) == [GATE]
    assert store.cameras["AAA:0"].path == "cong"
    saved = _saved(tmp_path)
    assert saved["version"] == 2 and "account" not in saved
    assert saved["accounts"] == [record.to_dict()]

    again = Store(tmp_path)
    again.load()
    assert [item.to_dict() for item in again.accounts] == [record.to_dict()]
    assert again.unused_terminal_id() != TERMINAL


def test_store_migration_is_repeatable_after_a_crash(tmp_path: Path) -> None:
    legacy = {"terminal_id": TERMINAL, "account": {"account": "u@example.com", "password": "pw"}}
    _write(tmp_path / "config.json", legacy)
    target = tmp_path / f"devices-{migrated_account_id(TERMINAL)}.json"
    _write(target, {"devices": [YARD]})
    _write(tmp_path / "devices.json", {"devices": [GATE]})
    store = Store(tmp_path)
    store.load()
    # The list moved by the interrupted run wins; the stale copy is left alone.
    assert store.load_devices(store.accounts[0].id) == [YARD]
    assert (tmp_path / "devices.json").exists()


def test_store_repairs_bad_account_entries(tmp_path: Path) -> None:
    def entry(account_id: str, account: str, terminal_id: str) -> dict[str, str]:
        return {"id": account_id, "account": account, "password": "x", "terminal_id": terminal_id}

    _write(
        tmp_path / "config.json",
        {
            "version": 2,
            "terminal_id": TERMINAL,
            "accounts": [
                entry("abcd1234", "a@example.com", "t" * 32),
                entry("abcd1234", "b@example.com", "short"),
                entry("../x", "c@example.com", "u" * 32),
                {"account": " ", "password": "4"},
                "garbage",
            ],
        },
    )
    store = Store(tmp_path)
    store.load()
    accounts = [record.account for record in store.accounts]
    assert accounts == ["a@example.com", "b@example.com", "c@example.com"]
    ids = [record.id for record in store.accounts]
    assert ids[0] == "abcd1234" and len(set(ids)) == 3
    assert all(re.fullmatch(r"[a-z0-9]{8}", account_id) for account_id in ids)
    assert store.accounts[1].terminal_id != "short" and len(store.accounts[1].terminal_id) == 32
    assert store.accounts[2].terminal_id == "u" * 32
    assert [entry["id"] for entry in _saved(tmp_path)["accounts"]] == ids


# ------------------------------------------------------------------ cloud


def test_account_identity_matches_imou_spelling() -> None:
    assert account_identity("+84 912 345 678") == account_identity("0912345678")
    assert account_identity("User@Example.com ") == account_identity("user@example.com")
    assert account_identity("a@example.com") != account_identity("b@example.com")


def test_shared_device_keeps_one_camera_and_prefers_the_owner(tmp_path: Path) -> None:
    store, cloud = _linked(
        tmp_path,
        ("guest@example.com", [{**GATE, "role": "share"}, {**YARD, "deviceId": "G1"}]),
        ("owner@example.com", [{**GATE, "role": "owner"}, {**YARD, "deviceId": "O1"}]),
    )
    guest, owner = cloud.accounts
    assert cloud.sync_cameras() == 3
    assert {key: config.path for key, config in store.cameras.items()} == {
        "AAA:0": "cong_truoc",
        "G1:0": "san_sau",
        "O1:0": "san_sau_2",
    }
    account, device, channel = cloud.locate("AAA:0")
    assert account is owner and device is owner.devices["AAA"] and channel is not None
    assert cloud.devices["AAA"] is owner.devices["AAA"]
    assert cloud.locate("G1:0")[0] is guest
    assert cloud.locate("AAA:7")[0] is owner and cloud.locate("AAA:7")[2] is None
    assert cloud.locate("NOPE:0") == (None, None, None)
    assert len(cloud.devices) == 3


def test_labels_status_and_message_cover_every_account(tmp_path: Path) -> None:
    store = Store(tmp_path)
    store.load()
    assert CloudManager(make_settings(tmp_path), store, None).status == "not_configured"
    _, cloud = _linked(
        tmp_path, ("user1@example.com", []), ("user2@example.com", []), ("0912345678", [])
    )
    first, second, third = cloud.accounts
    assert cloud.labels() == {
        first.id: "us***@example.com (1)",
        second.id: "us***@example.com (2)",
        third.id: "091***78",
    }
    for account in cloud.accounts:
        account.status = "ok"
    assert cloud.status == "ok" and cloud.message == ""
    second.status, second.message = "error", "mất mạng"
    assert cloud.status == "error"
    assert cloud.message == "us***@example.com (2): mất mạng"
    third.status = "needs_login"
    assert cloud.status == "needs_login"
    first.updated, second.updated = 10.0, 20.0
    assert cloud.updated == 20.0


async def test_linking_and_signing_in_again(tmp_path: Path) -> None:
    factory, made = fake_imou_factory(
        {"a@example.com": [GATE], "b@example.com": [YARD, {**GATE, "role": "share"}]}
    )
    store = Store(tmp_path)
    store.load()
    changes: list[int] = []
    cloud = CloudManager(
        make_settings(tmp_path),
        store,
        None,
        on_change=lambda: changes.append(1),
        client_factory=factory,
    )

    cloud.begin_login("a@example.com", "pw-a")
    await settle(cloud.login)
    assert cloud.login.step == STEP_DONE
    [first] = cloud.accounts
    # The first account keeps the shared terminal id (no new CAPTCHA after an upgrade).
    assert first.record.terminal_id == store.terminal_id
    assert first.client is made[-1]

    cloud.begin_login("b@example.com", "pw-b")
    await settle(cloud.login)
    second = cloud.accounts[1]
    assert second.record.terminal_id not in (store.terminal_id, "")
    assert made[-1].terminal_id == second.record.terminal_id
    assert changes

    await cloud.refresh_all()
    assert [account.status for account in cloud.accounts] == ["ok", "ok"]
    assert sorted(store.cameras) == ["AAA:0", "BBB:0"]
    assert cloud.locate("AAA:0")[0] is first
    assert cloud.locate("BBB:0")[0] is second
    assert [raw["deviceId"] for raw in store.load_devices(second.id)] == ["BBB", "AAA"]

    # Typing a linked account again signs that account in again; no password = stored one.
    cloud.begin_login("A@EXAMPLE.COM", "")
    assert cloud.login.target == first.id
    await settle(cloud.login)
    assert len(cloud.accounts) == 2
    assert (made[-1].account, made[-1].password) == ("a@example.com", "pw-a")
    assert made[-1].terminal_id == first.record.terminal_id
    assert first.client is made[-1]

    cloud.begin_login("", "new-b", second.id)
    await settle(cloud.login)
    assert (made[-1].account, made[-1].password) == ("b@example.com", "new-b")
    saved = _saved(tmp_path)["accounts"]
    assert [(entry["account"], entry["password"]) for entry in saved] == [
        ("a@example.com", "pw-a"),
        ("b@example.com", "new-b"),
    ]


async def test_begin_login_refusals(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    factory, _ = fake_imou_factory(
        auth_errors={"otp@example.com": [ImouTwoStepVerificationRequired("otp")]}
    )
    store = Store(tmp_path)
    store.load()
    cloud = CloudManager(make_settings(tmp_path), store, None, client_factory=factory)

    cloud.begin_login("a@example.com", "pw")
    assert cloud.login.busy
    with pytest.raises(AccountError) as busy:
        cloud.begin_login("b@example.com", "pw")
    assert busy.value.status == 409
    await settle(cloud.login)

    with pytest.raises(AccountError) as unknown:
        cloud.begin_login("", "", "nope1234")
    assert unknown.value.status == 404

    cloud.begin_login("otp@example.com", "pw")
    await settle(cloud.login)
    assert cloud.login.step == STEP_OTP
    with pytest.raises(AccountError) as pending:
        cloud.begin_login("b@example.com", "pw")
    assert pending.value.status == 409
    cloud.login.cancel()

    monkeypatch.setattr(cloud_module, "MAX_ACCOUNTS", 1)
    with pytest.raises(AccountError) as full:
        cloud.begin_login("b@example.com", "pw")
    assert full.value.status == 400
    # Signing in again into a linked account is still allowed.
    cloud.begin_login("a@example.com", "")
    await settle(cloud.login)
    assert cloud.login.step == STEP_DONE and len(cloud.accounts) == 1


async def test_failed_refresh_marks_only_that_account(tmp_path: Path) -> None:
    factory, made = fake_imou_factory({"a@example.com": [GATE], "b@example.com": [YARD]})
    store = Store(tmp_path)
    store.load()
    store.add_account("a@example.com", "pw", store.unused_terminal_id())
    store.add_account("b@example.com", "pw", store.unused_terminal_id())
    cloud = CloudManager(make_settings(tmp_path), store, None, client_factory=factory)
    for account in cloud.accounts:
        account.connect()
    made[0].list_error = ImouAuthError("expired")
    await cloud.refresh_all()
    first, second = cloud.accounts
    assert first.status == "needs_login" and not first.usable
    assert second.status == "ok" and sorted(store.cameras) == ["BBB:0"]
    assert cloud.status == "needs_login"
    await cloud.refresh_all()
    assert made[0].list_calls == 1 and made[1].list_calls == 2


async def test_removing_an_account_keeps_camera_settings(tmp_path: Path) -> None:
    factory, made = fake_imou_factory(
        {"a@example.com": [GATE], "b@example.com": [YARD]},
        auth_errors={"b@example.com": [ImouTwoStepVerificationRequired("otp")]},
    )
    store = Store(tmp_path)
    store.load()
    store.add_account("a@example.com", "pw", store.unused_terminal_id())
    store.add_account("b@example.com", "pw", store.unused_terminal_id())
    changes: list[int] = []
    cloud = CloudManager(
        make_settings(tmp_path),
        store,
        None,
        on_change=lambda: changes.append(1),
        client_factory=factory,
    )
    for account in cloud.accounts:
        account.connect()
    await cloud.refresh_all()
    first, second = cloud.accounts
    assert sorted(store.cameras) == ["AAA:0", "BBB:0"]

    # A sign-in waiting for the code of the removed account is dropped as well.
    cloud.begin_login("", "", second.id)
    await settle(cloud.login)
    assert cloud.login.step == STEP_OTP and cloud.login.target == second.id
    changes.clear()
    assert await cloud.remove_account(second.id) is True
    assert await cloud.remove_account(second.id) is False
    assert cloud.login.step == STEP_ACCOUNT and cloud.login.target == ""
    assert [account.id for account in cloud.accounts] == [first.id]
    assert second.client is None and second.status == "not_configured"
    assert changes == [1]
    assert sorted(store.cameras) == ["AAA:0", "BBB:0"]
    assert cloud.locate("BBB:0") == (None, None, None)
    assert not store.devices_path(second.id).exists()
    assert [entry["id"] for entry in _saved(tmp_path)["accounts"]] == [first.id]

    # A device list that arrives after the account was removed is ignored.
    gate = asyncio.Event()
    made[0].list_gate = gate
    task = asyncio.create_task(first.refresh())
    await asyncio.sleep(0)
    assert await cloud.remove_account(first.id) is True
    gate.set()
    await task
    assert not store.devices_path(first.id).exists()
    assert cloud.accounts == [] and cloud.status == "not_configured"
