from __future__ import annotations

import asyncio
from typing import Any

import pytest

from app.imou.api import (
    CAPTCHA_REJECTED_CODE,
    ImouApiError,
    ImouCaptchaChallenge,
    ImouCaptchaRequired,
    ImouConnectionError,
    ImouCredentialError,
    ImouTwoStepVerificationRequired,
)
from app.login import STEP_ACCOUNT, STEP_CAPTCHA, STEP_DONE, STEP_OTP, LoginFlow


class FakeClient:
    """Replays scripted outcomes (values or exceptions) per API call."""

    def __init__(self, script: dict[str, list[Any]]) -> None:
        self.script = script
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
        # Positional arguments of every client_factory call that returned this client.
        self.factory_args: list[tuple[Any, ...]] = []

    async def _run(self, name: str, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((name, args, kwargs))
        outcomes = self.script.get(name) or []
        outcome = outcomes.pop(0) if outcomes else None
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    async def async_authenticate(self, **kwargs: Any) -> Any:
        return await self._run("authenticate", **kwargs)

    async def async_prepare_captcha(self, challenge: ImouCaptchaChallenge) -> Any:
        await self._run("prepare", challenge)
        return challenge

    async def async_validate_image_captcha(self, challenge: Any, code: str) -> Any:
        return await self._run("validate_image", code)

    async def async_validate_geetest(self, challenge: Any, result: Any) -> Any:
        return await self._run("validate_geetest", dict(result))

    async def async_request_two_step_code(self) -> Any:
        return await self._run("request_code")

    async def async_grant_two_step_code(self, code: str) -> Any:
        return await self._run("grant", code)

    async def async_authenticate_after_two_step(self) -> Any:
        return await self._run("after_two_step")


def _captcha(mode: str = "image") -> ImouCaptchaRequired:
    return ImouCaptchaRequired("captcha", 1, ImouCaptchaChallenge(mode=mode, image="AAAA"))


def _flow(client: FakeClient) -> tuple[LoginFlow, list[tuple[Any, str, str]]]:
    adopted: list[tuple[Any, str, str]] = []

    async def on_success(adopted_client: Any, account: str, password: str) -> None:
        adopted.append((adopted_client, account, password))

    def factory(*args: Any, **kwargs: Any) -> FakeClient:
        client.factory_args.append(args)
        return client

    flow = LoginFlow(
        None,
        "0123456789abcdef0123456789abcdef",
        language="en_US",
        on_success=on_success,
        client_factory=factory,
    )
    return flow, adopted


async def _settle(flow: LoginFlow) -> None:
    for _ in range(200):
        if not flow.busy:
            return
        await asyncio.sleep(0.01)
    raise AssertionError("login flow did not settle")


async def test_full_flow_captcha_then_otp() -> None:
    client = FakeClient(
        {
            "authenticate": [_captcha(), ImouTwoStepVerificationRequired("otp")],
            "request_code": [{"bindPhone": "09******12"}],
        }
    )
    flow, adopted = _flow(client)
    assert flow.start(" user@example.com ", "pw")
    await _settle(flow)
    assert flow.step == STEP_CAPTCHA and flow.generation == 1
    snapshot = flow.snapshot()
    assert snapshot["captcha"]["image"] is True and snapshot["captcha"]["status"] == "required"

    assert flow.submit_captcha(1, {"code": "ab12"})
    await _settle(flow)
    assert flow.step == STEP_OTP
    assert flow.delivery == "SMS đến số điện thoại đã liên kết"
    assert ("validate_image", ("ab12",), {}) in client.calls

    assert flow.submit_otp("123456")
    await _settle(flow)
    assert flow.step == STEP_DONE
    assert adopted == [(client, "user@example.com", "pw")]
    names = [call[0] for call in client.calls]
    assert names[-2:] == ["grant", "after_two_step"]


async def test_wrong_password_returns_to_account_form() -> None:
    flow, adopted = _flow(FakeClient({"authenticate": [ImouCredentialError(2)]}))
    flow.start("user", "bad")
    await _settle(flow)
    assert flow.step == STEP_ACCOUNT
    assert flow.snapshot()["error_text"] == "Imou từ chối tài khoản hoặc mật khẩu."
    assert adopted == []


async def test_missing_fields_and_connection_error() -> None:
    flow, _ = _flow(FakeClient({"authenticate": [ImouConnectionError("down")]}))
    assert flow.start("", "")
    assert flow.error == "missing_fields" and not flow.busy
    flow.start("user", "pw")
    await _settle(flow)
    assert flow.error == "cannot_connect"


async def test_captcha_generation_mismatch_is_rejected() -> None:
    client = FakeClient({"authenticate": [_captcha("geetest")]})
    flow, _ = _flow(client)
    flow.start("user", "pw")
    await _settle(flow)
    flow.submit_captcha(99, {"lot_number": "x"})
    await _settle(flow)
    assert flow.step == STEP_CAPTCHA
    assert flow.captcha_status == "rejected"
    assert not any(call[0] == "validate_geetest" for call in client.calls)


async def test_rejected_captcha_requests_a_new_one() -> None:
    client = FakeClient(
        {
            "authenticate": [_captcha(), _captcha()],
            "validate_image": [ImouApiError("bad", CAPTCHA_REJECTED_CODE)],
        }
    )
    flow, _ = _flow(client)
    flow.start("user", "pw")
    await _settle(flow)
    flow.submit_captcha(1, {"code": "zzzz"})
    await _settle(flow)
    assert flow.step == STEP_CAPTCHA
    assert flow.generation == 2
    assert flow.captcha_status == "required"


async def test_otp_validation_and_pending_grant() -> None:
    client = FakeClient(
        {
            "authenticate": [ImouTwoStepVerificationRequired("otp")],
            "request_code": [{}],
            "after_two_step": [ImouTwoStepVerificationRequired("still")],
        }
    )
    flow, adopted = _flow(client)
    flow.start("user", "pw")
    await _settle(flow)
    assert flow.step == STEP_OTP and flow.delivery == "kênh bảo mật đã liên kết"
    flow.submit_otp("12ab")
    await _settle(flow)
    assert flow.error == "invalid_code"
    assert not any(call[0] == "grant" for call in client.calls)
    flow.submit_otp("654321")
    await _settle(flow)
    assert flow.step == STEP_OTP and flow.error == "verification_pending"
    assert adopted == []


async def test_busy_flow_refuses_new_actions() -> None:
    gate = asyncio.Event()

    class SlowClient(FakeClient):
        async def async_authenticate(self, **kwargs: Any) -> Any:
            await gate.wait()
            return None

    flow, adopted = _flow(SlowClient({}))
    assert flow.start("user", "pw")
    await asyncio.sleep(0)
    assert flow.busy
    assert flow.start("user", "pw") is False
    assert flow.submit_otp("123456") is False
    gate.set()
    await _settle(flow)
    assert flow.step == STEP_DONE and len(adopted) == 1


async def test_cancel_resets_the_flow() -> None:
    flow, _ = _flow(FakeClient({"authenticate": [_captcha()]}))
    flow.start("user", "pw")
    await _settle(flow)
    flow.cancel()
    assert flow.step == STEP_ACCOUNT and flow.challenge is None


async def test_start_signs_in_with_the_accounts_own_terminal() -> None:
    client = FakeClient({})
    flow, adopted = _flow(client)
    default_fingerprint = flow.fingerprint
    assert flow.start("user", "pw", terminal_id="1" * 32, target="acct0001")
    assert client.factory_args[0][1:] == ("user", "pw", "1" * 32)
    assert flow.terminal_id == "1" * 32 and flow.fingerprint != default_fingerprint
    assert flow.snapshot()["target"] == "acct0001"
    await _settle(flow)
    assert flow.step == STEP_DONE and adopted == [(client, "user", "pw")]
    flow.cancel()
    assert (flow.step, flow.account, flow.target) == (STEP_ACCOUNT, "", "")


async def test_a_finished_flow_can_sign_in_another_account() -> None:
    client = FakeClient({})
    flow, adopted = _flow(client)
    assert flow.snapshot()["finished"] == 0
    flow.start("first", "pw1", terminal_id="1" * 32)
    await _settle(flow)
    assert flow.step == STEP_DONE
    first = flow.snapshot()["finished"]
    assert first > 0
    assert flow.start("second", "pw2", terminal_id="2" * 32)
    assert flow.step == STEP_ACCOUNT and flow.busy
    await _settle(flow)
    assert flow.step == STEP_DONE
    # The UI spots the second sign-in even if it never saw the step leave "done".
    assert flow.snapshot()["finished"] > first
    assert [entry[1:] for entry in adopted] == [("first", "pw1"), ("second", "pw2")]
    assert [args[3] for args in client.factory_args] == ["1" * 32, "2" * 32]


@pytest.mark.parametrize(
    ("response", "text"),
    [
        ({"bindEmail": "a***@x.com"}, "email đã liên kết"),
        ({"phone": "09***"}, "SMS đến số điện thoại đã liên kết"),
        ({"bindPhone": ""}, "kênh bảo mật đã liên kết"),
        (None, "kênh bảo mật đã liên kết"),
    ],
)
def test_delivery_text(response: Any, text: str) -> None:
    from app.login import delivery_text

    assert delivery_text(response) == text
