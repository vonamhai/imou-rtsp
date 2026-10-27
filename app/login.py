"""Imou Life sign-in state machine: account → CAPTCHA → one-time code.

Ported from the ``config_flow.py`` of trankhanhduy2929-beep/imou_homeassistant
(MIT). Every cloud call runs in a background task because a single step (for
example the post-OTP propagation retries) can take more than 30 seconds; the
web UI polls :meth:`LoginFlow.snapshot`.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable, Coroutine, Mapping
from hashlib import sha256
from typing import Any

from .imou.api import (
    CAPTCHA_REJECTED_CODE,
    ImouApiClient,
    ImouApiError,
    ImouAuthError,
    ImouCaptchaChallenge,
    ImouCaptchaRequired,
    ImouConnectionError,
    ImouCredentialError,
    ImouQrLoginRequired,
    ImouTwoStepVerificationRequired,
)

_LOGGER = logging.getLogger(__name__)

RESUME_AUTHENTICATE = "authenticate"
RESUME_SEND_OTP = "send_otp"
RESUME_GRANT_OTP = "grant_otp"

STEP_ACCOUNT = "account"
STEP_CAPTCHA = "captcha"
STEP_OTP = "otp"
STEP_DONE = "done"

ERROR_TEXT = {
    "cannot_connect": "Không kết nối được Imou cloud.",
    "invalid_auth": "Imou từ chối tài khoản hoặc mật khẩu.",
    "invalid_code": "Mã xác minh sai hoặc đã hết hạn.",
    "verification_pending": (
        "Imou chưa ghi nhận quyền cho thiết bị đăng nhập này sau khi đã nhận mã. "
        "Hãy yêu cầu mã mới và xác minh lại."
    ),
    "code_send_failed": "Imou không gửi được mã xác minh.",
    "captcha_unavailable": "Imou không trả về CAPTCHA có thể sử dụng.",
    "missing_fields": "Hãy nhập tài khoản và mật khẩu.",
    "unknown": "Imou trả về lỗi không xác định.",
}
INFO_TEXT = {"code_sent": "Đã gửi một mã xác minh mới."}
DEFAULT_DELIVERY = "kênh bảo mật đã liên kết"

SuccessCallback = Callable[[ImouApiClient, str, str], Awaitable[None]]
ClientFactory = Callable[..., ImouApiClient]


def delivery_text(response: Any) -> str:
    """Describe where Imou sent the one-time code."""
    if isinstance(response, Mapping):
        for key, value in response.items():
            if value in (None, ""):
                continue
            normalized = str(key).casefold().replace("_", "")
            if normalized in {"bindphone", "phone", "mobile", "mobilephone"}:
                return "SMS đến số điện thoại đã liên kết"
            if normalized in {"bindemail", "email"}:
                return "email đã liên kết"
    return DEFAULT_DELIVERY


class LoginFlow:
    """One interactive sign-in at a time, driven by the web UI."""

    def __init__(
        self,
        session: Any,
        terminal_id: str,
        *,
        language: str,
        on_success: SuccessCallback,
        request_timeout: float = 15.0,
        client_factory: ClientFactory = ImouApiClient,
    ) -> None:
        self._session = session
        self._language = language
        self._on_success = on_success
        self._request_timeout = request_timeout
        self._client_factory = client_factory
        self._client: ImouApiClient | None = None
        self._password = ""
        self._task: asyncio.Task[None] | None = None
        self._terminal_id = ""
        self.fingerprint = ""
        self._set_terminal(terminal_id)
        # Stamp (ms) of the latest completed sign-in. It only grows, so the UI notices
        # a sign-in that finished between two polls even when the step stayed "done".
        self.finished = 0
        self.first_seen = int(time.time() * 1000)
        self.account = ""
        # Id of the stored account being signed in again ("" for a new account).
        self.target = ""
        self.step = STEP_ACCOUNT
        self.error = ""
        self.info = ""
        self.delivery = DEFAULT_DELIVERY
        self.challenge: ImouCaptchaChallenge | None = None
        self.generation = 0
        self.resume = RESUME_AUTHENTICATE
        self.pending_code: str | None = None
        self.captcha_status = ""
        self.captcha_message = ""

    @property
    def busy(self) -> bool:
        return self._task is not None and not self._task.done()

    @property
    def terminal_id(self) -> str:
        """Terminal id the current sign-in authorizes (one per Imou account)."""
        return self._terminal_id

    def _set_terminal(self, terminal_id: str) -> None:
        self._terminal_id = terminal_id
        self.fingerprint = sha256(f"geetest:{terminal_id}".encode()).hexdigest()

    def snapshot(self) -> dict[str, Any]:
        challenge = self.challenge
        return {
            "step": self.step,
            "busy": self.busy,
            "finished": self.finished,
            "account": self.account,
            "target": self.target,
            "error": self.error,
            "error_text": ERROR_TEXT.get(self.error, self.error),
            "info": INFO_TEXT.get(self.info, ""),
            "delivery": self.delivery,
            "captcha": {
                "generation": self.generation,
                "image": bool(challenge is not None and challenge.is_image),
                "status": self.captcha_status,
                "message": self.captcha_message,
            },
        }

    # ------------------------------------------------------------------ actions

    def _spawn(self, coro: Coroutine[Any, Any, None]) -> bool:
        if self.busy:
            coro.close()
            return False
        self._task = asyncio.create_task(self._guard(coro), name="imou login")
        return True

    async def _guard(self, coro: Coroutine[Any, Any, None]) -> None:
        try:
            await coro
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - surface unexpected failures in the UI
            _LOGGER.exception("Unexpected error during Imou sign-in")
            self._show_account("unknown")

    def start(
        self,
        account: str,
        password: str,
        *,
        terminal_id: str | None = None,
        target: str = "",
    ) -> bool:
        """Begin a new sign-in with fresh credentials.

        ``terminal_id`` is the device identity Imou authorizes for this account and
        ``target`` the id of the stored account being signed in again, if any.
        """
        if self.busy:
            return False
        account = account.strip()
        self.account = account
        self.target = target
        if terminal_id:
            self._set_terminal(terminal_id)
        self.info = ""
        if not account or not password:
            self._show_account("missing_fields")
            return True
        self._password = password
        self.first_seen = int(time.time() * 1000)
        self.step = STEP_ACCOUNT
        self.challenge = None
        self.pending_code = None
        self.resume = RESUME_AUTHENTICATE
        self.captcha_status = ""
        self.captcha_message = ""
        self.error = ""
        self._client = self._client_factory(
            self._session,
            account,
            password,
            self._terminal_id,
            request_timeout=self._request_timeout,
            language=self._language,
        )
        return self._spawn(self._start_authentication())

    def submit_captcha(self, generation: Any, result: Any) -> bool:
        return self._spawn(self._submit_captcha(generation, result))

    def refresh_captcha(self) -> bool:
        if self.step != STEP_CAPTCHA or self._client is None:
            return True
        return self._spawn(self._repeat_pending_action())

    def submit_otp(self, code: str) -> bool:
        return self._spawn(self._submit_two_step_code(str(code or "").strip()))

    def resend_otp(self) -> bool:
        return self._spawn(self._resend_two_step_code())

    def cancel(self) -> None:
        if self._task is not None and not self._task.done():
            self._task.cancel()
        self._task = None
        self._client = None
        self._password = ""
        self.challenge = None
        self.pending_code = None
        self.account = ""
        self.target = ""
        self.step = STEP_ACCOUNT
        self.error = ""
        self.info = ""

    # ----------------------------------------------------------------- helpers

    def _show_account(self, error: str) -> None:
        self.step = STEP_ACCOUNT
        self.error = error
        self.challenge = None

    def _show_two_step(self, error: str = "") -> None:
        self.step = STEP_OTP
        self.error = error

    def _set_captcha(self, status: str, message: str) -> None:
        self.captcha_status = status
        self.captcha_message = message

    async def _finish(self) -> None:
        client = self._client
        password = self._password
        assert client is not None
        self.step = STEP_DONE
        self.finished = max(self.finished + 1, int(time.time() * 1000))
        self.error = ""
        self.info = ""
        self.challenge = None
        self.pending_code = None
        self._client = None
        self._password = ""
        _LOGGER.info("Imou sign-in completed")
        await self._on_success(client, self.account, password)

    # -------------------------------------------------------------- the flow

    async def _start_authentication(self) -> None:
        assert self._client is not None
        try:
            await self._client.async_authenticate(use_pc_client=False)
        except ImouCaptchaRequired as err:
            await self._begin_captcha(err.challenge, RESUME_AUTHENTICATE)
            return
        except ImouTwoStepVerificationRequired:
            await self._begin_two_step()
            return
        except ImouCredentialError:
            self._show_account("invalid_auth")
            return
        except ImouQrLoginRequired:
            self._show_account("captcha_unavailable")
            return
        except ImouConnectionError:
            self._show_account("cannot_connect")
            return
        except ImouAuthError:
            self._show_account("invalid_auth")
            return
        except ImouApiError:
            self._show_account("unknown")
            return
        await self._finish()

    async def _begin_captcha(
        self,
        challenge: ImouCaptchaChallenge,
        resume: str,
        *,
        fallback: str = STEP_ACCOUNT,
    ) -> None:
        assert self._client is not None
        try:
            prepared = await self._client.async_prepare_captcha(challenge)
        except (ImouApiError, ValueError) as err:
            _LOGGER.warning("Imou CAPTCHA could not be prepared: %s", err)
            if fallback == STEP_OTP:
                self._show_two_step("captcha_unavailable")
            else:
                self._show_account("captcha_unavailable")
            return
        self.challenge = prepared
        self.resume = resume
        self.generation += 1
        self.step = STEP_CAPTCHA
        self.error = ""
        self._set_captcha("required", "Hoàn tất CAPTCHA để tiếp tục.")
        _LOGGER.info(
            "Imou requires a %s CAPTCHA", "picture" if prepared.is_image else "GeeTest"
        )

    async def _submit_captcha(self, generation: Any, result: Any) -> None:
        if self.step != STEP_CAPTCHA or self.challenge is None or self._client is None:
            self._set_captcha("rejected", "Dữ liệu CAPTCHA không hợp lệ.")
            return
        try:
            generation_number = int(generation)
        except (TypeError, ValueError):
            generation_number = -1
        if generation_number != self.generation:
            self._set_captcha("rejected", "Phiên CAPTCHA đã thay đổi; trang sẽ tải lại.")
            return
        if not isinstance(result, Mapping):
            self._set_captcha("rejected", "Dữ liệu CAPTCHA không hợp lệ.")
            return
        self._set_captcha("validating", "Đang kiểm tra CAPTCHA với Imou…")
        try:
            if self.challenge.is_image:
                await self._client.async_validate_image_captcha(
                    self.challenge, str(result.get("code") or "")
                )
            else:
                await self._client.async_validate_geetest(self.challenge, result)
        except ValueError:
            self._set_captcha("rejected", "Kết quả CAPTCHA không đầy đủ hoặc đã hết hạn.")
            return
        except ImouApiError as err:
            if err.code == CAPTCHA_REJECTED_CODE:
                self._set_captcha("rejected", "Imou từ chối CAPTCHA. Đang tạo thử thách mới…")
                await self._repeat_pending_action()
                return
            self._show_account("cannot_connect")
            return
        self._set_captcha("accepted", "CAPTCHA hợp lệ. Đang tiếp tục đăng nhập…")
        await self._resume_after_captcha()

    async def _repeat_pending_action(self) -> None:
        self._set_captcha("validating", "Đang yêu cầu CAPTCHA mới từ Imou…")
        await self._resume_after_captcha()

    async def _resume_after_captcha(self) -> None:
        assert self._client is not None
        resume = self.resume
        try:
            if resume == RESUME_SEND_OTP:
                response = await self._client.async_request_two_step_code()
                self.delivery = delivery_text(response)
                self.challenge = None
                self._show_two_step()
                return
            if resume == RESUME_GRANT_OTP:
                if self.pending_code is None:
                    self.challenge = None
                    self._show_two_step("invalid_code")
                    return
                await self._client.async_grant_two_step_code(self.pending_code)
                self.pending_code = None
                await self._client.async_authenticate_after_two_step()
            else:
                await self._client.async_authenticate(force=True, use_pc_client=False)
        except ImouCaptchaRequired as err:
            if resume == RESUME_GRANT_OTP and self.pending_code is None:
                resume = RESUME_AUTHENTICATE
            await self._begin_captcha(err.challenge, resume)
            return
        except ImouTwoStepVerificationRequired:
            if resume == RESUME_GRANT_OTP:
                self.challenge = None
                self._show_two_step(
                    "verification_pending" if self.pending_code is None else "invalid_code"
                )
                return
            self.challenge = None
            await self._begin_two_step()
            return
        except ImouCredentialError:
            self._show_account("invalid_auth")
            return
        except ImouQrLoginRequired:
            self._show_account("captcha_unavailable")
            return
        except ImouConnectionError:
            self._show_account("cannot_connect")
            return
        except ImouAuthError:
            self._show_account("invalid_auth")
            return
        except ImouApiError:
            if resume == RESUME_GRANT_OTP:
                self.challenge = None
                self._show_two_step(
                    "verification_pending" if self.pending_code is None else "invalid_code"
                )
            else:
                self._show_account("unknown")
            return
        await self._finish()

    async def _begin_two_step(self) -> None:
        assert self._client is not None
        try:
            response = await self._client.async_request_two_step_code()
        except ImouCaptchaRequired as err:
            await self._begin_captcha(err.challenge, RESUME_SEND_OTP, fallback=STEP_OTP)
            return
        except ImouApiError as err:
            _LOGGER.warning("Imou could not send a verification code: %s", err)
            self._show_two_step("code_send_failed")
            return
        self.delivery = delivery_text(response)
        self._show_two_step()

    async def _resend_two_step_code(self) -> None:
        if self.step != STEP_OTP or self._client is None:
            return
        self.info = ""
        try:
            response = await self._client.async_request_two_step_code()
        except ImouCaptchaRequired as err:
            await self._begin_captcha(err.challenge, RESUME_SEND_OTP, fallback=STEP_OTP)
            return
        except ImouConnectionError:
            self._show_two_step("cannot_connect")
            return
        except ImouApiError:
            self._show_two_step("code_send_failed")
            return
        self.delivery = delivery_text(response)
        self.error = ""
        self.info = "code_sent"

    async def _submit_two_step_code(self, code: str) -> None:
        if self.step != STEP_OTP or self._client is None:
            return
        self.info = ""
        if len(code) != 6 or not code.isdigit():
            self._show_two_step("invalid_code")
            return
        self.error = ""
        self.pending_code = code
        try:
            await self._client.async_grant_two_step_code(code)
            self.pending_code = None
            await self._client.async_authenticate_after_two_step()
        except ImouCaptchaRequired as err:
            resume = RESUME_GRANT_OTP if self.pending_code is not None else RESUME_AUTHENTICATE
            await self._begin_captcha(err.challenge, resume, fallback=STEP_OTP)
            return
        except ImouTwoStepVerificationRequired:
            granted = self.pending_code is None
            self.pending_code = None
            self._show_two_step("verification_pending" if granted else "invalid_code")
            return
        except ImouConnectionError:
            self.pending_code = None
            self._show_two_step("cannot_connect")
            return
        except ImouCredentialError:
            self.pending_code = None
            self._show_two_step("invalid_auth")
            return
        except ImouApiError:
            granted = self.pending_code is None
            self.pending_code = None
            self._show_two_step("verification_pending" if granted else "invalid_code")
            return
        await self._finish()
