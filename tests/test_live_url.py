"""Which Imou API is asked for a live link first, and how bad link types are set aside."""

from __future__ import annotations

from typing import Any

from app.imou.api import ImouApiClient, ImouApiError, ImouConnectionError

KEY = ("P1", "DEV1", "0", "0")
TRANSFER = {"tlsResource": "rtsp://relay.example:9133/t_1?digest=t"}
STANDARD = {"url": "rtsp://relay.example:554/s_1?digest=s"}


class _Imou:
    """Answers live link calls per mode; modes that are not listed fail with 12100."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.modes: list[str] = []
        self.client = ImouApiClient(None, "user@example.com", "pw", "terminal")
        self.client.async_request = self._request  # type: ignore[method-assign]
        self.client.async_invoke_service = self._service  # type: ignore[method-assign]

    def _answer(self, mode: str) -> dict[str, Any]:
        self.modes.append(mode)
        answer = self.answers.get(mode)
        if answer is None:
            raise ImouApiError("not supported", 12100)
        if isinstance(answer, Exception):
            raise answer
        return dict(answer)

    async def _request(self, api: str, revision: str, data: dict[str, Any]) -> dict[str, Any]:
        if api == "device.info.GetLiveStreamUrl":
            return self._answer(f"standard-{data['streamType'].casefold()}")
        assert api == "things.media.GetRealTransferStreamUrl"
        return self._answer("rtsv1" if data.get("type") == "RTSV1" else "transfer")

    async def _service(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return self._answer("service")

    async def live(self, *, fresh: bool = True) -> dict[str, Any]:
        self.modes.clear()
        return await self.client.async_get_live_url("P1", "DEV1", "0", use_cache=not fresh)

    def reject(self, mode: str, **kwargs: Any) -> None:
        self.client.reject_live_mode(*KEY, mode, **kwargs)

    @property
    def mode(self) -> str:
        return self.client.live_mode(*KEY)


async def test_transfer_links_are_asked_for_first() -> None:
    imou = _Imou({"transfer": TRANSFER, "standard-rtsp": STANDARD})
    assert imou.mode == ""
    assert await imou.live() == TRANSFER
    assert imou.modes == ["transfer"] and imou.mode == "transfer"
    assert imou.client.live_diagnostic(*KEY) == "playable:transfer"


async def test_standard_links_are_used_when_transfer_is_not_supported() -> None:
    imou = _Imou({"standard-rtsp": STANDARD})
    assert await imou.live() == STANDARD
    assert imou.modes == ["transfer", "rtsv1", "standard-rtsp"]
    assert imou.mode == "standard-rtsp"
    await imou.live()
    assert imou.modes == ["standard-rtsp"]  # the mode that played goes first


async def test_rejected_modes_are_tried_last_for_a_while() -> None:
    imou = _Imou({"standard-rtsp": STANDARD})
    await imou.live()
    imou.answers["transfer"] = TRANSFER
    assert await imou.live() == STANDARD

    imou.reject("")
    imou.reject("standard-rtsp")
    assert imou.mode == ""
    assert await imou.live(fresh=False) == TRANSFER  # the cached link is dropped too
    assert imou.modes == ["transfer"]

    del imou.answers["transfer"]
    assert await imou.live() == STANDARD  # still used when nothing else works
    assert imou.modes == [
        "transfer",
        "rtsv1",
        "standard-hls",
        "standard-flv",
        "standard-rtmp",
        "service",
        "service",
        "standard-rtsp",
    ]

    imou.reject("standard-rtsp", ttl=0)
    await imou.live()
    assert imou.modes == ["transfer", "rtsv1", "standard-rtsp"]


async def test_an_unreachable_standard_api_is_skipped() -> None:
    imou = _Imou({"standard-rtsp": ImouConnectionError("down"), "service": STANDARD})
    assert await imou.live() == STANDARD
    assert imou.modes == ["transfer", "rtsv1", "standard-rtsp", "service"]
    assert imou.mode == "service-rtsv1"


async def test_live_mode_is_only_reported_for_playable_links() -> None:
    imou = _Imou({"transfer": TRANSFER})
    await imou.live()
    assert imou.mode == "transfer"
    imou.answers["transfer"] = {"resource": "rtsv1://relay.example/x"}
    await imou.live()
    assert imou.mode == ""
    assert imou.client.live_diagnostic(*KEY) == "private_transport"
